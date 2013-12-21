unit AhApiCatalog;

interface

uses Classes, Windows, SysUtils, RPNit, IniFilesW, StringsW, StringUtils, AhCommon;

type
  TAhApiCatalog = class;
  TAhCallConvClass = class of TAhCallConv;

  TApiParamKind = set of (apNum, ap1, ap2, ap4, ap8, apSigned,
                          apChar, apWideChar,
                          apPointer);

  TApiParam = record
    Name: String;
    Aliases: TWideStringArray;
    Kind: TApiParamKind;
    KindHint: WideString;

    Consts: TWideStringArray;
    ConstIsSetOf: Boolean;
  end;

  TApiParamArray = array of TApiParam;

  TApiParams = class
  protected
    FCatalog: TAhApiCatalog;
  public
    Params: TApiParamArray;

    class function Parse(const Str: WideString): TApiParam;
    class function StrToKindHinting(Str: WideString; out Hint: WideString): TApiParamKind;

    constructor Create(Catalog: TAhApiCatalog);

    procedure Add(Param: TApiParam);
    procedure CheckParamIndex(Index: Integer);
    
    function ConstNameByValue(Param: Integer; const Value: TRpnScalar): WideString;
  end;

  TApiProcInfo = class
  public
    // If Lib = '' and Addr <> -1 it's absolute (typically within EXE's base addr).
    Lib, Call: String;
    Addr: DWord;    // -1 = use GetProcAddress.
    PrologueLength: Integer;
    Return: TApiParamKind;
    ReturnHint: WideString;
    AnyCaller: Boolean;
  end;

  TAhCallConv = class (TPersistent)
  public
    class function Get(const CallConv: String): TAhCallConvClass;

    class function CallerCleansStack: Boolean; virtual; abstract;
    class function ParamAddrOf(Index: Integer; rESP: DWord): DWord; virtual; abstract;
    class function ReturnValueAddr(const Registers: TAhRegisters): DWord; virtual; abstract;
  end;                                                         

  TAhApiCatalog = class
  protected
    FIni: TMemIniFileW;
    FConsts: TAhConstants;

    FInfo: TObjectHash;     // of TApiProcInfo.
    FParams: TObjectHash;   // of TApiParams.

    function LoadProc(const Name: String): Boolean;
    function LoadInfoFrom(List: TStringsW; const Name: String = '???'): TApiProcInfo;
    function LoadParamsFrom(List: TStringsW; const Name: String = '???'): TApiParams;

    function ProcSection(const Name: String): String;
    function ParamsOf(const Proc: String): TApiParams;

    function GetInfo(Proc: String): TApiProcInfo;
    function GetCallConv(Proc: String): TAhCallConvClass;
    function GetParamArray(Proc: String): TApiParamArray;
    function GetParamIndex(Proc, Param: String): Integer;
    function GetParamConsts(Proc, Param: String): TWideStringArray;    
    function GetName(Index: Integer): String;
  public
    class function ToValueByType(Kind: TApiParamKind; Addr: DWord): TRpnScalar;

    constructor Create(Ini: TCustomIniFileW);
    destructor Destroy; override;

    property Consts: TAhConstants read FConsts;

    property Info[Proc: String]: TApiProcInfo read GetInfo; default;
    property CallConv[Proc: String]: TAhCallConvClass read GetCallConv;

    property Params[Proc: String]: TApiParamArray read GetParamArray;
    property ParamIndex[Proc, Param: String]: Integer read GetParamIndex;
    property ParamConsts[Proc, Param: String]: TWideStringArray read GetParamConsts;

    property Names[Index: Integer]: String read GetName;

    function ParamToValue(const Proc: String; Param: Integer; rESP: DWord): TRpnScalar;
    function ConstNameByParamValue(const Proc: String; Param: Integer;
      const Value: TRpnScalar): WideString;
  end;

implementation

type
  TStdCallConv = class (TAhCallConv)
  public
    class function CallerCleansStack: Boolean; override;
    class function ParamAddrOf(Index: Integer; rESP: DWord): DWord; override;
    class function ReturnValueAddr(const Registers: TAhRegisters): DWord; override;
  end;

  TCdeclConv = class (TStdCallConv)
  public
    class function CallerCleansStack: Boolean; override;
  end;

{ TAhApiCatalog }

class function TAhApiCatalog.ToValueByType(Kind: TApiParamKind; Addr: DWord): TRpnScalar;
begin
  Result.Kind := [];

  if apNum in Kind then
  begin
    if ap1 in Kind then
      if apSigned in Kind then
        Result := RpnNum( ShortInt(Addr and $FF) )
        else
          Result := RpnNum( Addr and $FF )
      else if ap2 in Kind then            
        if apSigned in Kind then
          Result := RpnNum( SmallInt(Addr and $FFFF) )
          else
            Result := RpnNum( Addr and $FFFF )
        else if ap4 in Kind then
          if apSigned in Kind then
            Result := RpnNum( Integer(Addr) )
            else
              Result := RpnNum( Addr )
          else if ap8 in Kind then
            Result := RpnNum( PInt64(Addr)^ );
  end
    else if apChar in Kind then
      Result := RpnStr(String(PChar(Addr)))
      else if apWideChar in Kind then
        Result := RpnStr(PWideChar(Addr))
        else if apPointer in Kind then
          Result := RpnNum(Addr);

  if Result.Kind = [] then
    raise AhEx.CreateFmt('ToValueByType couldn''t return anything (Kind = %.4X).', [BinToHex(Kind, SizeOf(Kind))]);
end;

constructor TAhApiCatalog.Create(Ini: TCustomIniFileW);
begin
  FIni := TMemIniFileW.Create;
  FIni.CopyAllFrom(Ini);

  if FIni.SectionCount = 0 then
    raise AhEx.Create('Empty API catalog.');

  FConsts := TAhConstants.Create;
  Consts.AssignFromSectionOf(FIni, 'Constants');
  FIni.EraseSection('Constants');

  FInfo := TObjectHash.Create(True);
  FInfo.CaseSensitive := False;

  FParams := TObjectHash.Create(True);
  FParams.CaseSensitive := False;
end;

destructor TAhApiCatalog.Destroy;
begin
  FParams.Free;
  FInfo.Free;
  
  FConsts.Free;
  FIni.Free;

  inherited;
end;

function TAhApiCatalog.GetInfo(Proc: String): TApiProcInfo;
begin
  if LoadProc(Proc) then
    Result := FInfo[Proc] as TApiProcInfo
    else
      raise AhEx.CreateFmt('Cannot get info for unknown API proc %s.', [Proc]);
end;

function TAhApiCatalog.GetCallConv(Proc: String): TAhCallConvClass;
begin
  Result := TAhCallConv.Get( Info[Proc].Call );
end;

function TAhApiCatalog.GetParamArray(Proc: String): TApiParamArray;
begin
  Result := ParamsOf(Proc).Params;
end;

function TAhApiCatalog.GetParamIndex(Proc, Param: String): Integer;
var
  Params: TApiParamArray;
  I: Integer;
begin
  Param := LowerCase(Param);       
  Params := Self.Params[Proc];   

  for Result  := 0 to Length(Params) -1 do
    if LowerCase( Params[Result].Name ) = Param then
      Exit
      else
        for I := 0 to Length(Params[Result].Aliases) - 1 do
          if LowerCase( Params[Result].Aliases[I] ) = Param then
            Exit;
              
  Result := -1;
end;

function TAhApiCatalog.LoadProc(const Name: String): Boolean;
var
  List: TStringListW;
begin
  Result := FParams.IndexOf(Name) <> -1;

  if not Result then
  begin
    List := TStringListW.Create;
    try
      FIni.ReadSectionValues(ProcSection(Name), List);

      Result := List.Count > 0;
      if Result then
      begin
        FInfo.AddObject(Name, LoadInfoFrom(List, Name));
        FParams.AddObject(Name, LoadParamsFrom(List, Name));
      end;
    finally
      List.Free;
    end;
  end;
end;

  function TAhApiCatalog.LoadInfoFrom(List: TStringsW; const Name: String = '???'): TApiProcInfo;
  var
    Int: Integer;
  begin
    Result := TApiProcInfo.Create;

    Result.Lib := List.Values['Lib'];
    Result.Call := List.Values['Call'];

    if List.IndexOfName('Addr') = -1 then
      Result.Addr := DWord(-1)
      else if TryStrToInt('$' + List.Values['Addr'], Int) then
        Result.Addr := DWord(Int)   // casting signed to unsigned.
        else
          raise AhEx.CreateFmt('Addr of API proc %s is not a valid hexadecimal number: %s.', [Name, List.Values['Addr']]);

    if not TryStrToInt(List.Values['Prologue'], Result.PrologueLength) then
      Result.PrologueLength := 0;

    Result.Return := TApiParams.StrToKindHinting( List.Values['Return'], Result.ReturnHint );
    Result.AnyCaller := TrimLeft(List.Values['AnyCaller'], '0 ') <> '';
  end;

  function TAhApiCatalog.LoadParamsFrom(List: TStringsW; const Name: String = '???'): TApiParams;
  var
    I: Integer;      
    SkipNext: Boolean;
    Line: WideString;
  begin
    Result := TApiParams.Create(Self);
    SkipNext := False;

    for I := 0 to List.Count - 1 do
      if SkipNext then
        SkipNext := False
        else if Copy(List[I], 1, 1) = ':' then
        begin
          Line := TrimRight( Copy(List[I], 2, MaxInt) );

          SkipNext := (I < List.Count - 1) and (Line[Length(Line)] = '=');
          if SkipNext then
            Line := Line + List[I + 1];

          Result.Add(TApiParams.Parse(Line));
        end;
  end;

function TAhApiCatalog.ProcSection(const Name: String): String;
begin
  Result := Name;
end;

function TAhApiCatalog.ParamsOf(const Proc: String): TApiParams;
begin
  if LoadProc(Proc) then
    Result := FParams[Proc] as TApiParams
    else
      raise AhEx.CreateFmt('Cannot get params of unknown API proc %s.', [Proc]);
end;      

function TAhApiCatalog.GetName(Index: Integer): String;
begin
  Result := FInfo.Names[Index];
end;

function TAhApiCatalog.ParamToValue(const Proc: String; Param: Integer; rESP: DWord): TRpnScalar;
begin
  rESP := CallConv[Proc].ParamAddrOf(Param, rESP);
  Result := ToValueByType(Params[Proc][Param].Kind, rESP);
end;            
                                           
function TAhApiCatalog.ConstNameByParamValue(const Proc: String; Param: Integer;
  const Value: TRpnScalar): WideString;
begin
  Result := ParamsOf(Proc).ConstNameByValue(Param, Value);
end;
                          
function TAhApiCatalog.GetParamConsts(Proc, Param: String): TWideStringArray;
var
  Index: Integer;
begin
  Index := ParamIndex[Proc, Param];
  if Index <> -1 then
    Result := ParamsOf(Proc).Params[Index].Consts
    else
      SetLength(Result, 0);
end;

{ TApiParams }

class function TApiParams.Parse(const Str: WideString): TApiParam;
var
  Name, Kind, Consts: WideString;
  Aliases: TWideStringArray;
begin
  FillChar(Result, SizeOf(Result), 0);
  Split(Str, '=', Name, Kind);

  if Split(Kind, '=', Kind, Consts) then
  begin
    Consts := Trim(Consts);

    Result.ConstIsSetOf := (Length(Consts) > 7) and (Copy(Consts, 1, 7) = 'set of ');
    if Result.ConstIsSetOf then
      Consts := Copy(Consts, 8, MaxInt);

    if Consts <> '' then
      Result.Consts := Explode(' ', Consts, 0, True);
  end;

  Result.Kind := StrToKindHinting(Kind, Result.KindHint);

  if Split(Name, ' ', Name, Kind) then
    Aliases := Explode(' ', Kind)
    else
      SetLength(Aliases, 0);

  Result.Name := Name;
  Result.Aliases := Aliases;
end;

class function TApiParams.StrToKindHinting(Str: WideString; out Hint: WideString): TApiParamKind;
begin
  Split(Str, ' ', Str, Hint);
  Str := LowerCase(Str);

  if Str = 'pchar' then
    Result := [apChar]
    else if Str = 'pwidechar' then
      Result := [apWideChar]
      else if Str = 'pointer' then
        Result := [apPointer]
        else if (Str = 'byte') or (Str = 'bool') or (Str = 'char') then
          Result := [ap1, apNum]
          else if (Str = 'word') or (Str = 'short') then
            Result := [ap2, apNum]
            else if (Str = 'dword') or (Str = 'integer') or (Str = 'long') then
              Result := [ap4, apNum]
              else if Str = 'qword' then
                Result := [ap8, apNum]
                else
                  raise AhEx.CreateFmt('Invalid param kind "%s".', [Str]);

  if (Str = 'integer') or (Str = 'long') then
    Include(Result, apSigned);                   
end;

constructor TApiParams.Create(Catalog: TAhApiCatalog);
begin                  
  FCatalog := Catalog;
  SetLength(Params, 0);
end;

procedure TApiParams.Add(Param: TApiParam);
begin
  SetLength(Params, Length(Params) + 1);
  Params[Length(Params) - 1] := Param;
end;

procedure TApiParams.CheckParamIndex(Index: Integer);
begin
  if (Index < 0) or (Index > Length(Params)) then
    raise AhEx.CreateFmt('API proc parameter index %d is out of bounds - %d params total.', [Index, Length(Params)]);
end;

function TApiParams.ConstNameByValue(Param: Integer; const Value: TRpnScalar): WideString;
begin
  CheckParamIndex(Param);
  Result := FCatalog.Consts.NameBy(Value, Params[Param].Consts, Params[Param].ConstIsSetOf);
end;

{ TAhCallConv }

class function TAhCallConv.Get(const CallConv: String): TAhCallConvClass;
var
  Cls: WideString;
begin
  Cls := 'T' + LowerCase(CallConv) + 'Conv';
  Result := TAhCallConvClass(GetClass(Cls));

  if Result = NIL then
    raise AhEx.CreateFmt('Unknown calling convention "%s".', [CallConv]);
end;

{ TStdCallConv }

class function TStdCallConv.CallerCleansStack: Boolean;
begin
  Result := False;
end;

class function TStdCallConv.ParamAddrOf(Index: Integer; rESP: DWord): DWord;
asm
  { stdcall:  right-to-left parameter pushing }
  MOV   EAX, [rESP+Index*4]
end;

class function TStdCallConv.ReturnValueAddr(const Registers: TAhRegisters): DWord;
asm
  { stdcall:  return value in EAX }
  MOV   EAX, Registers.rEAX
end;

{ TCdeclConv }

class function TCdeclConv.CallerCleansStack: Boolean;
begin
  Result := True;
end;

initialization
  Classes.RegisterClass(TStdCallConv);
  Classes.RegisterClass(TCdeclConv);
end.
