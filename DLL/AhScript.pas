unit AhScript;

//{$DEFINE WithLightpath}

interface

uses Contnrs, Classes, Windows, SysUtils, Math, CallbackHash, IniFilesW, StringsW,
     RPNit, StringUtils, Utils, AhCommon;

type
  TAhAction = class;
  TAhScript = class;
  TAhActionClass = class of TAhAction;

  TAhRunPhase = (raPre, raPost);
  TAhRunPhases = set of TAhRunPhase;
  THookMode = (hmPrologue, hmImport);   
  TAhEndType = (FixedEnd, LengthEnd);

  TAhGetRegister = function (Reg: String; out Value: DWord): Boolean of object;
  TAhGetArg = function (Arg: String): TRpnScalar of object;
  TAhGetResult = function: TRpnScalar of object;
  TAhGetSaved = function (Name: WideString): TRpnScalar of object;
  TAhSetSaved = procedure (Name: WideString; const Value: TRpnScalar) of object;
  TAhGetProcName = function: String of object;
  TAhSaveFile = procedure (Name: WideString; const Buf; Size: DWord) of object;
  TAhGetConstName = function (Arg: String): WideString of object;
  TAhConstsByValue = function (const Value: TRpnScalar; const ConstNames: TWideStringArray;
    IsSetOf: Boolean; Joiner: WideString = ' '): WideString of object;
  TAhGetHumanReadableArg = function (Arg: String): WideString of object;
  TAhModuleNameOfAddr = function (Addr: DWord): WideString of object;   // '' if couldn't determine.

  TAhContext = record
    Log: TAhOnLog;

    GetRegister: TAhGetRegister;
    GetArg: TAhGetArg;
    GetResult: TAhGetResult;
    GetSaved: TAhGetSaved;
    SetSaved: TAhSetSaved;
    ProcName: TAhGetProcName;

    SaveFile: TAhSaveFile;
    GetConstName: TAhGetConstName;
    ConstsByValue: TAhConstsByValue;
    GetHumanReadableArg: TAhGetHumanReadableArg;
    ModuleNameOfAddr: TAhModuleNameOfAddr;
  end;

  TAhScriptProc = class
  protected
    FHookMode: THookMode;
    FActions: TObjectList;  // of TAhAction.

    function GetAction(Index: Integer): TAhAction;
  public
    constructor Create;
    destructor Destroy; override;

    property HookMode: THookMode read FHookMode write FHookMode default hmPrologue;

    function ActionCount: Integer;
    property Actions[Index: Integer]: TAhAction read GetAction;
    procedure AddAction(const Str: WideString; Owner: TAhScript);

    // returns number of actions ran.
    function RunActions(Context: TAhContext; RunPhases: TAhRunPhases): Integer;
  end;

  TAhScript = class
  protected
    FConsts: TAhConstants;
    FProcs: TObjectHash;      // of TAhScriptProc.
    FRpnSettings: TRpnCompSettings;

    FParseConsts: Boolean;    // used by ParseLine.
    FParsing: (pActions, pConsts, pOptions);    // used by ParseLine.

    procedure Parse(const Str: WideString; LoadConsts: Boolean = True);
    function ParseLine(Line: WideString; Data: DWord): Boolean;
    procedure HandleOption(const Line: WideString);
    procedure CleanProcs;

    function GetProc(Index: Integer): TAhScriptProc;
    function GetProcName(Index: Integer): String;
  public
    constructor Create(const Str: WideString);
    destructor Destroy; override;

    property Consts: TAhConstants read FConsts;

    property RpnSettings: TRpnCompSettings read FRpnSettings write FRpnSettings;

    function ProcCount: Integer;
    property ProcNames[Index: Integer]: String read GetProcName;
    property Procs[Index: Integer]: TAhScriptProc read GetProc; default;
    function IndexOfProc(const Name: String): Integer;

    function RunActionsOf(const Proc: String; Context: TAhContext;
      RunPhases: TAhRunPhases): Integer;
  end;

  TAhActionArgs = class (TArgList)
  public
    constructor Create(Args: TWideStringArray); reintroduce;
  end;

  TAhAction = class (TPersistent)
  protected
    FOwner: TAhScript;    // can be NIL.

    FArgStr: WideString;
    FArgs: TAhActionArgs;
    FPhases: TAhRunPhases;

    FContext: TAhContext;
    FSkipRemaining: Boolean;

    function Parse(Args: WideString): TWideStringArray; virtual;
    procedure Perform; virtual; abstract;

    function ExpandStr(const Str: WideString): WideString;
    function ExpandPieceOf(const Str: WideString; out Pos: Integer): WideString;
    function ExpandAndCutPieceFrom(var Str: WideString): WideString;
    function Eval(const RpnExpr: WideString): TRpnScalar;

    procedure NeedArgs(Count: Integer; const Syntax: WideString);
    function Error(const Msg: WideString; Fmt: array of const): Boolean;
    procedure Log(Level: TAhLogLevel; Str: WideString; Fmt: array of const);
  public
    class function From(Cmd: WideString; Owner: TAhScript): TAhAction; overload;
    class function From(const Action, Args: WideString): TAhActionClass; overload;
    class function ClassOf(const Action: WideString): TAhActionClass;

    class function Name: WideString;
    class function DefaultFileName(const Ext: WideString): WideString;

    constructor Create(const Args: WideString; Owner: TAhScript = NIL);
    destructor Destroy; override;

    property RunPhases: TAhRunPhases read FPhases write FPhases;
    function GetRpnSettings: TRpnCompSettings;

    function PerformIn(Context: TAhContext): Boolean; virtual;
  end;

  TAhRangeAction = class (TAhAction)
  protected
    FEndType: TAhEndType;

    function Parse(Args: WideString): TWideStringArray; override;
    procedure Perform; override;
    procedure CheckArgs; virtual;
    procedure PerformOnRange(Start, Size: Integer); virtual; abstract;
  end;

function AhEvalRPN(Context: TAhContext; Expr: WideString; Settings: TRpnCompSettings): TRpnScalar;

implementation

{$IFDEF WithLightpath}
uses AhLight;
{$ENDIF}

type
  TAhRpnVarList = class (TRpnVariables)
  protected
    FContext: TAhContext;

    function FunctionVar(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
      function ConstantVar(const Name: WideString; out Value: TRpnScalar): Boolean;
      function BitwiseFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
      function BoolFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
      function StringFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
      function PointerFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
      function MiscFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
  public
    constructor Create(Context: TAhContext); reintroduce;
    function GetIfExists(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean; override;
  end;

  TLogAction = class (TAhAction)
  protected
    procedure Perform; override;
  end;

  TSaveAction = class (TAhAction)
  protected
    procedure Perform; override;
    procedure MultipleArgSave;
  end;

  TDumpAction = class (TAhRangeAction)
  protected
    FFile: WideString;
    FIsPeriod: Boolean;

    function Parse(Args: WideString): TWideStringArray; override;
    procedure CheckArgs; override;
    procedure PerformOnRange(Start, Size: Integer); override;
  end;

  TIfAction = class (TAhAction)
  protected
    procedure Perform; override;
  end;

  TStackAction = class (TAhAction)
  protected
    FFmtChar: String;
    FDepth: Integer;
    FBaseESP: WideString;

    function Parse(Args: WideString): TWideStringArray; override;
    procedure Perform; override;
  end;

function AhFormatOne(const Value: TRpnScalar; Fmt: Char): WideString;
  function BinTo(Fmt: Char; const Buf; Size: Integer): WideString;
  var
    I: DWord;
  begin
    if Size = 0 then
      Result := NilRPN
      else if Fmt = 'd' then
      begin
        Result := '';

        if Size > 0 then
        begin
          for I := 0 to Size - 1 do
            Result := Result + IntToStr(PByte( DWord(@Buf) + I )^) + ' ';

          Delete(Result, Length(Result), 1);
        end;
      end
        else
        begin
          Result := BinToHex(Buf, Size, ' ');
          if Fmt = 'x' then
            Result := SysUtils.LowerCase(Result);
        end;
  end;

  function BytesToANSI(const Bytes: String): WideString;
  var
    I: Integer;
  begin
    SetLength(Result, Length(Bytes));

    for I := 1 to Length(Bytes) do
      Result[I] := WideChar(Bytes[I]);
  end;

  function StrToWideHex(const Str: WideString): WideString;
  var
    I: Integer;
    S: WideString;
  begin
    SetLength(Result, Length(Str) * 5);

    for I := 1 to Length(Str) do
    begin
      S := IntToHex(Word(Str[I]), 4) + ' ';
      Move(S[1], Result[I * Length(S)], Length(S) * 2);
    end;

    SetLength(Result, Length(Result) - 1);    // trailing space.
  end;

const
  BoolStrs: array[Boolean] of WideString = ('FALSE', 'TRUE');
  Error = 'Invalid combination of Value (%s, kind %s) and Format (%s) for AhFormatOne.';
begin
  Result := '';

  with Value do
    case Fmt of
    'd':
      if valStr in Kind then
        Result := BinTo(Fmt, Str[1], Length(Str) * 2)
        else if valBytes in Kind then
          Result := BinTo(Fmt, Bytes[1], Length(Bytes))
          else if valBool in Kind then
            Result := IntToStr( Sign(Byte(Bool)) );
    'x', 'X':
      if (valNum in Kind) and (Frac(Num) = 0) then
      begin
        Result := IntToHex(Trunc(Num), 1);
        if Fmt = 'x' then
          Result := SysUtils.LowerCase(Result);
      end
        else if valStr in Kind then
          Result := BinTo(Fmt, Str[1], Length(Str) * 2)
          else if valBytes in Kind then
            Result := BinTo(Fmt, Bytes[1], Length(Bytes));
    'f':
      if valNum in Kind then
        Result := Format('%g', [Num]);
    's':
      if (valNum in Kind) and (Frac(Num) = 0) then
        Result := IntToStr(Trunc(Num))
        else if valBytes in Kind then
          Result := BytesToANSI(Bytes)
          else if valBool in Kind then
            Result := BoolStrs[Bool];
    'u':
      if valStr in Kind then
        Result := StrToWideHex(Str)
        else if valBytes in Kind then
        begin
          SetLength(Result, Length(Bytes) div 2 + Length(Bytes) mod 2);
          Result[Length(Result) - 1] := #0;
          Move(Bytes[1], Result[1], Length(Bytes));
        end;
    end;

  if Result = '' then
    raise AhEx.CreateFmt(Error, [RpnValueToStr(Value, NilRPN), RpnKindToStr(Value.Kind), Fmt]);
end;

function AhEvalRPN(Context: TAhContext; Expr: WideString; Settings: TRpnCompSettings): TRpnScalar;
var
  Vars: TAhRpnVarList;
begin
  Vars := TAhRpnVarList.Create(Context);
  try
    Settings.Variables := Vars;
    Result := EvalRPN(Expr, Settings);
  finally
    Vars.Free;
  end;
end;

function ExpandAhRpnStringPiece(Context: TAhContext; const Str: WideString;
  const Settings: TRpnCompSettings; var StrPos: Integer): WideString;
const
  ArgChars = ['a'..'z', 'A'..'Z', '0'..'9', '_'];
var
  I: Integer;

  function CutName(Esc: Char; out IsEsc: Boolean): WideString;
  var
    Len: Integer;
  begin
    Len := 0;

    while (I + Len <= Length(Str)) and (Char(Str[I + Len]) in ArgChars) do
      Inc(Len);

    IsEsc := Len = 0;

    if IsEsc then
    begin
      Result := Esc;
      if Copy(Str, I, 1) = Esc then   // '::'
        Inc(I);
    end
      else
      begin
        Result := Copy(Str, I, Len);
        Inc(I, Len);
      end;
  end;

  function GetArg: WideString;
    function GetRegOrArg(const Name: WideString): TRpnScalar;
    var
      Reg: DWord;
    begin
      if Context.GetRegister(Name, Reg) then
        Result := RpnNum(Reg)
        else
          Result := Context.GetArg(Name);
    end;

  var
    IsEsc: Boolean;
    Fmt: WideString;
    EmptyPart: Boolean;
  begin
    Inc(I);
    Result := CutName(':', IsEsc);

    if not IsEsc and (Result <> '') then
    begin
      while (I < Length(Str)) and (Str[I] = ':') do
      begin
        Inc(I);

        if (I > Length(Str)) or (Str[I] = ':') then
          Break;

        EmptyPart := True;

        while (I <= Length(Str)) and (Char(Str[I]) in ArgChars) do
        begin
          if EmptyPart then
          begin
            Result := Result + ' ';
            EmptyPart := False;
          end;

          Result := Result + Str[I];
          Inc(I);
        end;

        if EmptyPart then
        begin
          Dec(I);
          Break;
        end;
      end;

      if Split(Result, ' ', Result, Fmt) then
        if (Length(Fmt) = 1) and (Char(Fmt[1]) in ['d', 'x', 'X', 'f', 's', 'u']) then
          Result := AhFormatOne(GetRegOrArg(Result), Char(Fmt[1]))
          else
            Result := RpnValueToStr( AhEvalRPN(Context, ':' + Result + ' ' + Fmt, Settings), NilRPN )
        else if UpperCase(Result) = Result then
          Result := RpnValueToStr( Context.GetArg(Result), NilRPN )
          else
            Result := Context.GetHumanReadableArg(Result);
    end;
  end;

  function GetResultOrVar: WideString;
  var
    IsEsc: Boolean;
  begin
    Inc(I);

    if (I > Length(Str)) or not (Char(Str[I]) in ArgChars) then
      Result := RpnValueToStr( Context.GetResult, NilRPN )
      else
      begin
        Result := CutName('^', IsEsc);

        if not IsEsc then
          if Result = '' then
            Result := RpnValueToStr( Context.GetResult, NilRPN )
            else
              Result := RpnValueToStr( Context.GetSaved(Result), NilRPN );
      end;
  end;

  function GetAsm: WideString;
  var
    Pos: Integer;
  begin
    Inc(I);

    if I <= Length(Str) then
      if Str[I] = '>' then
        Dec(I)    // '<>' is output as is
        else if Str[I] <> '<' then    // double '<<' equals '<'
        begin
          Pos := I;

          while True do
          begin
            Pos := PosW('>', Str, Pos) + 1;

            if Pos = 1 then
              raise AhEx.CreateFmt('Unterminated <expression> string near "%s".',
                                   [Copy(Str, I - 5, MaxInt)]);

            if (Pos > Length(Str)) or (Str[Pos] <> '>') then
              Break;
          end;

          Result := RpnValueToStr( AhEvalRPN(Context, Copy(Str, I, Pos - I - 1), Settings), NilRPN );
          I := Pos;
        end;
  end;

begin
  Result := '';

  I := StrPos;
  if I < 1 then
    I := 1;

  while I <= Length(Str) do
    case Char(Str[I]) of
    ':':      Result := Result + GetArg;
    '^':      Result := Result + GetResultOrVar;
    '<':      Result := Result + GetAsm;
    #0..' ':  Break;
    else
      begin
        Result := Result + Str[I];
        Inc(I);
      end;
    end;

  StrPos := I;
end;

function ExpandAhRpnString(Context: TAhContext; const Str: WideString;
  const Settings: TRpnCompSettings): WideString;
var
  I: Integer;
begin
  I := 0;
  Result := '';

  while I <= Length(Str) do
  begin
    if I > 0 then
      Result := Result + Str[I];

    Inc(I);
    Result := Result + ExpandAhRpnStringPiece(Context, Str, Settings, I);
  end;
end;

{ TAhRpnVarList }

constructor TAhRpnVarList.Create(Context: TAhContext);
begin
  inherited Create;
  FContext := Context;
end;

function TAhRpnVarList.GetIfExists(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
var
  Int: Integer;
  RegVal: DWord;
begin
  Result := True;

  if Name[1] = '$' then
    if TryStrToInt(Name, Int) then
      Value := RpnNum(Int)
      else
        raise AhEx.CreateFmt('Invalid hex number "%s" in RPN expression.', [Name])
    else if Name = '^' then
      Value := FContext.GetResult
      else if Name[1] = '^' then
        Value := FContext.GetSaved(Copy(Name, 2, MaxInt))
        else if Name[1] = ':' then
          Value := FContext.GetArg(Copy(Name, 2, MaxInt))
          else if FContext.GetRegister(Name, RegVal) then
            Value := RpnNum(RegVal)
            else if FunctionVar(Eval, Name, Value) then
              {Return}
              else
                Value := RpnStr(Name);
end;

function TAhRpnVarList.FunctionVar(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
begin
  Value.Kind := [];

  Result := BitwiseFunc(Eval, Name, Value) or
            BoolFunc(Eval, Name, Value) or
            StringFunc(Eval, Name, Value) or
            PointerFunc(Eval, Name, Value) or
            MiscFunc(Eval, Name, Value) or
            ConstantVar(Name, Value);
end;

function TAhRpnVarList.ConstantVar(const Name: WideString; out Value: TRpnScalar): Boolean;
begin
  Result := (Name = 'TRUE') or (Name = 'FALSE') or (Name = 'NIL');

  if Result then
  begin
    if Name = 'TRUE' then
      Value := RpnBool(True)
      else if Name = 'FALSE' then
        Value := RpnBool(False)
        else if Name = 'NIL' then
          Value.Kind := [];
  end;
end;

function TAhRpnVarList.BitwiseFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
var
  A: Double;
begin
  Result := (Name = '<<') or (Name = '>>') or (Name = '&') or (Name = '|') or (Name = '^');

  if Result then
  begin
    A := Eval.Stack.PopInt;

    if Name = '<<' then
      Value := RpnNum(Trunc(A) shl Trunc(Eval.Stack.PopInt))
      else if Name = '>>' then
        Value := RpnNum(Trunc(A) shr Trunc(Eval.Stack.PopInt))
        else if Name = '&' then
          Value := RpnNum(Trunc(A) and Trunc(Eval.Stack.PopInt))
          else if Name = '|' then
            Value := RpnNum(Trunc(A) or Trunc(Eval.Stack.PopInt))
            else if Name = '^' then
              Value := RpnNum(Trunc(A) xor Trunc(Eval.Stack.PopInt));
  end;
end;

function TAhRpnVarList.BoolFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
  function Negate(const Value: TRpnScalar): TRpnScalar;
  const
    Error = 'NOT function can only be used on integer and boolean operands, %s operand given.';
  begin
    Result := Value;

    with Result do
    begin
      if (valNum in Kind) and (Frac(Num) = 0) then
        Num := not Trunc(Num);
      if valBool in Kind then
        Bool := not Bool;

      if (Num = Value.Num) and (Bool = Value.Bool) then
        raise EInvalidRpnOperation.Create(Error, [RpnKindToStr(Kind)]);
    end;
  end;

const
  AndError = 'AND/OR functions require 2 boolean operands, %s and %s given.';
var
  A, B: Double;
  AVal, BVal: TRpnScalar;
begin
  Result := (Name = 'NOT') or (Name = 'nil') or (Name = 'AND')  or (Name = 'OR') or
            (Name = 'EQU')  or (Name = 'NEQ') or
            (Name = 'LEQ') or (Name = 'GEQ') or (Name = 'LESS') or (Name = 'MORE');

  if Result then
    if Name = 'NOT' then
      Value := Negate(Eval.Stack.Pop)
      else if (Name = 'nil') then
        Value := RpnBool( Eval.Stack.Pop.Kind = [] )
        else if (Name = 'AND') or (Name = 'OR') then
        begin
          BVal := Eval.Stack.Pop;
          AVal := Eval.Stack.Pop;

          if [valBool] * AVal.Kind * BVal.Kind = [] then
            raise AhEx.CreateFmt(AndError, [RpnKindToStr(AVal.Kind), RpnKindToStr(BVal.Kind)]);

          if Name = 'AND' then
            Value := RpnBool(AVal.Bool and BVal.Bool)
            else
              Value := RpnBool(AVal.Bool or BVal.Bool);
        end
          else if (Name = 'EQU') or (Name = 'NEQ') then
          begin
            Value := Eval.Stack.Pop;
            Value := RpnBool( CompareRpnValues(Eval.Stack.Pop, Value) );

            if Name = 'NEQ' then
              Value.Bool := not Value.Bool;
          end
            else
            begin
              B := Eval.Stack.PopInt;  // note the reversed order of A/B since we pop
              A := Eval.Stack.PopInt;  // values off the stack from right to left.

              if Name = 'LEQ' then
                Value := RpnBool(A <= B)
                else if Name = 'GEQ' then
                  Value := RpnBool(A >= B)
                  else if Name = 'LESS' then
                    Value := RpnBool(A < B)
                    else if Name = 'MORE' then
                      Value := RpnBool(A > B);
            end;
end;

function TAhRpnVarList.StringFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
const
  FmtError    = 'FMT function expects a single format character on top of stack, "%s" string given.';
  PosError    = 'POS function works on str-str and bytes-bytes needle (%s) and haystack (%s).';
  PosiError   = 'POSI function works on str-str needle (%s) and haystack (%s).';
  CatFewArgs  = 'CAT function requires at least 2 arguments on top of the stack, %d found.';
var
  Str: WideString;
  Sub: TRpnScalar;
  Max: Integer;
begin
  Result := (Name = 'chr') or (Name = 'fmt') or (Name = 'pos') or (Name = 'posi') or
            (Copy(Name, 1, 3) = 'cat') or (Name = 'up') or (Name = 'down');

  if Result then
  begin
    if Name = 'chr' then
      Value := RpnStr(WideChar( Trunc(Eval.Stack.PopInt) ))
      else if Name = 'fmt' then
      begin
        Str := Eval.Stack.PopStr;
        if Length(Str) <> 1 then
          raise AhEx.CreateFmt(FmtError, [Str]);

        Value := RpnStr( AhFormatOne(Eval.Stack.Pop, Char(Str[1])) );
      end
        else if (Name = 'pos') or (Name = 'posi') then
        begin
          Sub := Eval.Stack.Pop;
          Value := Eval.Stack.Pop;

          if Name = 'posi' then
            if [valStr] * Sub.Kind * Value.Kind <> [] then
              Value := RpnNum( PosW(LowerCase(Sub.Str), LowerCase(Value.Str)) - 1 )
              else
                raise AhEx.CreateFmt(PosiError, [RpnKindToStr(Sub.Kind), RpnKindToStr(Value.Kind)])
            else if [valStr] * Sub.Kind * Value.Kind <> [] then
              Value := RpnNum( PosW(Sub.Str, Value.Str) - 1 )
              else if [valBytes] * Sub.Kind * Value.Kind <> [] then
                Value := RpnNum( System.Pos(Sub.Bytes, Value.Bytes) - 1 )
                else
                  raise AhEx.CreateFmt(PosError, [RpnKindToStr(Sub.Kind), RpnKindToStr(Value.Kind)]);

          Include(Value.Kind, valBool);
          Value.Bool := Value.Num >= 0;
        end
          else if Copy(Name, 1, 3) = 'cat' then
          begin
            Str := Copy(Name, 4, MaxInt);

            if Str = '' then
              Max := Eval.Stack.Count
              else if not TryStrToInt(Str, Max) then
                raise AhEx.CreateFmt('CATx must be followed by a number, "%s" given.', [Name]);

            if Eval.Stack.Count < 2 then
              raise AhEx.CreateFmt(CatFewArgs, [Eval.Stack.Count]);

            Value := RpnStr('');
            for Max := Max downto 1 do
              Value.Str := Eval.Stack.PopStr + Value.Str;
          end
            else if Name = 'up' then
              Value := RpnStr(UpperCase(Eval.Stack.PopStr))
              else if Name = 'down' then
                Value := RpnStr(LowerCase(Eval.Stack.PopStr));
  end;
end;

function TAhRpnVarList.PointerFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
var
  A: Double;
begin
  Result := (Name = '[]') or (Name = 'DW[]') or (Name = 'W[]') or (Name = 'B[]');

  if Result then
  begin
    A := Eval.Stack.PopInt;

    if (Name = '[]') or (Name = 'DW[]') then
      Value := RpnNum( PDWord(Trunc(A))^ )
      else if Name = 'W[]' then
        Value := RpnNum( PWord(Trunc(A))^ )
        else if Name = 'B[]' then
          Value := RpnNum( PByte(Trunc(A))^ );
  end;
end;

function TAhRpnVarList.MiscFunc(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
var
  Consts: TWideStringArray;
  S: WideString;
begin
  Result := (Name = 'arg') or (Name = 'rev') or (Name = 'load') or (Name = 'const') or
            (Name = 'consts') or (Name = 'constset');

  if Result then
  begin
    if Name = 'arg' then
      Value := RpnStr( FContext.GetHumanReadableArg(Eval.Stack.PopStr) )
      else if Name = 'rev' then
      begin
        if not Eval.Stack.Reverse then
          raise AhEx.Create('REV function requires a non-empty stack.');

        Value := Eval.Stack.Pop;
      end
        else if Name = 'load' then
          Value := FContext.GetSaved(Eval.Stack.PopStr)
          else if (Name = 'const') or (Name = 'consts') or (Name = 'constset') then
          begin
            SetLength(Consts, 1);
            Consts[0] := '*';

            Value := RpnStr( FCOntext.ConstsByValue(Eval.Stack.Pop, Consts, Name = 'constset') );

            if Name = 'const' then
              Split(Value.Str, ' ', Value.Str, S);
          end;
  end;
end;

{ TAhScript }

constructor TAhScript.Create(const Str: WideString);
begin
  FRpnSettings := DefaultRpnSettings;

  FConsts := TAhConstants.Create;

  FProcs := TObjectHash.Create(True);
  FProcs.CaseSensitive := False;

  Parse(Str);
end;

destructor TAhScript.Destroy;
begin
  FProcs.Free;
  FConsts.Free;
  inherited;
end;

procedure TAhScript.Parse(const Str: WideString; LoadConsts: Boolean = True);
begin
  FProcs.Clear;
  if LoadConsts then
    FConsts.Clear;

  FParseConsts := LoadConsts;
  FParsing := pActions;

  FProcs.Sorted := False;
  try
    CallOnEachLineIn(Str, ParseLine);
    CleanProcs;
  finally
    FProcs.Duplicates := dupAccept;
    FProcs.Sorted := True;
  end;

  if FProcs.Count = 0 then
    raise AhEx.CreateFmt('ApiHook script contains no procedures to hook:'#13#10'%s', [Str]);
end;

function TAhScript.ParseLine(Line: WideString; Data: DWord): Boolean;
var
  Section, Comment, Value: WideString;
begin
  Result := False;
  Line := Trim(Line);

  if (Line <> '') and (Line[1] <> '#') and (Line[1] <> ';') then
    if (Line[1] = '[') and (Line[Length(Line)] = ']') then
    begin
      Section := Trim( Copy(Line, 2, Length(Line) - 2) );

      // each section can contain optional comment string following section "ID"
      // (procedure name) which can't contain spaces:
      Split(Section, ' ', Section, Comment);

      if LowerCase(Section) = 'apihook' then
        FParsing := pOptions
        else if LowerCase(Section) <> 'constants' then
        begin
          FProcs.AddObject(Section, TAhScriptProc.Create);
          FParsing := pActions;
        end
          else if FParseConsts then
            FParsing := pConsts;
    end
      else if FParsing = pConsts then
      begin
        if Split(Line, '=', Line, Value) then
          FConsts.Add(Line, FConsts.StrToValue(Value));
      end
        else if FParsing = pOptions then
          HandleOption(Line)
          else if FProcs.Count = 0 then
            raise AhEx.CreateFmt('Script hook command outside of any [proc] section: "%s".', [Line])
            else
              (FProcs.Objects[FProcs.Count - 1] as TAhScriptProc).AddAction(Line, Self);
end;

procedure TAhScript.HandleOption(const Line: WideString);
  function ToBool(Value: WideString): Boolean;
  begin
    Value := LowerCase(Value);
    Result := (Value = '1') or (Value = 'on') or (Value = 'yes') or (Value = 'y') or (Value = 'true');
  end;

var
  Key, Value: WideString;
begin
  if not Split(Line, '=', Key, Value) then
    Value := '1';

  Key := LowerCase(Trim(Key));
  Value := Trim(Value);

  if Key = 'prefix notation' then
    FRpnSettings.PrefixNotation := ToBool(Value);
end;

procedure TAhScript.CleanProcs;
var
  I: Integer;

  function SetOptions: Boolean;
  begin
    Result := True;

    case Char(FProcs.Strings[I][ Length(FProcs.Strings[I]) ]) of
    '*':    (FProcs.Objects[I] as TAhScriptProc).HookMode := hmImport
    else
      Result := False;
    end;
  end;

begin
  for I := FProcs.Count - 1 downto 0 do
    if (FProcs.Strings[I] = '') or (FProcs.Strings[I][1] = ';') then
      FProcs.Delete(I)
      else if SetOptions then
        FProcs.Strings[I] := Copy(FProcs.Strings[I], 1, Length(FProcs.Strings[I]) - 1)
        else if not (Char(FProcs.Strings[I][1]) in ['a'..'z', 'A'..'Z', '0'..'9', '_'] )
                or (( FProcs.Objects[I] as TAhScriptProc ).ActionCount = 0) then
          FProcs.Delete(I);
end;

function TAhScript.ProcCount: Integer;
begin
  Result := FProcs.Count;
end;

function TAhScript.GetProcName(Index: Integer): String;
begin
  Result := FProcs.Strings[Index];
end;

function TAhScript.GetProc(Index: Integer): TAhScriptProc;
begin
  Result := FProcs.Objects[Index] as TAhScriptProc;
end;

function TAhScript.IndexOfProc(const Name: String): Integer;
begin
  Result := FProcs.IndexOf(Name);
end;

function TAhScript.RunActionsOf(const Proc: String; Context: TAhContext;
  RunPhases: TAhRunPhases): Integer;
var
  I: Integer;
begin
  Result := 0;

  I := IndexOfProc(Proc);
  if I = -1 then
    raise AhEx.CreateFmt('%s.RunActionsOf could find no actions for %s proc.', [ClassName, Proc])
    else
    begin
      // THashedStringListW.IndexOf doesn't necessary return index of the first matching string.
      while (I > 0) and (FProcs.Strings[I - 1] = Proc) do
        Dec(I);

      repeat
        Inc( Result, Procs[I].RunActions(Context, RunPhases) );
        Inc(I);
      until (I >= ProcCount) or (FProcs.Strings[I] <> Proc);
    end;
end;

{ TAhScriptProc }

constructor TAhScriptProc.Create;
begin
  FHookMode := hmPrologue;
  FActions := TObjectList.Create(True);
end;

destructor TAhScriptProc.Destroy;
begin
  FActions.Free;
  inherited;
end;

function TAhScriptProc.ActionCount: Integer;
begin
  Result := FActions.Count;
end;

function TAhScriptProc.GetAction(Index: Integer): TAhAction;
begin
  Result := FActions[Index] as TAhAction;
end;

procedure TAhScriptProc.AddAction(const Str: WideString; Owner: TAhScript);
begin
  FActions.Add(TAhAction.From(Str, Owner));
end;

function TAhScriptProc.RunActions(Context: TAhContext; RunPhases: TAhRunPhases): Integer;
var
  I: Integer;
begin
  Result := 0;

  for I := 0 to ActionCount - 1 do
    if RunPhases * Actions[I].RunPhases <> [] then
    begin
      Inc(Result);
      if Actions[I].PerformIn(Context) then
        Break;
    end;
end;

{ TAhActionArgs }

constructor TAhActionArgs.Create(Args: TWideStringArray);
begin
  inherited Create('');
  FValues := Args;
end;

{ TAhAction }

class function TAhAction.Name: WideString;
begin
  Result := Copy(ClassName, 2, Length(ClassName) - 7);    // T...Action
end;

class function TAhAction.DefaultFileName(const Ext: WideString): WideString;
begin
  Result := ChangeFileExt(ParamStrW(0), Ext);
end;

class function TAhAction.From(Cmd: WideString; Owner: TAhScript): TAhAction;
const
  PostPf = '.';
  BothPf = '*';
var
  Args: WideString;
  Phases: TAhRunPhases;
begin
  Cmd := Trim(Cmd);

  if Char(Cmd[1]) in [PostPf, BothPf] then
  begin
    if Cmd[1] = PostPf then
      Phases := [raPost]
      else
        Phases := [raPre, raPost];

    Delete(Cmd, 1, 1);
  end
    else
      Phases := [raPre];

  Split(Trim(Cmd), ' ', Cmd, Args);
  Result := From(Cmd, Args).Create(Args, Owner);

  Result.RunPhases := Phases;
end;

class function TAhAction.From(const Action, Args: WideString): TAhActionClass;
begin
  Result := ClassOf(Action);
  if Result = NIL then
    raise AhEx.CreateFmt('Unknown hook action "%s" (given args: "%s").', [Action, Args]);
end;

class function TAhAction.ClassOf(const Action: WideString): TAhActionClass;
var
  Cls: String;
begin
  Cls := 'T' + UpperCaseFirst(LowerCase(Action)) + 'Action';
  Result := TAhActionClass(GetClass(Cls));
end;

constructor TAhAction.Create(const Args: WideString; Owner: TAhScript = NIL);
begin
  FOwner := Owner;
  FArgs := TAhActionArgs.Create(Parse(Args));
end;

destructor TAhAction.Destroy;
begin
  FArgs.Free;
  inherited;
end;

function TAhAction.Parse(Args: WideString): TWideStringArray;
begin
  FArgStr := Args;
  SetLength(Result, 0);
end;

function TAhAction.PerformIn(Context: TAhContext): Boolean;
begin
  FContext := Context;
  FSkipRemaining := False;

  Perform;
  Result := FSkipRemaining;
end;

procedure TAhAction.NeedArgs(Count: Integer; const Syntax: WideString);
const
  Error = '%s action requires at least %d parameters, %d given (%s); syntax: %s.';
begin
  if FArgs.Count < Count then
    raise AhEx.CreateFmt(Error, [Name, Count, FArgs.Count, FArgStr, Syntax]);
end;

function TAhAction.Error(const Msg: WideString; Fmt: array of const): Boolean;
begin
  raise AhEx.CreateFmt(UpperCase(Name) + ' action: ' + Msg, Fmt);
end;

function TAhAction.ExpandStr(const Str: WideString): WideString;
begin
  Result := ExpandAhRpnString(FContext, Str, GetRpnSettings);
end;

function TAhAction.ExpandPieceOf(const Str: WideString; out Pos: Integer): WideString;
begin
  Pos := 1;
  Result := ExpandAhRpnStringPiece(FContext, Str, GetRpnSettings, Pos);
end;

function TAhAction.ExpandAndCutPieceFrom(var Str: WideString): WideString;
var
  Pos: Integer;
begin
  Result := ExpandPieceOf(Str, Pos);
  Str := Copy(Str, Pos + 1, MaxInt);
end;

function TAhAction.Eval(const RpnExpr: WideString): TRpnScalar;
begin
  Result := AhEvalRPN(FContext, RpnExpr, GetRpnSettings);
end;

function TAhAction.GetRpnSettings: TRpnCompSettings;
begin
  if FOwner = NIL then
    Result := DefaultRpnSettings
    else
      Result := FOwner.RpnSettings;
end;

procedure TAhAction.Log(Level: TAhLogLevel; Str: WideString; Fmt: array of const);
begin
  FContext.Log(Level, '{wi ' + FContext.ProcName + ':} ' + Str, Fmt);
end;
                
{ TAhRangeAction }

function TAhRangeAction.Parse(Args: WideString): TWideStringArray;
const
  Types: array[Boolean] of TAhEndType = (FixedEnd, LengthEnd);
  Separators: array[TAhEndType] of WideString = ('--', '..');
begin
  inherited Parse(Args);

  FEndType := Types[PosW('..', Args) > 0];
  Result := Explode(Separators[FEndType], Args, 2);
end;

procedure TAhRangeAction.Perform;
var
  AFrom, ATo: DWord;
begin
  CheckArgs;

  AFrom := RpnValueToInt( Eval(FArgs[0]) );
  ATo   := RpnValueToInt( Eval(FArgs[1]) );

  if FEndType = FixedEnd then
    if ATo < AFrom then
      Error('end address %.8X is less than start address %.8X', [ATo, AFrom])
      else
        Dec(ATo, AFrom);

  PerformOnRange(AFrom, ATo);
end;

procedure TAhRangeAction.CheckArgs;
begin
  NeedArgs(2, 'startAddr..size OR startAddr--endAddr');
end;

{ TLogAction }

procedure TLogAction.Perform;
begin
  Log(logUser, '%s', [ ExpandStr(FArgStr) ]);
end;

{ TSaveAction }

procedure TSaveAction.Perform;
const
  Syntax = 'varName [expression] OR var+ArgName, second[, ...]';
var
  NameIsExpr, MultiArgSave: Boolean;
  S, Name: WideString;
begin
  if FArgStr = '' then
    NeedArgs(1, Syntax);

  NameIsExpr := not ( Char(FArgStr[1]) in ['a'..'z', 'A'..'Z', '0'..'9', '_'] );
  MultiArgSave := not NameIsExpr and Split(FArgStr, ' ', S, Name) and (S[Length(S)] = ',');

  if MultiArgSave then
    MultipleArgSave
    else
    begin
      S := FArgStr;

      if NameIsExpr then
        Name := ExpandAndCutPieceFrom(S)
        else if not Split(S, ' ', Name, S) then
          S := ':' + Name;

      FContext.SetSaved(Name, Eval(S));
    end;
end;

procedure TSaveAction.MultipleArgSave;
const
  Error = 'Wrong Save action syntax: all but the last var+arg parameters must end on' +
          ' comma; given parameter string: %s';
var
  Args: TWideStringArray;
  I: Integer;
begin
  Args := Explode(' ', FArgStr, 0, True);

  for I := 0 to Length(Args) - 1 do
  begin
    if Args[I][ Length(Args[I]) ] = ',' then
      Delete(Args[I], Length(Args[I]), 1)
      else if I < Length(Args) - 1 then
        raise AhEx.CreateFmt(Error, [FArgStr]);

    FContext.SetSaved(Args[I], FContext.GetArg(Args[I]));
  end;
end;

{ TDumpAction }

function TDumpAction.Parse(Args: WideString): TWideStringArray;
begin
  FArgStr := Args;
  Split(Args, ' ', FFile, Args);
  Result := inherited Parse(Args);
end;

procedure TDumpAction.CheckArgs;
begin
  NeedArgs(2, 'file startAddr..size OR file startAddr--endAddr; file can contain ''*''s for a random string');
end;

procedure TDumpAction.PerformOnRange(Start, Size: Integer);
var
  Name: WideString;
  Buf: Pointer;
begin
  Name  := ExpandStr(FFile);
  GetMem(Buf, Size);
  try
    Move(Pointer(Start)^, Buf^, Size);
    FContext.SaveFile(Name, Buf^, Size);
  finally
    FreeMem(Buf, Size);
  end;
end;

{ TIfAction }

procedure TIfAction.Perform;
var
  Res: TRpnScalar;
begin
  Res := Eval(FArgStr);

  if valBool in Res.Kind then
    FSkipRemaining := not Res.Bool
    else
      Error('result of expression must be Boolean, "%s" has evaluated to %s.', [FArgStr, RpnKindToStr(Res.Kind)]);
end;

{ TStackAction }

function TStackAction.Parse(Args: WideString): TWideStringArray;
const
  MaxDepth = 500;
var
  I, Int: Integer;
begin
  inherited Parse(Args);

  FFmtChar := 'X';
  FDepth := 30;
  FBaseESP := '';

  Result := Explode(' ', Args, 3, True);

  for I := 0 to Length(Result) - 1 do
    if TryStrToInt(Result[I], Int) and (Int <= MaxDepth) then
      FDepth := Int
      else if Length(Result[I]) < 2 then
      begin
        if Result[I] = '-' then
          FFmtChar := ''
          else
            FFmtChar := Result[I];
      end
        else
          FBaseESP := Result[I];
end;

procedure TStackAction.Perform;
var
  I, ESP, Addr: DWord;
  Msg, Module: WideString;
  EspValue: TRpnScalar;
begin
  ESP := 0;

    if FBaseESP <> '' then
    begin
      EspValue := Eval(FBaseESP);
      if not (valNum in EspValue.Kind) or (Frac(EspValue.Num) <> 0) then
        Error('ESP expression argument must evaluate to an integer value, got "%s" RPN type.', [RpnKindToStr(EspValue.Kind)]);

      ESP := Trunc(EspValue.Num);
    end;

    if (ESP = 0) and not FContext.GetRegister('ESP', ESP) and
       Error('error retrieving default ESP value from ESP register', []) then
      Exit;

  Msg := '';

    for I := 0 to FDepth - 1 do
    begin
      if FFmtChar = 'i' then
        Msg := Msg + IntToStr(I + 1) + '='
        else if FFmtChar <> '' then
          Msg := Msg + AhFormatOne(RpnNum(I * 4), FFmtChar[1]) + '=';

      Addr := PDWord(ESP + I * 4)^;
      Msg := Msg + IntToHex(Addr, 8);

      Module := FContext.ModuleNameOfAddr(Addr);
      if Module <> '' then
        if Module = ParamStrW(0) then
          Msg := Msg + ' [SELF]'
          else
          begin
            Module := ExtractFileName(Module);

            if LowerCase( ExtractFileExt(Module) ) = '.dll' then
              Module := ChangeFileExt(Module, '');

            Msg := Msg + ' [' + Module + ']';
          end;

      Msg := Msg + ', ';
    end;

  Delete(Msg, Length(Msg) - 1, 2);
  Log(logUser, 'Stack trace: %s', [Msg]);
end;

initialization
  SetRpnVarChars(RpnVarChars + '<>|&:^[]$');
  UnregisterDefaultRpnOperator('^', TRpnPower);

  Classes.RegisterClass(TLogAction);
  Classes.RegisterClass(TSaveAction);
  Classes.RegisterClass(TDumpAction);
  Classes.RegisterClass(TIfAction);
  Classes.RegisterClass(TStackAction);
end.
