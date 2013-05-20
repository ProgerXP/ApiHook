unit AhCommon;

interface

uses Windows, SysUtils, Contnrs, CLasses, IniFilesW, StringsW, FileStreamW,
     RPNit, StringUtils, Utils;

type
  TRpnScalar = RPNit.TRpnScalar;
  TAhLogLevel = (logDebug, logInfo, logUser, logError);  
  TAhCritSectionMode = (csNone, csPerProc, csGlobal);

  AhEx = class (Exception);
  EPipeIsClosing = class (AhEx);

  TAhSettings = record
    UseCriticalSections: TAhCritSectionMode;
    HookModule: array[0..255] of WideChar;
    UseThreads: Boolean;
    Pipe: array[0..255] of Char;
  end;

  TAhRegisters = record
    rEAX, rECX, rEDX, rEBX, rESP, rEBP, rESI, rEDI: DWord;
    rEIP: DWord;    // holds hooked proc caller's address.
    //ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7: Real;   // currently ST* capturing is unimplemented.
  end;

  TAhOnLog = procedure (Level: TAhLogLevel; Str: WideString; Fmt: array of const) of object;
  TAhSetSettings = function (const ASettings: TAhSettings): Boolean; stdcall;

  TAhPipe = class
  protected
    FHandle: THandle;
    FStream: THandleStream;
    FLogSend, FLogReceive: Boolean;
    FLastError: DWord;

    function ReadStr: WideString;
    function SendStr(const S: WideString): Boolean;

    function ReadDWord: DWord;
    function SendDWord(Value: DWord): Boolean;
    function ReadData(out Data; Size: Integer): Boolean;
    function SendData(const Data; Size: Integer): Boolean;

    function ReadCmd: WideString;
    procedure SendCmd(const Cmd: WideString);

    procedure SendEOS;
    procedure ReadEOS;

    procedure DoReport(Msg: WideString; Fmt: array of const); virtual; abstract;
    procedure PipeIsClosing; virtual;
  public
    // owns Handle.
    constructor Create(Handle: THandle); virtual;
    destructor Destroy; override;

    property Hadnle: THandle read FHandle;

    procedure Report(Msg: WideString; Fmt: array of const); virtual;
    procedure ReportData(Msg: WideString; Fmt: array of const); virtual; abstract;
    function SysErrorMsg: WideString;
  end;

    TAhServerPipe = class (TAhPipe)
    protected
      // returns True if pipe must be detached.
      function DoSend(const Cmd: WideString): Boolean; virtual; abstract;
    public
      procedure Send(const Cmd: WideString);
    end;

    TAhClientPipe = class (TAhPipe)
    protected
      // returns True if pipe must be detached.
      function DoRead(const Cmd: WideString): Boolean; virtual; abstract;
    public
      constructor ConnectTo(const NamedPipe: String);
      function Read: WideString;
    end;

  TAhLogger = class
  protected
    FFileName: WideString;
    FLog: TStream;
    FLevelsToLog: String;

    procedure CreateLog;
    function CanLog(Level: TAhLogLevel): Boolean;
  public
    constructor Create(const LogFN: WideString = '');
    destructor Destroy; override;

    property LevelsToLog: String read FLevelsToLog write FLevelsToLog;  // defaults to 'iue'.

    // if LogFN starts with '+' log file is appended if exists, otherwise it's rewritten.
    procedure Reopen(LogFN: WideString);
    procedure Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
  end;

  TAhLoggers = class
  protected
    FLogs: TObjectList;
  public
    constructor Create(AddDefault: Boolean = True);
    destructor Destroy; override;

    procedure Add(const LogFN, LevelsToLog: WideString);
    procedure AddDefault;
    procedure DeleteAll;
    function Count: Integer;

    procedure Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
  end;

  TAhConstants = class (TRpnVariables)
  public
    class function StrToValue(Str: WideString): TRpnScalar;
    class function Contains(const Full, Part: TRpnScalar; IsSetOf: Boolean): Boolean;

    // returns number of constants copied.
    function AssignFromSectionOf(Ini: TCustomIniFileW; const Section: WideString): Integer;

    function NameBy(const Value: TRpnScalar; const ConstNames: TWideStringArray;
      IsSetOf: Boolean; Joiner: WideString = ' '): WideString;
  end;

const
  AhVersion   = $0054;
  AhHomePage  = 'http://proger.i-forge.net/ApiHook';

  NilRPN      = '<NIL>';
  HostExitCodeOnLibShutdown = 8084;
  MaxPipeInitTime = 2 * 1000;
  MaxPipeExitTime = 5 * 1000;

  // when SizeOf is called inside CaptureRegisters or another asm proc it yields 50, not 32.
  RegistersSize = SizeOf(TAhRegisters);

  LogEOLN     = #13#10;
  LogPaths: array[0..4] of WideString = ('%TEMP%\', '%APPDATA%\', '\', 'C:\', 'D:\');

function LogLevelToPrefix(Level: TAhLogLevel): WideString;
function LogLevelToChar(Level: TAhLogLevel): Char;
function ExtractLogLevelFrom(var FN: WideString): WideString;

function AhSettings(UseCriticalSections: TAhCritSectionMode; UseThreads: Boolean; const Pipe: String;
  const HookModule: WideString = ''): TAhSettings;
function InlineAhScriptToFull(Script: WideString): WideString;

// replaces '$' in Msg with each item from Fmt; replaces '$$' with '$'.
// Fmt is a pipe-separated (|) list of format arguments.
function PortableFormat(Msg, Fmt: WideString): WideString;
// "converts" a call to standard Format into a tranmittable representation of all Fmt.
procedure MakePortableFormat(Msg: WideString; Fmt: array of const;
  out NewMsg, NewFmt: WideString);

implementation

function LogLevelToPrefix(Level: TAhLogLevel): WideString;
const
  Prefixes: array[TAhLogLevel] of WideString = ('[dbg]', '[inf]', '[usr]', '[err]');
begin
  Result := Prefixes[Level];
end;

function LogLevelToChar(Level: TAhLogLevel): Char;
const
  Chars: array[TAhLogLevel] of Char = ('d', 'i', 'u', 'e');
begin
  Result := Chars[Level];
end;

function ExtractLogLevelFrom(var FN: WideString): WideString;
const
  Levels: WideString = 'diue';
var
  I, Level: Integer;
begin
  I := 1;

  if (I <= Length(FN)) and (FN[I] = '+') then
    Inc(I);

  Level := 0;
  while (I <= Length(FN)) and (FN[I] = '#') do
  begin
    Inc(Level);
    Inc(I);
  end;

  Delete(FN, I - Level, Level);

  if Level = 0 then
    Result := 'iue'
    else
      Result := Copy(Levels, Level, MaxInt);
end;

function AhSettings(UseCriticalSections: TAhCritSectionMode; UseThreads: Boolean; const Pipe: String;
  const HookModule: WideString = ''): TAhSettings;
begin
  ZeroMemory(@Result, SizeOf(Result));

  Result.UseCriticalSections := UseCriticalSections;
  Result.UseThreads := UseThreads;
  Move(Pipe[1], Result.Pipe[0], Length(Pipe));
  Move(HookModule[1], Result.HookModule[0], Length(HookModule) * 2);
end;

function InlineAhScriptToFull(Script: WideString): WideString;
var
  Proc: WideString;
begin
  if Split(Script, ' ', Proc, Script) then
    Result := '[' + Proc + ']' + #13#10 +
              StrReplace(Script, ';', #13#10, [rfReplaceAll])
    else
      Result := '';
end;

function PortableFormat(Msg, Fmt: WideString): WideString;
var
  OrigMsg, Rest: WideString;
  Formats: TWideStringArray;
  CurFormat: Integer;
begin
  OrigMsg := Msg;
  Formats := ExplodeUnquoting('|', Fmt);
  CurFormat := 0;

  while Split(Msg, '$', Msg, Rest) do
  begin
    if Copy(Rest, 1, 1) = '$' then
    begin
      Result := Result + '$';
      Delete(Rest, 1, 1);
    end
      else
      begin
        if CurFormat >= Length(Formats) then
          raise AhEx.CreateFmt('Too few Fmt for PortableFormat(%s).', [OrigMsg]);

        Result := Result + Msg + Formats[CurFormat];
        Inc(CurFormat);
      end;

    Msg := Rest;
  end;

  if (CurFormat <> Length(Formats)) and ((Fmt <> '') or (CurFormat > 0)) then
    raise AhEx.CreateFmt('Too many Fmt for PortableFormat(%s).', [OrigMsg]);

  Result := Result + Msg;
end;

procedure MakePortableFormat(Msg: WideString; Fmt: array of const;
  out NewMsg, NewFmt: WideString);
var
  OrigMsg, Rest, ThisFmt: WideString;
  CurFormat, FmtEnd: Integer;

  function FindFmtEnd: Integer;
  const
    FmtMods = ['.', '-', '0'..'9'];
    FmtEnds = ['d', 'u', 'e', 'f', 'g', 'n', 'm', 'p', 's', 'x'];
  begin
    for Result := 1 to Length(Rest) do
      if not (Char(Rest[Result]) in FmtMods) then
        Break;

    if (Char(Rest[Result]) in FmtEnds) or
       ((Chr(Ord(Char(Rest[Result])) + 32 {lower case})) in FmtEnds) then
      Inc(Result);
  end;

begin
  OrigMsg := Msg;
  NewMsg := '';
  NewFmt := '';
  CurFormat := 0;

  Msg := StrReplace(Msg, '$', '$$', [rfReplaceAll]);

  while Split(Msg, '%', Msg, Rest) do
  begin
    if Copy(Rest, 1, 1) = '%' then
    begin
      NewMsg := NewMsg + '%';
      Delete(Rest, 1, 1);
    end
      else
      begin
        if CurFormat >= Length(Fmt) then
          raise AhEx.CreateFmt('Too few Fmt for MakePortableFormat(%s).', [OrigMsg]);

        FmtEnd := FindFmtEnd;
        ThisFmt := Copy(Rest, 1, FmtEnd - 1);
        Rest := Copy(Rest, FmtEnd, MaxInt);

        NewMsg := NewMsg + Msg + '$';

        ThisFmt := WideFormat('%' + ThisFmt, Fmt[CurFormat]);
        NewFmt := NewFmt + '|' + StrReplace(ThisFmt, '|', '||', [rfReplaceAll]);

        Inc(CurFormat);
      end;

    Msg := Rest;
  end;

  if CurFormat <> Length(Fmt) then
    raise AhEx.CreateFmt('Too many Fmt for MakePortableFormat(%s).', [OrigMsg]);

  NewMsg := NewMsg + Msg;
  Delete(NewFmt, 1, 1);
end;

{ TAhPipe }

constructor TAhPipe.Create(Handle: THandle);
begin
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) then
    raise AhEx.CreateFmt('Cannot open named pipe: (%d) %s', [GetLastError, SysErrorMessage(GetLastError)]);

  FLogSend := False;
  FLogReceive := False;
  FLastError := 0;

  FHandle := Handle;
  FStream := THandleStream.Create(Handle);
end;

destructor TAhPipe.Destroy;
begin
  FStream.Free;
  CloseHandle(FHandle);

  inherited;
end;

function TAhPipe.ReadStr: WideString;
var
  Len: Integer;
begin
  if FStream.Read(Len, SizeOf(Len)) <> SizeOf(Len) then
    Report('error reading string length: %s', [SysErrorMsg]);

  SetLength(Result, Len);
  if (Len > 0) and (FStream.Read(Result[1], Len * 2) <> Len * 2) then
    Report('error reading string data of length %d * 2.', [Len * 2]);

  if FLogReceive then
    ReportData('recv> ' + Result, []);
end;

function TAhPipe.SendStr(const S: WideString): Boolean;
var
  Len: Integer;
begin
  if FLogSend then
    ReportData('send> ' + S, []);

  Len := Length(S);

  Result := FStream.Write(Len, SizeOf(Len)) = SizeOf(Len);
  Result := (FStream.Write(S[1], Len * 2) = Len * 2) and Result;

  if not Result then
    Report('error sending string "%s": %s.', [S, SysErrorMsg]);
end;

function TAhPipe.ReadData(out Data; Size: Integer): Boolean;
begin
  Result := FStream.Read(Data, Size) = Size;

  if not Result then
    Report('error reading %d bytes of data: %s', [Size, SysErrorMsg]);

  if FLogReceive then
    ReportData('recv$ ' + BinToHex(Result, Size, ' '), []);
end;

function TAhPipe.SendData(const Data; Size: Integer): Boolean;
begin
  if FLogSend then
    ReportData('send% ' + BinToHex(Data, Size, ' '), []);

  Result := FStream.Write(Data, Size) = Size;

  if not Result then
    Report('error sending %d bytes of data: %s', [Size, SysErrorMsg]);
end;

function TAhPipe.ReadDWord: DWord;
begin
  ReadData(Result, SizeOf(Result));
end;

function TAhPipe.SendDWord(Value: DWord): Boolean;
begin
  Result := SendData(Value, SizeOf(Value));
end;

function TAhPipe.ReadCmd: WideString;
begin
  Result := ReadStr;

  if (Result = '') or (Result[1] <> '<') or (Result[Length(Result)] <> '>') or
     (Result <> UpperCase(Result)) then
    Report('expected to read a "<COMMAND>" but "%s" was read.', [Result]);

  Result := Copy(Result, 2, Length(Result) - 2);
end;

procedure TAhPipe.SendCmd(const Cmd: WideString);
begin
  if not SendStr( '<' + UpperCase(Cmd) + '>' ) then
    Report('error sending command name "%s".', [Cmd]);
end;

procedure TAhPipe.SendEOS;
begin
  if not SendStr('EOS') then
    Report('error sending "EOS".', []);
end;

procedure TAhPipe.ReadEOS;
begin
  if ReadStr <> 'EOS' then
    Report('expected to read "EOS".', []);
end;

function TAhPipe.SysErrorMsg: WideString;
begin
  FLastError := GetLastError;
  Result := WideFormat('(#%d) %s', [FLastError, SysErrorMessage(FLastError)]);
end;

procedure TAhPipe.Report(Msg: WideString; Fmt: array of const);
begin
  if (FLastError = ERROR_BROKEN_PIPE) or (FLastError = ERROR_NO_DATA) then
    PipeIsCLosing
    else
      DoReport(Msg, Fmt);
end;

procedure TAhPipe.PipeIsClosing;
begin
  raise EPipeIsClosing.Create('Named pipe is closing.');
end;

{ TAhServerPipe }

procedure TAhServerPipe.Send(const Cmd: WideString);
begin
  SendCmd(Cmd);

  try
    if DoSend(UpperCase(Cmd)) then
      Exit;
  except
    on E: Exception do
      Report('exception while sending "%s": <%s> %s', [Cmd, E.ClassName, E.Message]);
  end;

  SendEOS;
end;

{ TAhClientPipe }

constructor TAhClientPipe.ConnectTo(const NamedPipe: String);
begin
  inherited Create(FileCreate(NamedPipe));
end;

function TAhClientPipe.Read: WideString;
begin
  Result := ReadCmd;

  try
    if DoRead(Result) then
      Exit;
  except
    on E: Exception do
      Report('exception while reading "%s": <%s> %s', [Result, E.ClassName, E.Message]);
  end;

  ReadEOS;
end;

{ TAhLogger }

constructor TAhLogger.Create(const LogFN: WideString);
begin
  FLog := NIL;
  FLevelsToLog := 'iue';

  Reopen(LogFN);
end;

destructor TAhLogger.Destroy;
begin
  if FLog <> NIL then
    FLog.Free;
  inherited;
end;

procedure TAhLogger.Reopen(LogFN: WideString);
begin
  if FLog <> NIL then
    FLog.Free;

  FFileName := LogFN;
end;

procedure TAhLogger.Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
begin
  if CanLog(Level) then
  begin
    CreateLog;

    if FLog <> NIL then
    begin
      if Length(Fmt) > 0 then
        Msg := WideFormat(Msg, Fmt);

      Msg := LogLevelToPrefix(Level) + ' ' + Msg + LogEOLN;
      FLog.Write(Msg[1], Length(Msg) * 2);
    end;
  end;
end;

function TAhLogger.CanLog(Level: TAhLogLevel): Boolean;
begin
  Result := PosW(LogLevelToChar(Level), FLevelsToLog) > 0;
end;

procedure TAhLogger.CreateLog;
  function Construct(Append: Boolean): Boolean;
  begin
    try
      if Append and FileExists(FFileName) then
        FLog := TFileStreamW.Create(FFileName, fmOpenReadWrite or fmShareDenyNone)
        else
          FLog := TFileStreamW.CreateCustom(FFileName, fmForcePath or fmShareDenyNone);

      Result := True;
    except
      Result := False;
    end;
  end;

var
  BaseName: WideString;
  Append: Boolean;
  I: Integer;
begin
  if (FLog = NIL) and (FFileName <> '-') then
  begin
    Append := Copy(FFileName, 1, 1) = '+';
    if Append then
      Delete(FFileName, 1, 1);

    if FFileName = '' then
    begin
      BaseName := ExtractFileName(ParamStrW(0)) + '.log';

      for I := 0 to Length(LogPaths) - 1 do
      begin
        FFileName := ResolveEnvVars(LogPaths[I]) + BaseName;
        if Construct(Append) then
          Break;
      end;
    end
      else
        Construct(Append);
  end;
end;

{ TAhLoggers }

constructor TAhLoggers.Create(AddDefault: Boolean = True);
begin
  FLogs := TObjectList.Create(True);

  if AddDefault then
    Self.AddDefault;
end;

destructor TAhLoggers.Destroy;
begin
  FLogs.Free;
  inherited;
end;

procedure TAhLoggers.Add(const LogFN, LevelsToLog: WideString);
var
  Log: TAhLogger;
begin
  if LogFN <> '-' then
  begin
    Log := TAhLogger.Create(LogFN);
    try
      Log.LevelsToLog := LevelsToLog;
      FLogs.Add(Log);
    except
      Log.Free;
      raise;
    end;
  end;
end;

procedure TAhLoggers.AddDefault;
begin
  Add('', 'iue');
end;

procedure TAhLoggers.DeleteAll;
begin
  FLogs.Clear;
end;

function TAhLoggers.Count: Integer;
begin
  Result := FLogs.Count;
end;

procedure TAhLoggers.Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    (FLogs[I] as TAhLogger).Log(Level, Msg, Fmt);
end;

{ TAhConstants }

class function TAhConstants.StrToValue(Str: WideString): TRpnScalar;
var
  Num: Integer;
  Dbl: Double;
  FS: TFormatSettings;
begin
  Str := Trim(Str);
  FS.DecimalSeparator := '.';

  if Str = '' then
    raise AhEx.Create('Empty constant value.')
    else if (Length(Str) > 1) and (Str[1] = '''') and (Str[Length(Str)] = '''') then
      Result := RpnStr(Copy(Str, 2, Length(Str) - 2))
      else if TryStrToInt(Str, Num) then
        if Char(Str[1]) in ['-', '+'] then
          Result := RpnNum(Num)
          else
            Result := RpnNum(DWord(Num))
        else if TryStrToFloat(Str, Dbl, FS) then
          Result := RpnNum(Dbl)
          else if Str = 'TRUE' then
            Result := RpnBool(True)
            else if Str = 'FALSE' then
              Result := RpnBool(False)
              else if Copy(Str, 1, 2) = 'x ' then
                Result := RpnBytes(HexToBin( StrReplace(Copy(Str, 3, MaxInt), ' ', '', [rfReplaceAll]) ))
                else
                  Result := RpnStr(Str);
end;

function TAhConstants.AssignFromSectionOf(Ini: TCustomIniFileW; const Section: WideString): Integer;
var
  Values: TStringListW;
  I: Integer;
begin
  Result := 0;

  Values := TStringListW.Create;
  try
    Ini.ReadSectionValues(Section, Values);

    for I := 0 to Values.Count - 1 do
      if (Values.ValueFromIndex[I] <> '') and not (Char( Values[I][1] ) in [';', '#']) then
      begin
        Add( Trim(Values.Names[I]), StrToValue(Values.ValueFromIndex[I]) );
        Inc(Result);
      end;
  finally
    Values.Free;
  end;
end;

function TAhConstants.NameBy(const Value: TRpnScalar; const ConstNames: TWideStringArray;
  IsSetOf: Boolean; Joiner: WideString = ' '): WideString;

  procedure Walk(const Names: TWideStringArray);
  var
    I: Integer;
  begin
    for I := 0 to Length(Names) - 1 do
      if Contains(Value, Get(NIL, Names[I]), IsSetOf) then
      begin
        if Result <> '' then
          Result := Result + Joiner;
        Result := Result + Names[I];
      end;
  end;

var
  I: Integer;
begin
  Result := '';

  for I := 0 to Length(ConstNames) - 1 do
    Walk( GetMatching(ConstNames[I]) );
end;

class function TAhConstants.Contains(const Full, Part: TRpnScalar; IsSetOf: Boolean): Boolean;
begin
  if [valNum] * Full.Kind * Part.Kind <> [] then
    if IsSetOf and (Frac(Full.Num) = 0) and (Frac(Part.Num) = 0) then
      Result := Trunc(Full.Num) and Trunc(Part.Num) <> 0
      else
        Result := Full.Num = Part.Num
    else if [valBool] * Full.Kind * Part.Kind <> [] then
      Result := Full.Bool = Part.Bool
      else if [valStr] * Full.Kind * Part.Kind <> [] then
        if IsSetOf then
          Result := PosW(Part.Str, Full.Str) <> 0
          else
            Result := Full.Str = Part.Str
        else if [valBytes] * Full.Kind * Part.Kind <> [] then
          if IsSetOf then
            Result := Pos(Part.Bytes, Full.Bytes) <> 0
            else
              Result := Full.Bytes = Part.Bytes
          else
            Result := False;
end;

end.
