program ah;

{$APPTYPE CONSOLE}

uses
  FastShareMem, Windows, MMSystem, SysUtils, Classes, FileStreamW, StringsW,
  Threads, CommandLine, ColorConsole, StringUtils, Utils, AhCommon;

type
  PLoaderData = ^TLoaderData;
  TLoaderData = record
    LoadLibraryW: function (lpLibFileName: PWideChar): HMODULE; stdcall;
    GetProcAddress: function (hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall;
    ExitThread: procedure (dwExitCode: DWORD); stdcall;

    DLL: array[0..MAX_PATH] of WideChar;
    BootstrapProc: array[0..255] of Char;

    JustLoad: DWord;    // 0 = False, 1 = True.
    Settings: TAhSettings;
  end;

  TAhProcInfo = record
    ProcessID, Thread: DWord;
  end;

  TAhConsolePipe = class (TAhServerPipe)
  protected
    function DoSend(const Cmd: WideString): Boolean; override;
    procedure DoReport(S: WideString; Fmt: array of const); override;
  public
    procedure ReportData(S: WideString; Fmt: array of const); override;
  end;

  TApiHookApp = class (TCLColorApplication)
  protected
    FInitialCWD: WideString;
    FLogLevel: TAhLogLevel;
    FLogTimeFmt, FPreviousLog: WideString;
    FOutputCritSection: TRTLCriticalSection;

    FArgs: record
      DLL, Script: WideString;
    end;

    FPipeName: String;
    FPipe: TAhConsolePipe;
    FPipeData: record
      ProcToResume: TAhProcInfo;
      IsPipeInitialized: Boolean;
      DetachType: WideString;
      SendScript: Integer;

      ClientVersion: Word;
      LibLogLevel: TAhLogLevel;
      LibLogs, UserPath: WideString;
      Catalog, Script: WideString;
      LastLogLevel: TAhLogLevel;
      LastLog: WideString;
    end;

    FPipeThread: TSingleThread;
    FExitPipeThread: Boolean;

    procedure Init; override;
    function CreateLang: TCLAppLang; override;

    function TryDoingTask(Task: WideString): Boolean; override;
    function Launch(const DLL, EXE: WideString): Boolean;
      function GetLdrSettings: TAhSettings;                     
    function Attach(const DLL, Process: WideString): Boolean;
    function Inject(const DLL, EXE: WideString): Boolean;
    function AttachToSelf(const DLL: WideString): Boolean;

    function CreateProc(const DLL, EXE: WideString): TAhProcInfo;
    function FindProc(const DLL, Process: WideString): TAhProcInfo;
    function InjectAndPipe(const Proc: TAhProcInfo; const DLL: WideString;
      const LdrData: TLoaderData): Boolean;
    function InjectInto(const Proc: TAhProcInfo; const DLL: WideString;
      const LdrData: TLoaderData): Boolean;
    function AllocAndLoadInto(Proc: THandle; const DLL: WideString;
      const Data: TLoaderData): Boolean;

      procedure ResumeProc(const Proc: TAhProcInfo);
      function VAllocAndWriteTo(Proc: THandle; const Data; Size: DWord): Pointer;
      procedure VDealloc(Proc: THandle; Addr: Pointer; Size: DWord);

    procedure Output(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
    function WatchLogLine(Line: WideString; Data: DWord): Boolean;

    procedure WriteStringTo(Handle: DWord; Str: WideString); override;
    function OnCtrlEvent(Event: DWord): Boolean; override;

    function InitPipe: String;
    function InitPipeName: String;
    procedure FreePipe;

    procedure InitLibraryViaPipe;
    procedure EnterPipeLoop; overload;
    procedure EnterPipeLoop(const ProcToResume: TAhProcInfo); overload;
    function PipeThread(Caller: TObject; const Arguments: TProcArguments): DWord;
    procedure LeavePipeLoop;
  public
    destructor Destroy; override;
    procedure SetInfo; override;

    procedure AcquireOptions; override;
    procedure AcquireTaskArgs(const Task: WideString);
    function ReadPostActionFor(const Task: WideString): WideString;
    procedure WatchLogLoop(const LogFile: WideString; Interval: Integer);

    function ExpandPath(Path, BasePath: WideString): WideString;

    procedure Error(Msg: WideString; Fmt: array of const);
    procedure Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);

    function SysErrorMsg(Code: Integer = -1): WideString;

    function GetLogLevelOpt(const Option: WideString): TAhLogLevel;
    function GetFlagOpt(const Option: WideString; AlwaysSet: Integer = 0; Default: Integer = 0): Integer;
  end;

const
  { Loader thread exit codes: }
  ThreadOK            = 700;
  ThreadLibError      = 701;
  ThreadSettingsError = 702;

  // controls how often the loader checks attached library for new log messages given
  // that previous check returned that there were no new messages.
  PipeLoopIdleSleep   = 250;
  // complements PipeLoopIdleSleep - the delay of fetching next log message given that
  // last time at least one new message has been retrieved.
  PipeLoopFetchNextSleep = 50;

  RemoteThreadTimeout = 5 * 1000;
  DefaultWatchInterval = 500;   // msec

  PipePrefix          = '\\.\pipe\ApiHook\';
  PipeMode            = PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT;
  MaxPipeClients      = 1;

var
  App: TApiHookApp;

{$R *.res}
{$R Resources.res}

function AhProcInfo(const ProcInfo: TProcessInformation): TAhProcInfo;
begin
  Result.ProcessID := ProcInfo.dwProcessId;
  Result.Thread := ProcInfo.hThread;
end;

function LoaderData(const DLL: WideString; JustLoad: Boolean; const Settings: TAhSettings): TLoaderData; overload;
begin
  ZeroMemory(@Result, SizeOf(Result));

  @Result.LoadLibraryW := GetProcAddress(GetModuleHandle(kernel32), 'LoadLibraryW');
  @Result.GetProcAddress := GetProcAddress(GetModuleHandle(kernel32), 'GetProcAddress');
  @Result.ExitThread := GetProcAddress(GetModuleHandle(kernel32), 'ExitThread');

  Move(DLL[1], Result.DLL[0], Length(DLL) * 2);
  Result.BootstrapProc := 'Bootstrap';

  Result.JustLoad := DWord(JustLoad);
  Move(Settings, Result.Settings, SizeOf(Settings));

  with Result do
    if not Assigned(LoadLibraryW) or not Assigned(GetProcAddress) or not Assigned(ExitThread)
       or (lstrlenw(@DLL[0]) = 0) or ((JustLoad = 0) and (lstrlen(@Settings.Pipe[0]) = 0)) then
      App.Language.RaiseText('error: LoaderData init', []);
end;

function LoaderData(const DLL: WideString; const Settings: TAhSettings): TLoaderData; overload;
begin
  Result := LoaderData(DLL, False, Settings);
end;

procedure Loader(Data: PLoaderData); stdcall;
var
  Lib: THandle;
  SetSettings: TAhSetSettings;
asm
  { Output:  EAX - thread exit code. }

  { How to address records/record pointers in Delphi assembler:
    http://docwiki.embarcadero.com/RADStudio/en/Assembly_Expressions#Symbols }

  PUSH  ECX
  PUSH  EBP
  MOV   EBP, Data

  LEA   EAX, TLoaderData[EBP].DLL[0]
  PUSH  EAX
  CALL  TLoaderData[EBP].LoadLibraryW
  TEST  EAX, EAX
  JNZ   @getAddr

  MOV   EAX, ThreadLibError
  JMP   @exit

  @getAddr:
  MOV   ECX, TLoaderData[EBP].JustLoad
  TEST  ECX, ECX
  JNZ   @success

  LEA   ECX, TLoaderData[EBP].BootstrapProc[0]
  PUSH  ECX
  PUSH  EAX
  CALL  TLoaderData[EBP].GetProcAddress
  TEST  EAX, EAX
  JNZ   @bootstrap

  MOV   EAX, ThreadLibError
  JMP   @exit

  @bootstrap:
  LEA   ECX, TLoaderData[EBP].Settings
  PUSH  ECX
  CALL  EAX
  TEST  EAX, EAX
  JNZ   @success

  MOV   EAX, ThreadSettingsError
  JMP   @exit

  @success:
  MOV   EAX, ThreadOK

  @exit:
  POP   EBP
  POP   ECX
end;

procedure LoaderEnd;
asm
end;

{ TApiHookApp }

procedure TApiHookApp.Init;
begin
  inherited;

  FPreviousLog := '';

  FPipeName := '';
  FPipe := NIL;
  ZeroMemory(@FPipeData, SizeOf(FPipeData));

  InitializeCriticalSection(FOutputCritSection);
end;

destructor TApiHookApp.Destroy;
begin
  DeleteCriticalSection(FOutputCritSection);
  FreePipe;

  // useful for debug and 'self' task - if the hook library isn't unloaded Access Violations occur.
  FreeLibrary(GetModuleHandleW( PWideChar(FArgs.DLL) ));

  inherited;
end;

function TApiHookApp.CreateLang: TCLAppLang;
begin
  Result := inherited CreateLang;

  if FileExists('en.ini') then
    Result.LoadFromIniFile('en.ini')
    else
      Result.LoadFromResource('LANG');
end;

procedure TApiHookApp.AcquireOptions;
var
  NewCWD: WideString;
begin
  inherited;

  FLogTimeFmt := FCLParser.Options['log-time'];
  if FLogTimeFmt = FCLParser.NotPassed then
    FLogTimeFmt := FLang['log time'];

  FLogLevel := GetLogLevelOpt('verbose');
  FInitialCWD := CurrentDirectory;

  NewCWD := FCLParser['chdir'];
  if (NewCWD <> FCLParser.NotPassed) then
  begin
    NewCWD := ExpandPath(NewCWD, ExtractFilePath( ParamStrW(0) ));

    if NewCWD <> CurrentDirectory then
      if ChDir(NewCWD) then
        Log(logDebug, 'ack: --chdir', [NewCWD])
        else
          Log(logError, 'error: no --chdir', [NewCWD, CurrentDirectory]);
  end;
end;

function TApiHookApp.ExpandPath(Path, BasePath: WideString): WideString;
begin
  if Path = '' then
    Path := '.';

  if Path[1] = '$' then
    Path := IncludeTrailingPathDelimiter( BasePath ) + ExcludeLeadingPathDelimiter( Copy(Path, 2, MaxInt) );

  Result := ExpandFileName(Path, FInitialCWD);
end;

procedure TApiHookApp.SetInfo;
begin
  Name := 'ApiHook';
  Version := AhVersion;
  Author := 'Proger_XP';
  WWW := AhHomePage;
  BuildDate := $10022012;

  Help := FLang['help'];
  HelpDetails := FLang['help details'];

  TaskAliases['h'] := 'help';
  TaskAliases['l'] := 'launch';
  TaskAliases['a'] := 'attach';
  TaskAliases['i'] := 'inject';
  TaskAliases['e'] := 'extend';
  TaskAliases['s'] := 'self';
end;

procedure TApiHookApp.Output(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
const
  TimeColors: array[TAhLogLevel] of WideString = ('@i', 'i@wi', '@gi',  '@mi');
  SoonColors: array[TAhLogLevel] of WideString = ('@i', 'i',    'gi',   'mi');
var
  Time: WideString;
begin
  if Level >= FLogLevel then
    if Msg <> '' then
    begin
      EnsureConsoleAtNewLine;

      if Length(Fmt) > 0 then
        Msg := FLang.Format(Msg, Fmt)
        else
          Msg := FLang[Msg];

      if FLogTimeFmt = '' then
        ConsoleWriteLn(Msg)
        else
        begin
          Time := FormatDateTime(FLogTimeFmt, Now);

          if FPreviousLog = Time then
            ConsoleWriteLn( FLang.Format('log soon', [SoonColors[Level], Msg]) )
            else
            begin
              FPreviousLog := Time;
              ConsoleWriteLn( FLang.Format('log', [TimeColors[Level], Time, Msg]) );
            end;
        end;
    end
      else
        ConsoleWriteLn
end;

  procedure TApiHookApp.Error(Msg: WideString; Fmt: array of const);
  begin
    Output(logError, Msg, Fmt);
  end;

  procedure TApiHookApp.Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
  begin
    Output(Level, Msg, Fmt);
  end;

procedure TApiHookApp.WriteStringTo(Handle: DWord; Str: WideString);
begin
  EnterCriticalSection(FOutputCritSection);
  try
    inherited;
  finally
    LeaveCriticalSection(FOutputCritSection);
  end;
end;

function TApiHookApp.InitPipe: String;
var
  Handle: THandle;
begin
  if FPipe = NIL then
  begin
    Handle := CreateNamedPipe(PChar(InitPipeName), PIPE_ACCESS_DUPLEX,
                              PipeMode, MaxPipeClients, 0, 0, 0, NIL);

    if Handle = INVALID_HANDLE_VALUE then
    begin
      Result := FPipeName;
      FPipeName := '';
      FLang.RaiseText('error: CreateNamedPipe', [Result, PipeMode, SysErrorMsg]);
    end;

    FPipe := TAhConsolePipe.Create(Handle);
  end;

  Result := FPipeName;
end;

function TApiHookApp.InitPipeName: String;
begin
  if FPipeName = '' then
    repeat
      FPipeName := PipePrefix + Copy(ExtractFileName(ParamStr(0)), 1, 50) + '\' + IntToStr(Random(MaxInt));
    until not WaitNamedPipe(PChar(FPipeName), 0) and (GetLastError <> ERROR_SEM_TIMEOUT);

  Result := FPipeName;
end;

procedure TApiHookApp.FreePipe;
begin
  LeavePipeLoop;

  if FPipe <> NIL then
    FreeAndNIL(FPipe);
end;

function TApiHookApp.TryDoingTask(Task: WideString): Boolean;
  function GetEXE: WideString;
  begin
    Result := ExpandFileName(TaskArg(Task));

    if (ExtractFileExt(Result) = '') and not FileExists(Result) and FileExists(Result + '.exe') then
      Result := Result + '.exe';
  end;

var
  Action: WideString;
begin
  Result := True;
  AcquireTaskArgs(Task);

  if Task = 'launch' then
    RanOK := Launch(FArgs.DLL, GetEXE)
    else if Task = 'attach' then
      RanOK := Attach(FArgs.DLL, TaskArg(Task))
      else if Task = 'inject' then
        RanOK := Inject(FArgs.DLL, GetEXE)
        else if Task = 'self' then
          RanOK := AttachToSelf(FArgs.DLL)
          else
            Result := inherited TryDoingTask(Task);

  if FPipeThread = NIL then
    Action := ''
    else if FCLParser.IsSwitchOn('detach') then
      Action := FCLParser.GetOrDefault('detach', 'd')
      else
        Action := ReadPostActionFor(Task);

  FreePipe;   // the sooner we disconnect it the better - less chances for resources to go unavailable.

  if Action = 'k' then
    FWaitOnExit := clAlwaysWait
    else if Action = 'w' then
      if FCLParser.IsPassed('lib-logs') then
        WatchLogLoop(FCLParser['lib-logs'], StrToIntDef(FCLParser['watch-interval'], DefaultWatchInterval))
        else
          Log(logError, 'post action: no watch log', []);
end;

  procedure TApiHookApp.AcquireTaskArgs(const Task: WideString);
    function GetScriptArgIndex: Integer;
    begin
      if (Task = 'launch') or (Task = 'attach') or (Task = 'inject') then
        Result := 1
        else if Task = 'self' then
          Result := 0
          else
            Result := -1;
    end;

  var
    I: Integer;
  begin
    with FArgs do
    begin
      if (Task = 'inject') or (Task = 'extend') then
        DLL := TaskArg(Task, 1)
        else
        begin
          DLL := FCLParser['lib'];
          if DLL = FCLParser.NotPassed then
          begin
            DLL := 'ApiHook.dll';
            Log(logDebug, 'ack: --lib', [DLL]);
          end;
        end;

      DLL := ExpandFileName(DLL);

      I := GetScriptArgIndex;
      if I = -1 then
        Script := ''
        else
        begin
          Script := '';

          if FCLParser.ArgCount - 1 <= I {task is arg #0} then
            if FileExists('Script.oo') then
              Script := 'Script.oo'
              else if FileExists('Script.txt') then
                Script := 'Script.txt';

          if Script = '' then
            Script := TaskArg(Task, I);

          if (ExtractFileExt(Script) = '') and not FileExists(Script) then
            if FileExists(Script + '.oo') then
              Script := Script + '.oo'
              else if FileExists(Script + '.txt') then
                Script := Script + '.txt';
        end;
    end;
  end;

  function TApiHookApp.ReadPostActionFor(const Task: WideString): WideString;
  var
    TimeStart: DWord;
  begin
    Result := '';

    TimeStart := timeGetTime;
    while not FPipeData.IsPipeInitialized and (timeGetTime - TimeStart < MaxPipeInitTime) do
      Sleep(MaxPipeInitTime div 10);

    if Task = 'self' then
    begin
      ConsoleWrite( FLang['post action: self'] );
      ConsoleWaitForEnter;
    end
      else if (Task = 'launch') or (Task = 'attach') then
        while RanOK and not FExitPipeThread and ( (Result = '') or (Result = #0) ) do
        begin
          if Result = '' then
            ConsoleWrite( FLang['post action'] )
            else
              ConsoleWrite( FLang['post action repeat'] );

          ReadLn(Result);
          Result := LowerCase(Copy(Result, 1, 1));

          if (Result = 'd') or (Result = 'w') then
            { Leave }
            else if (Result = 't') or (Result = 'k') then
              FPipeData.DetachType := 'TERMINATE'
              else if Result = 'r' then
                FPipeData.DetachType := 'RESTORE'
                else if (Result = 's') and FileExists(FArgs.Script) then
                begin
                  FPipeData.Script := TFileStreamW.LoadUnicodeFrom(FArgs.Script);
                  InterlockedIncrement(FPipeData.SendScript);
                  ConsoleWriteLn( FLang.Format('post action: script reloaded', [FArgs.Script]) );
                  Result := #0;
                end
                  else
                    Result := #0;
        end;
  end;

  procedure TApiHookApp.WatchLogLoop(const LogFile: WideString; Interval: Integer);
  const
    MaxTail = 20480;
  var
    Stream: TFileStreamW;
    LastPos, NewSize: DWord;
    Tail: WideString;
  begin
    if Interval < 20 then
      Interval := 20;

    LastPos := FileSize(LogFile);
    Log(logInfo, 'post action: watch', [LogFile, LastPos, Interval]);

    repeat
      Sleep(Interval);
      NewSize := FileSize(LogFile);

      if LastPos > NewSize then
      begin
        Log(logInfo, 'post action: watch shrunk', [LastPos - NewSize, NewSize]);
        LastPos := 0;
      end;

      if (LastPos < NewSize) and (NewSize > 0) then
      begin
        if NewSize - LastPos > MaxTail then
          SetLength(Tail, MaxTail div 2)
          else
            SetLength(Tail, (NewSize - LastPos) div 2);

        Stream := TFileStreamW.Create(LogFile, fmOpenRead + fmShareDenyNone);
        try
          Stream.Position := LastPos;
          Stream.Read(Tail[1], Length(Tail) * 2);
        finally
          Stream.Free;
        end;
                                                
        if NewSize - LastPos > MaxTail then
          Tail := Tail + '...';
        CallOnEachLineIn(Tail, WatchLogLine);

        if NewSize - LastPos > MaxTail then
          Log(logInfo, 'post action: watch tong tail', [NewSize - LastPos - MaxTail]);

        LastPos := NewSize;
      end;
    until not RanOK;
  end;

  function TApiHookApp.WatchLogLine(Line: WideString; Data: DWord): Boolean;
  begin
    Result := False;

    try
      Log(logUser, Line, []);
    except
      on EColorConsole do
        Log(logUser, CCQuote(Line), []);
    end;
  end;

function TApiHookApp.GetLogLevelOpt(const Option: WideString): TAhLogLevel;
var
  Level: WideString;
begin
  Level := FCLParser[Option];

  if (Level = '') or (Level = 'd') then
    Result := logDebug
    else if (Level = FCLParser.NotPassed) or (Level = 'i') then
      Result := logInfo
      else if Level = 'u' then
        Result := logUser
        else if Level = 'e' then
          Result := logError
          else
          begin
            Result := logInfo;
            Error('error: wrong log level', [Option, Level]);
          end;
end;

function TApiHookApp.GetFlagOpt(const Option: WideString; AlwaysSet, Default: Integer): Integer;
var
  Str: WideString;
begin
  Result := Default;

  Str := FCLParser[Option];
  if (Str <> FCLParser.NotPassed) and not TryStrToInt(Str, Result) then
    Error('error: launch: wrong flag option', [Option, Str]);

  Result := Result or AlwaysSet;
end;

function TApiHookApp.SysErrorMsg(Code: Integer = -1): WideString;
begin
  if Code = -1 then
    Code := GetLastError;

  Result := FLang.Format('syserrormsg', [Code, SysErrorMessage(Code)]);
end;

function TApiHookApp.CreateProc(const DLL, EXE: WideString): TAhProcInfo;
var
  CL, CWD: WideString;
  StartupInfo: TStartupInfo;
  Flags: Integer;
  ProcInfo: TProcessInformation;
begin
  if not FileExists(DLL) then
    FLang.RaiseText('error: launch: no lib', [DLL]);
  if not FileExists(EXE) then
    FLang.RaiseText('error: launch: no exe', [EXE]);

  CL := FCLParser['cl'];
  if CL = FCLParser.NotPassed then
    CL := '';

  CWD := FCLParser['new-dir'];
  if CWD = FCLParser.NotPassed then
    CWD := '';
  CWD := ExpandPath(CWD, ExtractFilePath(EXE));
  Log(logDebug, 'ack: --new-dir', [CWD]);

  Flags := GetFlagOpt('proc-flags', CREATE_SUSPENDED, CREATE_NEW_CONSOLE);
  if not FCLParser.IsSwitchOn('suspend', True) then
    Flags := Flags and not CREATE_SUSPENDED;

  ZeroMemory(@StartupInfo, SizeOf(StartupInfo));
  if not CreateProcessW(PWideChar(EXE), PWideChar(CL), NIL, NIL, False, Flags, NIL,
                        PWideChar(CWD), StartupInfo, ProcInfo) then
    FLang.RaiseText('error: launch: CreateProcess', [EXE, CWD, SysErrorMsg]);

  Result := AhProcInfo(ProcInfo);
end;

function TApiHookApp.FindProc(const DLL, Process: WideString): TAhProcInfo;
var
  ID: Integer;
  Flags: DWord;
begin
  if not TryStrToInt(Process, ID) then
    FLang.RaiseText('error: attach: invalid id', [Process]);

  Result.ProcessID := ID;

  Flags := GetFlagOpt('open-flags', 0, THREAD_QUERY_INFORMATION or THREAD_SUSPEND_RESUME or THREAD_TERMINATE);
  Result.Thread := MainThreadHandleOf(Result.ProcessID, Flags);
  
  if Result.Thread = 0 then
    FLang.RaiseText('error: attach: cannot get thread', [Result.ProcessID]);
end;

function TApiHookApp.Launch(const DLL, EXE: WideString): Boolean;
var
  Proc: TAhProcInfo;
begin
  Proc := CreateProc(DLL, EXE);
  Result := InjectAndPipe(Proc, DLL, LoaderData(DLL, GetLdrSettings));
end;

  function TApiHookApp.GetLdrSettings: TAhSettings;
  var
    ThreadSafe: TAhCritSectionMode;
  begin
    with FCLParser do
    begin
      if IsSwitchOn('thread-safe', True) then
        if Options['thread-safe'] = 'p' then
          ThreadSafe := csPerProc
          else
            ThreadSafe := csGlobal
        else
          ThreadSafe := csNone;

      Result := AhSettings(ThreadSafe, IsSwitchOn('threads', True), InitPipe, GetOrDefault('module', ''));
    end;
  end;

function TApiHookApp.Attach(const DLL, Process: WideString): Boolean;
var
  Proc: TAhProcInfo;
begin
  Proc := FindProc(DLL, Process);

  if FCLParser.IsSwitchOn('suspend', True) then
    SuspendThread(Proc.Thread);

  Result := InjectAndPipe(Proc, DLL, LoaderData(DLL, GetLdrSettings));
end;

function TApiHookApp.Inject(const DLL, EXE: WideString): Boolean;
var
  Proc: TAhProcInfo;
begin
  Proc := CreateProc(DLL, EXE);
  Result := InjectInto( Proc, DLL, LoaderData(DLL, True, AhSettings(csNone, False, '')) );
  ResumeProc(Proc);
end;

function TApiHookApp.AttachToSelf(const DLL: WideString): Boolean;
begin
  Result := InjectAndPipe(AhProcInfo(CurrentProcessInfo), DLL, LoaderData(DLL, GetLdrSettings));
end;

function TApiHookApp.InjectAndPipe(const Proc: TAhProcInfo; const DLL: WideString;
  const LdrData: TLoaderData): Boolean;
begin                                         
  Result := InjectInto(Proc, DLL, LdrData);
  EnterPipeLoop(Proc);
end;

function TApiHookApp.InjectInto(const Proc: TAhProcInfo; const DLL: WideString;
  const LdrData: TLoaderData): Boolean;
var
  Flags: DWord;
  Handle: THandle;
begin
  if not FileExists(DLL) then
    FLang.RaiseText('error: launch: no lib', [DLL]);

  Flags := GetFlagOpt('open-flags', 0, PROCESS_QUERY_INFORMATION or PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_VM_WRITE);

  Handle := OpenProcess(Flags, False, Proc.ProcessID);
  if Handle = 0 then
    FLang.RaiseText('error: attach: OpenProcess', [SysErrorMsg]);

  try
    if LowerCase(FCLParser['debug-loader']) = 'r' then
      ResumeProc(Proc);

    Result := AllocAndLoadInto(Handle, DLL, LdrData);
  finally
    CloseHandle(Handle);
  end;
end;

function TApiHookApp.AllocAndLoadInto(Proc: THandle; const DLL: WideString;
  const Data: TLoaderData): Boolean;
var
  DebugLoader: Boolean;
  PData, PCode: Pointer;
  CodeSize, ID, Code: DWord;
  Thread: THandle;
  SysError: WideString;
begin
  DebugLoader := FCLParser.IsSwitchOn('debug-loader');

  PData := VAllocAndWriteTo(Proc, Data, SizeOf(Data));
  try
    CodeSize := DWord(@LoaderEnd) - DWord(@Loader);
    PCode := VAllocAndWriteTo(Proc, Loader, CodeSize);

    if DebugLoader then
    begin
      Log(logUser, 'log: --debug-loader', [DWord(PCode), DWord(PData)]);
      ConsoleWaitForEnter;
    end;

    try
      Thread := CreateRemoteThread(Proc, NIL, 0, PCode, PData, 0, ID);
      if Thread = 0 then
        FLang.RaiseText('error: attach: CreateRemoteThread', [SysErrorMsg]);

      if DebugLoader then
        WaitForSingleObject(Thread, INFINITE)
        else if WaitForSingleObject(Thread, RemoteThreadTimeout) <> WAIT_OBJECT_0 then
          Error('error: attach: loader thread timeout', [RemoteThreadTimeout, SysErrorMsg]);

      if not GetExitCodeThread(Thread, Code) then
        Code := $FFFFFFFF;

      SysError := SysErrorMsg;
      CloseHandle(Thread);

      Result := Code = ThreadOK;
      if not Result then
        if (Code >= ThreadLibError) and (Code <= ThreadSettingsError) then
          Error('error: attach: thread exit: ' + IntToStr(Code), [])
          else
            Error('error: attach: thread exit: other', [Code, SysError]);
    finally
      VDealloc(Proc, PCode, CodeSize);
    end;
  finally
    VDealloc(Proc, PData, SizeOf(Data));
  end;
end;

  procedure TApiHookApp.ResumeProc(const Proc: TAhProcInfo);
  begin
    if ResumeThread(Proc.Thread) = $FFFFFFFF then
      Error('error: attach: ResumeThread', [SysErrorMsg]);
  end;

  function TApiHookApp.VAllocAndWriteTo(Proc: THandle; const Data; Size: DWord): Pointer;
  var
    Written: DWord;
  begin
    Result := VirtualAllocEx(Proc, NIL, Size, MEM_COMMIT, PAGE_READWRITE);

    if Result = NIL then
      FLang.RaiseText('error: attach: VirtualAllocEx', [Size, SysErrorMsg]);

    if not WriteProcessMemory(Proc, Result, @Data, Size, Written) then
      FLang.RaiseText('error: attach: WriteProcessMemory', [Size, DWord(@Data), DWord(Result), SysErrorMsg]);
  end;

  procedure TApiHookApp.VDealloc(Proc: THandle; Addr: Pointer; Size: DWord);
  begin
    VirtualFreeEx(Proc, Addr, Size, MEM_DECOMMIT);
  end;

procedure TApiHookApp.EnterPipeLoop;
var
  ResumeNoProc: TAhProcInfo;
begin
  ZeroMemory(@ResumeNoProc, SizeOf(ResumeNoProc));
  EnterPipeLoop(ResumeNoProc);
end;

procedure TApiHookApp.EnterPipeLoop(const ProcToResume: TAhProcInfo);
begin
  if FPipeThread = NIL then
  begin
    FExitPipeThread := False;
    FPipeData.ProcToResume := ProcToResume;

    if FCLParser.IsSwitchOn('threads', True) then
      FPipeThread := TSingleThread.Create(PipeThread)
      else
        PipeThread(NIL, NIL);
  end;
end;

procedure TApiHookApp.LeavePipeLoop;
begin
  if FPipeThread <> NIL then
  begin
    FExitPipeThread := True;

    if not FPipeThread.WaitFor(MaxPipeExitTime) then
      Error('error: pipe loop leave timeout', [MaxPipeExitTime div 1000]);

    // in case LeavePipeLoop was called twice from different threads and the first caller
    // was delayed by WaitFor above.
    if FPipeThread <> NIL then
      FreeAndNIL(FPipeThread);
  end;
end;

function TApiHookApp.PipeThread(Caller: TObject; const Arguments: TProcArguments): DWord;
  procedure LeaveThread(Code: DWord);
  begin
    FExitPipeThread := True;
    Result := 1;

    if FPipeThread <> NIL then
      ExitThread(1);
  end;

  procedure Run;
  begin
    // ConnectNamedPipe is sometimes necessary, sometimes not - but it doesn't seem to
    // harm to be left working anyway.
    ConnectNamedPipe(FPipe.Hadnle, NIL);

    InitLibraryViaPipe;

    if FPipeData.ProcToResume.ProcessID > 0 then
      ResumeProc(FPipeData.ProcToResume);

    if not FCLParser.IsSwitchOn('detach') then
      while not FExitPipeThread do
        if InterlockedExchange(FPipeData.SendScript, 0) > 0 then
          FPipe.Send('SCRIPT')
          else
          begin
            FPipe.Send('LOG');

            with FPipeData do
              if LastLog = '' then
                Sleep(PipeLoopIdleSleep)
                else
                begin
                  Log(LastLogLevel, LastLog, []);
                  Sleep(PipeLoopFetchNextSleep);
                end;
          end;

    FPipe.Send('DETACH');

    LeaveThread(0);
  end;

begin
  try
    Run;
  except
    on EPipeIsClosing do
    begin
      Log(logInfo, 'log: pipe is closing', []);
      LeaveThread(0);
    end;

    on E: Exception do
    begin
      App.HandleException(E);
      LeaveThread(1);
    end;
  end;
end;

procedure TApiHookApp.InitLibraryViaPipe;
  procedure AppendConstsTo(var Catalog: WideString);
  const
    ConstSection = '[Constants]';
  var
    Consts: WideString;
    ConstArray: TWideStringArray;
    Pos: Integer;
  begin
    ConstArray := NIL;    // compiler warning.

    Consts := FCLParser['consts'];
    if Consts = FCLParser.NotPassed then
      Consts := 'Constants.ini'
      else
        Log(logInfo, 'ack: --consts', [Consts]);
    if FileExists(Consts) then
      Consts := TFileStreamW.LoadUnicodeFrom(Consts);

    if Trim(Consts) = '' then
      Consts := '';

    if FCLParser['define'] <> FCLParser.NotPassed then
    begin
      ConstArray := ExplodeUnquoting(',', FCLParser['define'], 0, True);
      Consts := Consts + F_EOLN + Join(ConstArray, F_EOLN);
    end;

    Catalog := F_EOLN + Catalog + F_EOLN;
    Pos := PosW( F_EOLN + LowerCase(ConstSection) + F_EOLN, LowerCase(Catalog) );

    if Pos = 0 then
      Catalog := Catalog + '[Constants]' + F_EOLN + Consts
      else
        Insert(Consts + F_EOLN, Catalog, Pos + Length(ConstSection) + Length(F_EOLN) * 2);
  end;

begin
  with FPipeData do
  begin
    Log(logDebug, 'ack: pipe connected', [FPipeName]);


      LibLogLevel := GetLogLevelOpt('lib-verbose');

      LibLogs := FCLParser['lib-logs'];
      if LibLogs = FCLParser.NotPassed then
        LibLogs := '-';
      if LibLogs <> '-' then
      begin
        LibLogs := ExpandFileName(LibLogs);
        Log(logInfo, 'ack: --lib-logs', [LibLogs]);
      end;

      UserPath := FCLParser['user-path'];
      if UserPath = FCLParser.NotPassed then
        UserPath := 'User';
      UserPath := ExpandFileName(UserPath);
      if FCLParser['user-path'] <> FCLParser.NotPassed then
        Log(logInfo, 'ack: --user-path', [UserPath]);

    FPipe.Send('HELLO');


      if FPipeData.ClientVersion <> AhVersion then
        Log(logInfo, 'log: lib version', [StringUtils.FormatVersion(FPipeData.ClientVersion),
                                          StringUtils.FormatVersion(AhVersion)]);

      Catalog := FCLParser['catalog'];
      if Catalog = FCLParser.NotPassed then
        Catalog := 'Catalog.ini'
        else
          Log(logInfo, 'ack: --catalog', [Catalog]);
      if FileExists(Catalog) then
        Catalog := TFileStreamW.LoadUnicodeFrom(Catalog);

      AppendConstsTo(Catalog);

    FPipe.Send('CATALOG');


      if FileExists(FArgs.Script) then
      begin
        Script := TFileStreamW.LoadUnicodeFrom(FArgs.Script);
        Log(logInfo, 'ack: script file', [FArgs.Script]);
      end
        else
          Script := InlineAhScriptToFull(FArgs.Script);

      if Script = '' then
        FLang.RaiseText('error: invalid script arg', [FArgs.Script]);

    FPipe.Send('SCRIPT');
  end;

  FPipeData.IsPipeInitialized := True;
end;

function TApiHookApp.OnCtrlEvent(Event: DWord): Boolean;
begin
  Result := FPipeThread <> NIL;

  if Result then
  begin
    Log(logInfo, 'log: console is closing', []);
    FExitPipeThread := True;
  end;
end;

{ TAhConsolePipe }

function TAhConsolePipe.DoSend(const Cmd: WideString): Boolean;
var
  S: WideString;
begin
  Result := False;

  if Cmd = 'HELLO' then
  begin
    SendStr('VERSION');
    SendStr('$' + IntToHex(AhVersion, SizeOf(AhVersion) * 2));
    App.FPipeData.ClientVersion := StrToInt(ReadStr);

    SendStr('LOG LEVEL');
    SendDWord( DWord(App.FPipeData.LibLogLevel) );

    SendStr('LOGS');
    SendStr(App.FPipeData.LibLogs);

    SendStr('USER PATH');
    SendStr(App.FPipeData.UserPath);
  end
    else if Cmd = 'CATALOG' then
      SendStr(App.FPipeData.Catalog)
      else if Cmd = 'SCRIPT' then
        SendStr(App.FPipeData.Script)
        else if Cmd = 'LOG' then
          if ReadStr = 'NONE' then
            App.FPipeData.LastLog := ''
            else
            begin
              App.FPipeData.LastLogLevel := TAhLogLevel(ReadDWord);

              S := ReadStr;
              App.FPipeData.LastLog := PortableFormat(S, App.CCQuote(ReadStr));
            end
            else if Cmd = 'DETACH' then
            begin
              if App.FPipeData.DetachType = '' then
                SendStr('-')
                else
                  SendStr(App.FPipeData.DetachType);

              Result := True;
            end
              else
                Report('unknown command to send: "%s".', [Cmd]);
end;

procedure TAhConsolePipe.DoReport(S: WideString; Fmt: array of const);
begin
  with App.Language do
    RaiseText('error: pipe', [Format(S, Fmt)]);
end;

procedure TAhConsolePipe.ReportData(S: WideString; Fmt: array of const);
begin
  { Skip data reporting - it can be done by the library (via --lib-logs). }
end;

{ Entry point }

begin
  Randomize;

  App := TApiHookApp.Create;
  try
    App.Run;
  finally
    ExitCode := App.ExitCode;
    App.Free;
  end;
end.

