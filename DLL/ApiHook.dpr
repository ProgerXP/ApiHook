library ApiHook;

{$IFDEF AhDebug}
  {$MESSAGE WARN 'Building ApiHook in debug mode.'}

  {
    Debug mode changes the following:
    * Calls from within ApiHook.dll are not ignored (see LL's SkipHookedCaller)
    * Import Table entries (in hmImport mode) are hooked in ApiHook.dll instead of main process
    * After the loader has initialized the library CallDebugProcs is called with some test code
  }
{$ENDIF}

uses
  FastShareMem, Windows, MMSystem, SysUtils, Contnrs, Classes, FileStreamW, IniFilesW,
  Threads, StringUtils, Utils, AhCommon, AhApiCatalog, AhScript, AhLowLevel;

type
  TAhHookLib = class;

  TAhLibPipe = class (TAhClientPipe)
  protected
    FApp: TAhHookLib;
    FExitThread: Boolean;
    FLogQueue: TObjectQueue;    // of TLogQueueItem.
    FAddLogCritSection: TRTLCriticalSection;

    FLogError, FLogData: TStream;
    FLogErrorFN, FLogDataFN: WideString;

    FData: record
      ServerVersion: Word;
      MinLogLevel: TAhLogLevel;
    end;

    function DoRead(const Cmd: WideString): Boolean; override;
    procedure DoReport(Msg: WideString; Fmt: array of const); override;

    procedure WriteLog(var Log: TStream; var LogFN: WideString;
      Msg: WideString; Fmt: array of const);

    procedure SetLogErrorFN(const Value: WideString);
    procedure SetLogDataFN(const Value: WideString);
  public
    constructor ConnectTo(const NamedPipe: String; App: TAhHookLib); reintroduce;
    destructor Destroy; override;

    property ExitThread: Boolean read FExitThread write FExitThread;

    function ReceiveThread(Caller: TObject; const Arguments: TProcArguments): DWord;
    procedure QueueLog(Level: TAhLogLevel; const Msg: WideString; Fmt: array of const);

    property LogErrorFN: WideString read FLogErrorFN write SetLogErrorFN;
    property LogDataFN: WideString read FLogDataFN write SetLogDataFN;

    procedure ReportData(Msg: WideString; Fmt: array of const); override;
    procedure PipeIsClosing; override;
  end;

  TAhHookLib = class
  {$IFDEF AhDebug}
    private
      class procedure CallDebugProcs;
  {$ENDIF}
  protected
    FSettings: TAhSettings;
    FStartTime: DWord;
    FIsInitialized: Boolean;
    FLogs: TAhLoggers;

    FPipe: TAhLibPipe;
    FPipeThread: TSingleThread;

    FCatalog: TAhApiCatalog;
    FScript: TAhScript;
    FUserPath: WideString;

    procedure Hook;
    procedure Unhook;
    procedure DetachPipe;
  public
    constructor Create(const Settings: TAhSettings);
    destructor Destroy; override;

    property Settings: TAhSettings read FSettings;

    procedure Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
    procedure LowLevelLog(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
    procedure Debug(const Msg: WideString; Fmt: array of const);
    procedure Error(const Msg: WideString; Fmt: array of const);

    function Bootstrap: Boolean;

    { Pipe-invoked commands }
    procedure CmdSetLogs(const Logs: WideString);
    procedure CmdUserPath(const Path: WideString);
    procedure CmdCatalog(const Catalog: WideString);
    procedure CmdScript(const Script: WideString);
    procedure CmdDetach;
    procedure CmdShutdown(QuitHost: Boolean);
  end;

{$R *.res}

type
  TLogQueueItem = class
  public
    Level: TAhLogLevel;
    Msg, Fmt: WideString;

    constructor Create(ALevel: TAhLogLevel; const AMsg, AFmt: WideString);
  end;

const
  MaxLogQueue = 1000;

{ TLogQueueItem }

constructor TLogQueueItem.Create(ALevel: TAhLogLevel; const AMsg, AFmt: WideString);
begin
  Level := ALevel;
  Msg := AMsg;
  Fmt := AFmt;
end;

{ TAhLibPipe }

constructor TAhLibPipe.ConnectTo(const NamedPipe: String; App: TAhHookLib);
begin
  FApp := App;
  FExitThread := False;

  FillChar(FData, SizeOf(FData), 0);
  FData.MinLogLevel := logInfo;

  FLogError := NIL;
  FLogData := NIL;

  InitializeCriticalSection(FAddLogCritSection);
  FLogQueue := TObjectQueue.Create;

  inherited ConnectTo(NamedPipe);

  FLogSend := True;
  FLogReceive := True;
end;

destructor TAhLibPipe.Destroy;
begin
  while FLogQueue.Count > 0 do
    FLogQueue.Pop.Free;
  FLogQUeue.Free;

  DeleteCriticalSection(FAddLogCritSection);

  if FLogData <> NIL then
    FLogData.Free;
  if FLogError <> NIL then
    FLogError.Free;

  inherited;
end;

function TAhLibPipe.DoRead(const Cmd: WideString): Boolean;
var
  Action: WideString;
begin
  Result := False;

  if Cmd = 'HELLO' then
  begin
    if ReadStr = 'VERSION' then
    begin
      FData.ServerVersion := StrToInt(ReadStr);
      SendStr('$' + IntToHex(AhVersion, SizeOf(AhVersion) * 2));
    end;

    if ReadStr = 'LOG LEVEL' then
      FData.MinLogLevel := TAhLogLevel(ReadDWord);

    if ReadStr = 'LOGS' then
      FApp.CmdSetLogs(ReadStr);

    if ReadStr = 'USER PATH' then
      FApp.CmdUserPath(ReadStr);
  end
    else if Cmd = 'CATALOG' then
      FApp.CmdCatalog(ReadStr)
      else if Cmd = 'SCRIPT' then
        FApp.CmdScript(ReadStr)
        else if Cmd = 'LOG' then
          if FLogQueue.Count > 0 then
            with TLogQueueItem(FLogQueue.Pop) do
            begin
              SendStr('ONE');

              SendDWord(DWord(Level));
              SendStr(Msg);
              SendStr(Fmt);

              Free;
            end
            else
              SendStr('NONE')
          else if Cmd = 'DETACH' then
          begin
            Action := ReadStr;
            FApp.CmdDetach;
            Result := True;

            if (Action <> '') and (Action <> '-') then
            begin
              FApp.Debug('Pipe-controlled shutdown of type %s.', [Action]);
              FApp.CmdShutdown(Action = 'TERMINATE');
            end;
          end
            else
              Report('received unknown command: "%s".', [Cmd]);
end;

function TAhLibPipe.ReceiveThread(Caller: TObject; const Arguments: TProcArguments): DWord;
begin
  while not FExitThread do
    try
      Read;
    except
      on EPipeIsClosing do
      begin
        FApp.DetachPipe;
        Break;
      end;

      on E: Exception do
        FApp.Error('Pipe command exception: <%s> %s', [E.CLassName, E.Message]);
    end;

  Windows.ExitThread(0);
  Result := 0;
end;

procedure TAhLibPipe.QueueLog(Level: TAhLogLevel; const Msg: WideString; Fmt: array of const);
const
  MaxError = 'Too many log items - removing all but last %d; use --lib-logs for all output.';
var
  NewMsg, NewFmt: WideString;
  I: Integer;
begin
  if (FData.ServerVersion = 0) or (Level < FData.MinLogLevel) then
    Exit;

  if FLogQueue.Count >= MaxLogQueue then
  begin
    // should be faster to loop over a precalculated value than call Count 1000s of times.
    for I := FLogQueue.Count - 10 downto 1 do
      FLogQueue.Pop.Free;

    FApp.Log(logError, MaxError, [FLogQueue.Count]);
  end
    else
    begin
      if FApp.Settings.UseCriticalSections <> csNone then
        EnterCriticalSection(FAddLogCritSection);

      MakePortableFormat(Msg, Fmt, NewMsg, NewFmt);

      if (Level = logError) and (Msg = MaxError) then
        // this trick puts the message in front of others so it gets to the loader's
        // console output on the next update; otherwise it's a good chance that next
        // log messages overflow will erase it without a trace.
        TObjectStack(FLogQueue).Push( TLogQueueItem.Create(Level, NewMsg, NewFmt) )
        else
          FLogQueue.Push( TLogQueueItem.Create(Level, NewMsg, NewFmt) );

      if FApp.Settings.UseCriticalSections <> csNone then
        LeaveCriticalSection(FAddLogCritSection);
    end;
end;

procedure TAhLibPipe.DoReport(Msg: WideString; Fmt: array of const);
begin
  WriteLog(FLogError, FLogErrorFN, Msg, Fmt);
end;

procedure TAhLibPipe.ReportData(Msg: WideString; Fmt: array of const);
begin
  WriteLog(FLogData, FLogDataFN, Msg, Fmt);
end;

procedure TAhLibPipe.WriteLog(var Log: TStream; var LogFN: WideString;
  Msg: WideString; Fmt: array of const);
begin
  if Length(Fmt) > 0 then
    Msg := Format(Msg, Fmt);
  if Length(Msg) > 120 then
    Msg := Copy(Msg, 1, 100) + '...';
  OutputDebugStringW(PWideChar('Pipe: ' + Msg));

  if LogFN <> '' then
  begin
    if Log = NIL then
    begin
      if Copy(LogFN, 1, 1) = '+' then
      begin
        Delete(LogFN, 1, 1);
        if FileExists(LogFN) then
          Log := TFileStreamW.Create(LogFN, fmOpenReadWrite or fmShareDenyNone);
      end;

      if Log = NIL then
        Log := TFileStreamW.CreateCustom(LogFN, fmForcePath or fmShareDenyNone);
    end;

    if Length(Fmt) > 0 then
      Msg := WideFormat(Msg, Fmt);
    Msg := Msg + #13#10;

    Log.Write(Msg[1], Length(Msg) * 2);
  end;
end;

procedure TAhLibPipe.SetLogErrorFN(const Value: WideString);
begin
  FLogErrorFN := Value;

  if FLogError <> NIL then
    FreeAndNIL(FLogError);
end;

procedure TAhLibPipe.SetLogDataFN(const Value: WideString);
begin
  FLogDataFN := Value;

  if FLogData <> NIL then
    FreeAndNIL(FLogData);
end;

procedure TAhLibPipe.PipeIsClosing;
begin
  OutputDebugString('The loader''s side of the named pipe has closed - detaching.');
  inherited;
end;

{ TAhHookLib }

constructor TAhHookLib.Create(const Settings: TAhSettings);
begin
  Randomize;

  FIsInitialized := False;
  FStartTime := timeGetTime;

  Move(Settings, FSettings, SIzeOf(Settings));
  FLogs := TAhLoggers.Create;
end;

function TAhHookLib.Bootstrap: Boolean;
begin
  Result := FPipe = NIL;

  if Result then
  begin
    Debug('Bootstrapping; UseCriticalSections = %d; named pipe = %s',
          [Byte(FSettings.UseCriticalSections), FSettings.Pipe]);

    if lstrlen(@FSettings.Pipe[0]) > 0 then
      FPipe := TAhLibPipe.ConnectTo(FSettings.Pipe, Self)
      else
        FPipe := NIL;

    FPipeThread := NIL;

    if FPipe <> NIL then
    begin
      Debug('Starting pipe thread...', []);
      FPipeThread := TSingleThread.Create(FPipe.ReceiveThread);
    end;

    Debug('Bootstrapping finished in %d msec.', [timeGetTime - FStartTime]);
  end;
end;

destructor TAhHookLib.Destroy;
begin
  Debug('Shutting down the library; running time - %d sec...', [(timeGetTime - FStartTime) div 1000]);

  Unhook;
  DetachPipe;

  if FScript <> NIL then
    FScript.Free;
  if FCatalog <> NIL then
    FCatalog.Free;

  OutputDebugString('Shutdown complete. See you!');
  inherited;
end;

procedure TAhHookLib.Debug(const Msg: WideString; Fmt: array of const);
begin
  Log(logDebug, Msg, Fmt);
end;

procedure TAhHookLib.Error(const Msg: WideString; Fmt: array of const);
begin
  Log(logError, Msg, Fmt);
end;

procedure TAhHookLib.Log(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
begin
  try
    // OutputDebugStringW actually wraps around OutputDebugStringA - see MSGN.
    OutputDebugStringA(PChar( Format(Msg, Fmt) ));
  except
    asm nop end;   // to catch Format %char errors in code.
  end;

  FLogs.Log(Level, Msg, Fmt);

  if FPipe <> NIL then
    FPipe.QueueLog(Level, Msg, Fmt);
end;

procedure TAhHookLib.LowLevelLog(Level: TAhLogLevel; Msg: WideString; Fmt: array of const);
begin
  Log(Level, 'LowLevel: ' + Msg, Fmt);
end;

procedure TAhHookLib.Hook;
begin
  Unhook;

  LLUseCritSect := FSettings.UseCriticalSections;

  LLOnLog := Self.LowLevelLog;
  LLOnScriptLog := Self.Log;
  LLUserFilePath := IncludeTrailingPathDelimiter(FUserPath);

  // LowLevel will set FScript and/or FCatalog to NIL once it owns them.
  InitLowLevel(FScript, FCatalog, FSettings.HookModule);

  {$IFDEF AhDebug}
    CallDebugProcs;
  {$ENDIF}
end;

procedure TAhHookLib.Unhook;
begin
  ResetLowLevel;    
end;

procedure TAhHookLib.DetachPipe;
begin
  if FPipe <> NIL then
    FPipe.ExitThread := True;

  // even if FPipe and FPipeThread are not freed here they'll be freed on App.Destroy.
  if (FPipeThread <> NIL) and not FPipeThread.IsCurrent then
  begin
    OutputDebugString('Freeing named pipe thread and connection...');

    if FPipeThread <> NIL then
    begin
      FPipeThread.WaitFor(MaxPipeExitTime);
      FreeAndNIL(FPipeThread);
    end;

    if FPipe <> NIL then
      FreeAndNIL(FPipe);
  end;
end;

{ Pipe-invoked commands }

procedure TAhHookLib.CmdSetLogs(const Logs: WideString);
var
  Split: TWideStringArray;
  I: Integer;
  Level: WideString;
begin
  Debug('Switching library logs to %s...', [Logs]);

  Split := Explode(',', Logs);

  if Length(Split) <> 0 then
  begin
    FLogs.DeleteAll;

    for I := 0 to Length(Split) - 1 do
      if Copy(Split[I], 1, 1) = '!' then
        FPipe.LogErrorFN := Copy(Split[I], 2, MaxInt)
        else if Copy(Split[I], 1, 1) = '%' then
          FPipe.LogDataFN := Copy(Split[I], 2, MaxInt)
          else
          begin
            Level := ExtractLogLevelFrom(Split[I]);
            FLogs.Add(Split[I], Level);
          end;
  end;
end;

procedure TAhHookLib.CmdUserPath(const Path: WideString);
begin
  FUserPath := Path;
end;

procedure TAhHookLib.CmdCatalog(const Catalog: WideString);
var
  Ini: TCustomIniFileW;
begin
  Debug('Loading API catalog (%d) = "%s"...', [Length(Catalog), Copy(Catalog, 1, 50)]);

  if IsLowLevelInit then
  begin
    Error('API catalog cannot be changed while hooking is active.', []);
    Exit;
  end;

  Ini := TMemIniFileW.Create;
  try
    try
      Ini.LoadFromString(Catalog);

      if FCatalog <> NIL then
        FCatalog.Free;

      FCatalog := TAhApiCatalog.Create(Ini);
    except
      on E: Exception do
        Error('Error loading API catalog: <%s> %s', [E.ClassName, E.Message]);
    end;
  finally
    Ini.Free;
  end;
end;

procedure TAhHookLib.CmdScript(const Script: WideString);
begin
  Debug('Loading script & attaching handlers; Script (%d) = "%s"...', [Length(Script), Copy(Script, 1, 50)]);

  if FScript <> NIL then
    FScript.Free;

  try
    FScript := TAhScript.Create(Script);
    Hook;
  except
    on E: Exception do
      Error('Error loading script: <%s> %s', [E.ClassName, E.Message]);
  end;
end;

procedure TAhHookLib.CmdDetach;
begin
  Debug('Detaching library from pipe %s...', [FSettings.Pipe]);
  DetachPipe;
end;

procedure TAhHookLib.CmdShutdown(QuitHost: Boolean);
begin
  Unhook;

  if QuitHost then
  begin
    Debug('Terminating host process with exit code %d...', [HostExitCodeOnLibShutdown]);
    ExitProcess(HostExitCodeOnLibShutdown);
    Error('Failed! %d: %s', [GetLastError, SysErrorMessage(GetLastError)]);
  end;
end;

{$IFDEF AhDebug}
  class procedure TAhHookLib.CallDebugProcs;
  var
    Buf: array[0..255] of Char;
    I: DWord;
    F: TFileStream;
  begin
    //windows.Sleep(1);
    exit;
    f := tfilestreamw.Create('s.oo', fmopenread);
    while true do
      readfile(f.Handle, buf[0], 5, i, nil);
    f.Free;
    //  halt
  end;
{$ENDIF}

{ Exports & DLL Proc }

var
  App: TAhHookLib = NIL;

{------------>   Each export must have a top-level try..except block   <------------}

function Bootstrap(const ASettings: TAhSettings): Boolean; stdcall;
begin
  Result := False;
  OutputDebugString('ApiHook Bootstrap export procedure called.');

  try
    App := TAhHookLib.Create(ASettings);
  except
    Exit;
  end;

  try
    Result := App.Bootstrap;
  except
    on E: Exception do
      App.Error('Exception while bootstrapping ApiHook DLL: <%s> %s', [E.ClassName, E.Message]);
  end;
end;

procedure Shutdown; stdcall;
begin
  OutputDebugString('ApiHook Shutdown export procedure called.');

  if App <> NIL then
    try
      FreeAndNIL(App);
    except
    end;
end;

procedure PipeLoop; stdcall;
begin
  OutputDebugString('ApiHook PipeLoop export procedure called.');

  if (App <> NIL) and (App.FPipe <> NIL) then
    try
      App.FPipe.ReceiveThread(NIL, NIL);
    except
    end;
end;

procedure DllEvent(Event: Integer);
begin
  OutputDebugString(PChar( 'ApiHook DLL entry point, event = ' + IntToStr(Event) ));

  if Event = DLL_PROCESS_DETACH then
    if App <> NIL then
      try
        FreeAndNIL(App);
      except
      end;
end;

exports
  Bootstrap,
  Shutdown,
  PipeLoop;

begin
  DLLProc := DllEvent;
  IsMultiThread := True;
  DLLProc(DLL_PROCESS_ATTACH);
end.

