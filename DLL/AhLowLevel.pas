unit AhLowLevel;

interface

uses PsAPI, Windows, SysUtils, Math,
     StringUtils, RPNit, StringsW, FileStreamW, ProcUtils, Utils,
     AhCommon, AhApiCatalog, AhScript;

type
  TAhHookedContext  = class;

  TPrologue         = array[0..5] of Byte;
  TJumper           = array[0..90] of byte;

  TProcHook = record
    Index: Integer;
    Proc: String;
    Mode: THookMode;

    PrologueLength: Byte;
    VarPrologue: array[0..127] of Byte;
    VarProloguePtr: Pointer;

    // Number of threads (callers) that are currently inside a Pre/Post handler or
    // are waiting to acquire the critical section object.
    ActiveCount: Integer;
    // Is True when ActiveCount > 0 and UnhookProc waits for handlers to finish before
    // destroying this hook data.
    Unhooking: Integer;
    CritSection: TRTLCriticalSection;
    AnyCaller: Boolean;
    Context: TAhHookedContext;    // NIL when hook isn't executing.

    OrigAddr: Pointer;
    OldPageMode: DWord;           // VirtualProtect's.
    OrigPrologue, NewPrologue: TPrologue;
    Jumper: TJumper;
  end;

  TAhHookedContext = class
  protected
    FIndex: Integer;
    FIsAfterCall: Boolean;
    FRegisters: TAhRegisters;
    FSaved: TObjectHash;

    function GetRegister(Reg: String; out Value: DWord): Boolean;
    function GetArg(Arg: String): TRpnScalar;
    function GetResult: TRpnScalar;
    function GetProcName: String;

    function GetSaved(Name: WideString): TRpnScalar;
    procedure SetSaved(Name: WideString; const Value: TRpnScalar);
  public
    class function IsValidSavedName(const Name: WideString): Boolean;
    class function IsGlobalSave(const Name: WideString): Boolean;

    constructor Create(Index: Integer; const Registers: TAhRegisters);
    destructor Destroy; override;

    property IsAfterCall: Boolean read FIsAfterCall write FIsAfterCall;
    property Registers: TAhRegisters read FRegisters write FRegisters;
    property Saved[Name: WideString]: TRpnScalar read GetSaved write SetSaved;

    procedure SaveFile(Name: WideString; const Buf; Size: DWord);
    function GetConstName(Arg: String): WideString;
    function ConstsByValue(const Value: TRpnScalar; const ConstNames: TWideStringArray;
      IsSetOf: Boolean; Joiner: WideString = ' '): WideString;
    function GetHumanReadableArg(Arg: String): WideString;
    function ModuleNameOfAddr(Addr: DWord): WideString;

    function Bindings: TAhContext;
    function Hook: TProcHook;

    function IndexOfArg(const Arg: String): Integer;
  end;

var
  LLUseCritSect: TAhCritSectionMode = csGlobal;
  LLOnLog: TAhOnLog = NIL;
  LLOnScriptLog: TAhOnLog = NIL;
  LLUserFilePath: WideString = 'User\';

// Owns AScript and ACatalog - once acquired sets AScript/ACatalog to NIL. In case of
// exception one can be acquired while another wasn't so free the other if it's not NIL.
procedure InitLowLevel(var AScript: TAhScript; var ACatalog: TAhApiCatalog;
  const HookImageName: WideString);
procedure ResetLowLevel;
function IsLowLevelInit: Boolean;

implementation

type
  TSavedRpnValue = class
  public
    Value: TRpnScalar;
    constructor Create(AValue: TRpnScalar);
  end;

const
  InitialProcHookCount = 8;
  ProcHookEnlargeBy = 32;

  NewPrologueTpl: TPrologue = ({PUSH} $68, {addr} 0, 0, 0, 0, {RET} $C3);
  NewPrologueTplAddr = 1;

  JumperTpl: TJumper = (
                  {---------------- Prehook ----------------}

    {PUSH   index}              $68,        0, 0, 0, 0,   {index}
    {CALL   prehook}            $FF, $15,   0, 0, 0, 0,   {PreHookAddr}

                  {----------------  Debug ----------------}

  {$IFDEF 0}
    {INT    3 (debugger)}       $CD, $03,
  {$ELSE}
    {NOP, NOP}                  $90, $90,
  {$ENDIF}

                  {--------------- Original ---------------}

  {  Here we create a jumper code to be called after original function returns.       }
  {  It's created on stack to remain 100% thread-safe; offset is $2000 from ESP.      }

    {PUSH   EAX}                $50,
    {MOV    EAX, origRetAddr}   $8B, $44, $24,      $04,  // [ESP+4]

  {  writing    PUSH  origRetAddr }
    {MOV    stack, <PUSH>}      $C6, $84, $24,
                                     $00, $E0, $FF, $FF,  // [ESP-0x2000]
                                     $68,                 {PUSH opcode}
    {MOV    stack, EAX}         $89, $84, $24,
                                     $01, $E0, $FF, $FF,  // [ESP-0x1FFF]

  {  writing    PUSH  retHereAddr }
    {MOV    stack, <PUSH>}      $C6, $84, $24,
                                     $05, $E0, $FF, $FF,  // [ESP-0x1FFB]
                                     $68,                 {PUSH opcode}
    {MOV    stack, retHereAddr} $C7, $84, $24,
                                     $06, $E0, $FF, $FF,  // [ESP-0x1FFA]
                                     0, 0, 0, 0,

  {  writing    RET               }
    {MOV    stack, <RET>}       $C6, $84, $24,
                                     $0A, $E0, $FF, $FF,  // [ESP-0x1FF6]
                                     $C3,                 {RET opcode}

  {  Here we replace original caller's address with our newly created stack landing.  }

    {LEA EAX, retJumperAddr}    $8D, $84, $24,
                                     $00, $E0, $FF, $FF,  // [ESP-2000]
    {MOV retToReturnTo, EAX}    $89, $44, $24,
                                     $04,                 // [ESP+4]

    {POP    EAX}                $58,

  {  Original routine address points either to first function's or VarPrologue's      }
  {  opcode depending on PrologueLength.                                              }

    {PUSH   origRoutineAddr}    $FF, $35,   0, 0, 0, 0,
    {RET}                       $C3,

                  {--------------- Posthook ---------------}

  {  Executing contniues at this point after origRoutine -> stackLanging calls.       }

    {PUSH   index}              $68,        0, 0, 0, 0,
    {CALL   posthook}           $FF, $15,   0, 0, 0, 0,   {PostHookAddr}

                  {---------------- Return ----------------}

  {  We have pushed original caller's address in the stack jumper (before index).     }

    {RET}                       $C3
  );

  JumperTplIndex1    = 1;
  JumperTplPreHook   = JumperTplIndex1 + 6;
  JumperTplContSlot  = JumperTplPreHook + 41;
  JumperTplOrig      = JumperTplContSlot + 26;
  JumperTplContAt    = JumperTplOrig + 5;
  JumperTplIndex2    = JumperTplContAt + 1;
  JumperTplPostHook  = JumperTplIndex2 + 6;

var
  Procs: TAhApiCatalog = NIL;
  Script: TAhScript = NIL;
  GlobalSaved: TObjectHash = NIL;
  GlobalCritSection: TRTLCriticalSection;

  ProcHooks: array of TProcHook;
  ProcHookCount: Integer = 0;

  PreHookAddr, PostHookAddr: Pointer;
  SelfImageBase, SelfImageEnd: DWord;
  // if HookImageEnd = 0 only ApiHook.dll's callers are bypassed.
  HookImageBase, HookImageEnd: DWord;

  ProcModules: TProcessModules;

  SavedFileCounter: Integer = 0;

function LLErr(const Str: WideString; Fmt: array of const): Boolean;
begin
  Result := True;

  if Assigned(LLOnLog) then
    LLOnLog(logError, Str, Fmt);
end;

procedure LLHookRunningError(When, Proc: WideString; E: Exception);
const
  Fmt = 'Error while running %s-actions of %s (library image = %.8X..%.8X): <%s at %.8X> %s';
begin
  LLErr(Fmt, [When, Proc, SelfImageBase, SelfImageEnd, E.ClassName, DWord(ExceptAddr), E.Message]);
end;

procedure LLDbg(const Str: WideString; Fmt: array of const);
begin
  if Assigned(LLOnLog) then
    LLOnLog(logDebug, Str, Fmt);
end;

procedure SetModuleInfo(const Caption: WideString; Handle: HModule; out Base, Finish: DWord);
const
  Error = 'Error getting %s module information using GetModuleInformation(): (%d) %s';
var
  ModuleInfo: TModuleInfo;
begin
  if GetModuleInformation(GetCurrentProcess, Handle, @ModuleInfo, SizeOf(ModuleInfo)) then
  begin
    Base := DWord(ModuleInfo.lpBaseOfDll);
    Finish := Base + ModuleInfo.SizeOfImage;
  end
    else
    begin
      LLErr(Error, [Caption, GetLastError, SysErrorMessage(GetLastError)]);
      Base := 0;
      Finish := 0;
    end;
end;

procedure SetProcHookCount(Count: Integer);
var
  OldCount: Integer;
begin
  OldCount := Length(ProcHooks);
  SetLength(ProcHooks, Count);

  if Count > OldCount then
    FillChar(ProcHooks[OldCount], (Count - OldCount) * SizeOf(TProcHook), 0);

  if ProcHookCount > Count then
    ProcHookCount := Count;
end;

function CheckProcHookIndex(const Routine: String; Index: Integer): Boolean;
begin
  Result := (Index >= 0) and (Index < ProcHookCount);
  if not Result then
    LLErr('%s received wrong proc index %d (%d hooks total).', [Routine, Index, ProcHookCount]);
end;

function HookIndexOf(const Routine: String): Integer;
begin
  for Result := 0 to ProcHookCount - 1 do
    if ProcHooks[Result].Proc = Routine then
      Exit;

  Result := -1;
end;

procedure FillNewPrologueOf(var Hook: TProcHook);
begin
  Hook.NewPrologue := NewPrologueTpl;
  Patch(Hook.NewPrologue[NewPrologueTplAddr], DWord(@Hook.Jumper[0]));
end;

procedure FillVarPrologueOf(var Hook: TProcHook);
var
  ContinuationAddr: DWord;
begin
  with Hook do
  begin
    PatchCopying(@VarPrologue[0], OrigAddr, PrologueLength);
    PatchCopying(@VarPrologue[PrologueLength], @NewPrologueTpl[0], SizeOf(NewPrologueTpl));

    ContinuationAddr := DWord(OrigAddr) + PrologueLength;
    PatchCopying(@VarPrologue[PrologueLength + NewPrologueTplAddr], @ContinuationAddr, SizeOf(DWord));
  end;
end;

procedure FillJumperOf(var Hook: TProcHook);
begin
  with Hook do
  begin
    Jumper := JumperTpl;

    Patch(Jumper[JumperTplIndex1], Index);
    Patch(Jumper[JumperTplIndex2], Index);

    Patch(Jumper[JumperTplContSlot], DWord(@Jumper[JumperTplContAt]));

    if (Mode <> hmPrologue) or (PrologueLength = 0) then
      Patch(Jumper[JumperTplOrig], DWord(@OrigAddr))   // they're @pointers to proc pointers.
      else
      begin
        VarProloguePtr := @VarPrologue[0];
        Patch(Jumper[JumperTplOrig], DWord(@VarProloguePtr));
      end;

    Patch(Jumper[JumperTplPreHook], DWord(@PreHookAddr));
    Patch(Jumper[JumperTplPostHook], DWord(@PostHookAddr));
  end;
end;

function SkipHookedCaller(AnyCaller: Boolean; Addr: DWord): Boolean;
begin
  {$IFDEF AhDebug}
    Result := False;
  {$ELSE}
    if AnyCaller then
      Result := False
      else if HookImageEnd = 0 then
        Result := (Addr >= SelfImageBase) and (Addr <= SelfImageEnd)
        else
          Result := (Addr < HookImageBase) or (Addr > HookImageEnd);
  {$ENDIF}
end;

procedure InitModuleBounds;
begin
  if Length(ProcModules) = 0 then
    ProcModules := GetProcessModules;
end;

{ TSavedRpnVar }

constructor TSavedRpnValue.Create(AValue: TRpnScalar);
begin
  Value := AValue;
end;

{ TAhHookedContext }

class function TAhHookedContext.IsValidSavedName(const Name: WideString): Boolean;
var
  I: Integer;
begin
  Result := False;

  for I := 1 to Length(Name) do
    if not (Char(Name[I]) in ['a'..'z', 'A'..'Z', '0'..'9', '_']) then
      Exit;

  Result := True;
end;

class function TAhHookedContext.IsGlobalSave(const Name: WideString): Boolean;
begin
  Result := not ConsistsOfChars(Name, '0123456789') and (Name = UpperCase(Name));
end;

constructor TAhHookedContext.Create(Index: Integer; const Registers: TAhRegisters);
begin
  FIndex := Index;
  FIsAfterCall := False;
  FRegisters := Registers;

  FSaved := TObjectHash.Create(True);
end;

destructor TAhHookedContext.Destroy;
begin
  FSaved.Free;
  inherited;
end;

function TAhHookedContext.Bindings: TAhContext;
begin
  Result.Log := LLOnScriptLog;

  Result.GetRegister := GetRegister;
  Result.GetArg := GetArg;
  Result.GetResult := GetResult;
  Result.GetSaved := GetSaved;
  Result.SetSaved := SetSaved;
  Result.ProcName := GetProcName;

  Result.SaveFile := SaveFile;
  Result.GetCOnstName := GetConstName;
  Result.ConstsByValue := ConstsByValue;
  Result.GetHumanReadableArg := GetHumanReadableArg;
  Result.ModuleNameOfAddr := ModuleNameOfAddr;
end;

function TAhHookedContext.Hook: TProcHook;
begin
  Result.Index := -1;

  if CheckProcHookIndex('Context.Hook', FIndex) then
    Result := ProcHooks[FIndex];
end;

function TAhHookedContext.IndexOfArg(const Arg: String): Integer;
const
  LowCapCount = 'Attempted to retrieve param #%d from procedure %s that only has %d parameters.';
begin
  if not TryStrToInt(Arg, Result) then
    Result := Procs.ParamIndex[Hook.Proc, Arg];

  if Result < 0 then
    LLErr('Cannot find parameter :%s of procedure %s.', [Arg, Hook.Proc])
    else if Result >= Length(Procs.Params[Hook.Proc]) then
    begin
      LLErr(LowCapCount, [Result + 1, Hook.Proc, Length(Procs.Params[Hook.Proc])]);
      Result := -1;
    end;
end;

function TAhHookedContext.GetArg(Arg: String): TRpnScalar;
const
  StackCLeaned = 'Attempting to retrieve parameter :%s of procedure %s following %s' +
                 ' calling convention which prescribes that stack is cleaned by the' +
                 ' routine; thus parameter values are inaccessible for post-actions.';
var
  ArgIndex: Integer;
begin
  Result.Kind := [];

  if Hook.Index <> -1 then
    if FIsAfterCall and not Procs.CallConv[Hook.Proc].CallerCleansStack then
      LLErr(StackCLeaned, [Arg, Hook.Proc, Procs[Hook.Proc].Call])
      else
      begin
        ArgIndex := IndexOfArg(Arg);
        if ArgIndex <> -1 then
          Result := Procs.ParamToValue(Hook.Proc, ArgIndex, FRegisters.rESP);
      end;
end;

function TAhHookedContext.GetRegister(Reg: String; out Value: DWord): Boolean;
begin
  Result := True;

  if Reg = 'EAX' then
    Value := FRegisters.rEAX
    else if Reg = 'ECX' then
      Value := FRegisters.rECX
      else if Reg = 'EDX' then
        Value := FRegisters.rEDX
        else if Reg = 'EBX' then
          Value := FRegisters.rEBX
          else if Reg = 'ESP' then
            Value := FRegisters.rESP
            else if Reg = 'EBP' then
              Value := FRegisters.rEBP
              else if Reg = 'ESI' then
                Value := FRegisters.rESI
                else if Reg = 'EDI' then
                  Value := FRegisters.rEDI
                  else if Reg = 'EIP' then
                    Value := FRegisters.rEIP
                    else
                      Result := False;
end;

function TAhHookedContext.GetResult: TRpnScalar;
var
  Addr: DWord;
begin
  Result.Kind := [];

  if Hook.Index <> -1 then
  begin
    Addr := Procs.CallConv[Hook.Proc].ReturnValueAddr(FRegisters);
    Result := Procs.ToValueByType(Procs[Hook.Proc].Return, Addr);
  end;
end;

function TAhHookedContext.GetSaved(Name: WideString): TRpnScalar;
var
  I: Integer;
begin
  Result.Kind := [];

  if IsGlobalSave(Name) then
  begin
    I := GlobalSaved.IndexOf(Name);
    if I <> -1 then
      Result := (GlobalSaved.Objects[I] as TSavedRpnValue).Value;
  end
    else
    begin
      I := FSaved.IndexOf(Name);
      if I <> -1 then
        Result := (FSaved.Objects[I] as TSavedRpnValue).Value;
    end;
end;

procedure TAhHookedContext.SetSaved(Name: WideString; const Value: TRpnScalar);
const
  Error = '"%s" (new value "%s") is not a valid variable name - must consist of a-z, A-Z, 0-9 and ''_''.';
begin
  if IsValidSavedName(Name) then
    if IsGlobalSave(Name) then
      GlobalSaved[Name] := TSavedRpnValue.Create(Value)
      else
        FSaved[Name] := TSavedRpnValue.Create(Value)
    else
      LLErr(Error, [Name, RpnValueToStr(Value, NilRPN)]);
end;

procedure TAhHookedContext.SaveFile(Name: WideString; const Buf; Size: DWord);
var
  Stream: TFileStreamW;
  I, Counter: Integer;
begin
  if Copy(Name, 1, 1) <> PathDelim then
    Insert(IncludeTrailingPathDelimiter(LLUserFilePath), Name, 1);

  if Name = '' then
    Name := FormatDateTime('h-nn-ss', Now);

  if ExtractFileExt(Name) = '' then
    Name := Name + '.dat';

  I := Length(Name);
  while I > 0 do
  begin
    if Name[I] = '*' then
    begin
      Delete(Name, I, 1);

      Counter := InterlockedExchangeAdd(@SavedFileCounter, 1);
      Insert(IntToStr(Counter), Name, I);
    end;

    Dec(I);
  end;

  LLOnScriptLog(logInfo, 'Saving user file of %d bytes to %s...', [Size, Name]);

  Stream := TFileStreamW.CreateCustom(Name, fmForcePath or fmShareDenyNone);
  try
    Stream.Write(Buf, Size);
  finally
    Stream.Free;
  end;
end;

function TAhHookedContext.GetConstName(Arg: String): WideString;
var
  ArgIndex: Integer;
begin
  ArgIndex := IndexOfArg(Arg);

  if Hook.Index <> -1 then
    Result := Procs.ConstNameByParamValue(Hook.Proc, ArgIndex, GetArg( IntToStr(ArgIndex) ))
    else
      Result := '';
end;

function TAhHookedContext.ConstsByValue(const Value: TRpnScalar; const ConstNames: TWideStringArray;
  IsSetOf: Boolean; Joiner: WideString = ' '): WideString;
begin
  Result := Procs.Consts.NameBy(Value, ConstNames, IsSetOf, Joiner);
end;

function TAhHookedContext.GetHumanReadableArg(Arg: String): WideString;
var
  Suffix: WideString;
begin
  if Hook.Index = -1 then
    Result := ''
    else
    begin
      Result := RpnValueToStr(GetArg(Arg), NilRPN);
      Suffix := '';

      if Length( Procs.ParamConsts[Hook.Proc, Arg] ) > 0 then
        Suffix := GetConstName(Arg);

      if Suffix <> '' then
        Result := Result + ' [' + Suffix + ']';
    end;
end;

function TAhHookedContext.ModuleNameOfAddr(Addr: DWord): WideString;
  function Find: WideString;
  var
    I: Integer;
  begin
    for I := 0 to Length(ProcModules) - 1 do
      if (ProcModules[I].BaseAddress <= Addr) and (ProcModules[I].EndAddress >= Addr) then
      begin
        Result := ProcModules[I].Name;
        Exit;
      end;

    Result := '';
  end;

var
  ReInit: Boolean;
begin
  ReInit := Length(ProcModules) > 0;
  InitModuleBounds;

  Result := Find;

  if (Result = '') and ReInit then
  begin
    SetLength(ProcModules, 0);
    InitModuleBounds;

    Result := Find;
  end;
end;

function TAhHookedContext.GetProcName: String;
begin
  if Hook.Index <> -1 then
    Result := Hook.Proc
    else
      Result := '';
end;

{ Hooking routines }

procedure DoPreHook(const Registers: TAhRegisters; Index: Integer); stdcall; forward;
procedure DoPostHook(var Registers: TAhRegisters; Index: Integer; Caller: Pointer); stdcall; forward;

procedure CaptureRegisters;
asm
  PUSH  EAX
  MOV   EAX, [ESP + RegistersSize + $10]
  MOV   TAhRegisters[ESP+8].rEIP, EAX
  POP   EAX

  MOV   TAhRegisters[ESP+4].rESP, ESP
  ADD   TAhRegisters[ESP+4].rESP, RegistersSize + $10

  MOV   TAhRegisters[ESP+4].rEAX, EAX
  MOV   TAhRegisters[ESP+4].rECX, ECX
  MOV   TAhRegisters[ESP+4].rEDX, EDX
  MOV   TAhRegisters[ESP+4].rEBX, EBX
  MOV   TAhRegisters[ESP+4].rEBP, EBP
  MOV   TAhRegisters[ESP+4].rESI, ESI
  MOV   TAhRegisters[ESP+4].rEDI, EDI
end;

procedure RestoreRegisters;
asm
  { EIP and ESP are skipped }

  MOV   EAX, TAhRegisters[ESP+4].rEAX
  MOV   ECX, TAhRegisters[ESP+4].rECX
  MOV   EDX, TAhRegisters[ESP+4].rEDX
  MOV   EBX, TAhRegisters[ESP+4].rEBX
  MOV   EBP, TAhRegisters[ESP+4].rEBP
  MOV   ESI, TAhRegisters[ESP+4].rESI
  MOV   EDI, TAhRegisters[ESP+4].rEDI
end;

procedure PreHook;
asm
  { Input:  ESP+4 - proc hook index }

  SUB   ESP, RegistersSize
  CALL  CaptureRegisters

  PUSH  EAX
  PUSH  ECX
  MOV   ECX, [ESP + RegistersSize + $0C]

  PUSH  ECX
  LEA   EAX, [ESP + $0C]
  PUSH  EAX
  CALL  DoPreHook

  POP   ECX
  POP   EAX
                         
  CALL  RestoreRegisters
  ADD   ESP, RegistersSize
  RET   4
end;

procedure PostHook;
asm
  { Input:  ESP+4 - proc hook index }
  {         ESP+8 - original caller }

  SUB   ESP, RegistersSize
  CALL  CaptureRegisters

  PUSH  EAX
  PUSH  ECX

  MOV   ECX, [ESP + RegistersSize + $10]
  PUSH  ECX
  MOV   ECX, [ESP + RegistersSize + $10]
  PUSH  ECX
  LEA   EAX, [ESP + $10]
  PUSH  EAX
  CALL  DoPostHook

  POP   ECX
  POP   EAX

  CALL  RestoreRegisters
  ADD   ESP, RegistersSize
  RET   4
end;

procedure DoPreHook(const Registers: TAhRegisters; Index: Integer); stdcall;
var
  Count: Integer;
begin
  if not CheckProcHookIndex('PreHook', Index) then
    Exit;

  with ProcHooks[Index] do
  begin
    // optimization to avoid entering critical section on local calls.
    if (Mode = hmPrologue) and (PrologueLength > 0) and SkipHookedCaller(AnyCaller, Registers.rEIP) then
      Exit;

    InterlockedIncrement(ActiveCount);

    case LLUseCritSect of
    csGlobal:
      EnterCriticalSection(GlobalCritSection);
    csPerProc:
      EnterCriticalSection(CritSection);
    end;

    if (Mode = hmPrologue) and (PrologueLength = 0) then
      PatchCopying(OrigAddr, @OrigPrologue[0], SizeOf(TPrologue));

    if SkipHookedCaller(AnyCaller, Registers.rEIP) or (InterlockedExchangeAdd(Unhooking, 0) <> 0) then
    begin
      LLDbg('PREMATURE LEAVE PRE (index %d = %s).', [Index, Proc]);
      Exit;
    end;

    LLDbg('PRE HOOK (index %d = %s).', [Index, Proc]);
    Context := TAhHookedContext.Create(Index, Registers);

    try
      Count := Script.RunActionsOf(Proc, Context.Bindings, [raPre]);
      LLDbg('ran %d pre-actions.', [Count]);
    except
      on E: Exception do
        LLHookRunningError('pre', Proc, E);
    end;
  end;
end;

procedure DoPostHook(var Registers: TAhRegisters; Index: Integer; Caller: Pointer); stdcall;
  procedure PrepareLeave;
  begin
    case LLUseCritSect of
    csGlobal:   LeaveCriticalSection(GlobalCritSection);
    csPerProc:  LeaveCriticalSection(ProcHooks[Index].CritSection);
    end;

    InterlockedDecrement(ProcHooks[Index].ActiveCount);
  end;

var
  Count: Integer;
begin
  if not CheckProcHookIndex('PostHook', Index) then
    Exit;

  with ProcHooks[Index] do
  begin
    Registers.rEIP := DWord(Caller);

    if (Mode = hmPrologue) and (PrologueLength > 0) and SkipHookedCaller(AnyCaller, Registers.rEIP) then
      Exit;

    if (Mode = hmPrologue) and (PrologueLength = 0) then
      PatchCopying(OrigAddr, @NewPrologue[0], SizeOf(TPrologue));

    if SkipHookedCaller(AnyCaller, Registers.rEIP) or
       (InterlockedExchangeAdd(Unhooking, 0) <> 0) or
       ( (Context = NIL) and LLErr('PostHook(%d) called with NIL Context.', [Index]) ) then
    begin
      LLDbg('PREMATURE LEAVE POST (index %d = %s).', [Index, Proc]);
      PrepareLeave;
      Exit;
    end;

    LLDbg('POST HOOK (index %d = %s)', [Index, Proc]);

    Context.IsAfterCall := True;
    Context.Registers := Registers;

    try
      Count := Script.RunActionsOf(Proc, Context.Bindings, [raPost]);
      LLDbg('ran %d post-actions.', [Count]);
    except
      on E: Exception do
        LLHookRunningError('post', Proc, E);
    end;

    FreeAndNIL(Context);
    PrepareLeave;

    LLDbg('LEFT HOOK (index %d = %s)', [Index, Proc]);
  end;
end;

function HookPrologueProc(var Hook: TProcHook): Boolean;
const
  VpError = 'VirtualProtect(proc = %s, addr = %.8X, size = %d, PAGE_READWRITE) has failed.';
  ShortPrologueError = 'Prologue of function %s is too short (%d bytes) - must be at least %d.' +
                       ' Falling back to less safe hot prologue swapping.';
begin
  Result := False;

  with Hook do
  begin
    if not VirtualProtect(OrigAddr, SizeOf(TPrologue), PAGE_EXECUTE_READWRITE, @OldPageMode)
       and LLErr(VpError, [Proc, DWord(OrigAddr), SizeOf(TPrologue)]) then
      Exit;

    if (PrologueLength > 0) and (PrologueLength < SizeOf(TPrologue)) and
       LLErr(ShortPrologueError, [Proc, PrologueLength, SizeOf(TPrologue)]) then
      PrologueLength := 0;

    if PrologueLength > 0 then
      FillVarPrologueOf(Hook);

    PatchCopying(@OrigPrologue[0], OrigAddr, SizeOf(TPrologue));
    PatchCopying(OrigAddr, @NewPrologue[0], SizeOf(TPrologue));

    { We don't undo VirtualProtect because OrigAddr might be constantly rewritten by Pre/PostHook. }

    LLDbg('Assigned proc hook ID %d; patched prologue at %.8X (OrigAddr), points to jumper at %.8X.',
          [ProcHookCount, DWord(OrigAddr), DWord(@Jumper[0])]);
  end;

  Result := True;
end;

function HookImportProc(var Hook: TProcHook): Boolean;
begin
  {$IFDEF AhDebug}
    Result := PatchImport(Hook.OrigAddr, @Hook.Jumper[0], SelfImageBase);
  {$ELSE}
    Result := PatchImport(Hook.OrigAddr, @Hook.Jumper[0]);
  {$ENDIF}

  if Result then
    LLDbg('Assigned proc hook ID %d; patched Import Table.', [ProcHookCount]);
end;

function FindTarget(const Name: String; const Proc: TApiProcInfo): Pointer;
const
  BeyondWarning = 'Warning: API proc %s''s address %.8X is beyond the end of base module''s (%s) address space (%.8X).';
var
  Base, Finish: DWord;
begin
  Result := NIL;

  if Proc.Addr <> DWord(-1) then
  begin
    Result := Pointer(Proc.Addr);

    if Proc.Lib <> '' then
    begin
      SetModuleInfo('main', GetModuleHandle(NIL), Base, Finish);
      Result := Pointer(DWord(Result) + Base);

      if DWord(Result) > Finish then
        LLErr(BeyondWarning, [Name, Result, Finish]);
    end;
  end
    else if (GetModuleHandle(PChar(Proc.Lib)) = 0) and (LoadLibrary(PChar(Proc.Lib)) = 0) then
      LLErr('LoadLibrary(%s) for %s has failed.', [Proc.Lib, Name])
      else
      begin
        Result := GetProcAddress( GetModuleHandle(PChar(Proc.Lib)), PChar(Name) );

        if Result = NIL then
          LLErr('GetProcAddress(%s, %s) has failed.', [Proc.Lib, Name]);
      end;
end;

function HookProc(const ProcName: String): Boolean;
var
  Addr: Pointer;
begin
  if HookIndexOf(ProcName) <> -1 then
  begin
    Result := True;
    Exit;
  end;

  LLDbg('Hooking %s...', [ProcName]);
  Result := False;

  Addr := FindTarget(ProcName, Procs[ProcName]);
  if Addr = NIL then
    Exit;

  if ProcHookCount >= Length(ProcHooks) then
    SetProcHookCount(ProcHookCount + ProcHookEnlargeBy);

  with ProcHooks[ProcHookCount] do
  begin
    Index := ProcHookCount;
    Proc := ProcName;
    Mode := Script[ Script.IndexOfProc(ProcName) ].HookMode;
    PrologueLength := Procs[ProcName].PrologueLength;
    AnyCaller := Procs[ProcName].AnyCaller;
    OrigAddr := Addr;
    FillNewPrologueOf( ProcHooks[ProcHookCount] );
    FillJumperOf( ProcHooks[ProcHookCount] );

    if LLUseCritSect = csPerProc then
      InitializeCriticalSection(CritSection);

    if Mode = hmPrologue then
      Result := HookPrologueProc( ProcHooks[ProcHookCount] )
      else
        Result := HookImportProc( ProcHooks[ProcHookCount] );
  end;

  if Result then
    Inc(ProcHookCount);
end;

function UnhookPrologueProc(var Hook: TProcHook): Boolean;
  function RestorePrologue: Boolean;
  begin
    Result := False;

    try
      PatchCopying(Hook.OrigAddr, @Hook.OrigPrologue[0], SizeOf(TPrologue));

      Result := CompareMem(Hook.OrigAddr, @Hook.OrigPrologue[0], SizeOf(TPrologue));
      if not Result then
        LLErr('Prologue doesn''t match original bytecode after restoration at %.8X, expected %s but actually read %s.',
              [DWord(Hook.OrigAddr),
               BinToHex(Hook.OrigAddr^, SizeOf(TPrologue), ' '),
               BinToHex(Hook.OrigPrologue[0], SizeOf(TPrologue), ' ')]);
    except
      on E: Exception do
        LLErr('Exception while restoring prologue at %.8X - <%s> %s', [DWord(Hook.OrigAddr), E.ClassName, E.Message]);
    end;
  end;

const
  Delay = 50;   // msec.
var
  Count, Tries: Integer;
begin
  LLDbg('Unhooking %s at %.8X (OrigAddr)...', [Hook.Proc, DWord(Hook.OrigAddr)]);
  Result := True;

  InterlockedIncrement(Hook.Unhooking);
  Result := RestorePrologue and Result;

  case LLUseCritSect of
  csGlobal:
    begin
      EnterCriticalSection(GlobalCritSection);
      LeaveCriticalSection(GlobalCritSection);
    end;
  csPerProc:
    begin
      EnterCriticalSection(Hook.CritSection);
      LeaveCriticalSection(Hook.CritSection);
    end;
  end;

  for Tries := 5000 div Delay downto 0 do
  begin
    Count := InterlockedExchangeAdd(Hook.ActiveCount, 0);
    LLDbg('waiting for %d active pre/post handler(s) to return...', [Count]);
    if Count <= 0 then
      Break;
    Sleep(Delay);
  end;

  if (Count > 0) and LLErr('Active hook handlers of %s take too long to return - forcefully closing the context.', [Hook.Proc]) then
    Result := False;

  if (LLUseCritSect = csPerProc) and Result then
    // See the note below below on why we don't delete the section on Result = False.
    DeleteCriticalSection(Hook.CritSection);

  if Hook.Context <> NIL then
    { Might be expected (if Result = True) - if there was a PreHook handler running before
      we've set Unhooking to non-zero; once that handler returns and proceeds to PostHook
      it will see Unhooking and abandon its context.
      But if Result = False we leave the context hang leaking memory but at least avoiding
      Access Violations and NIL refs when we deallocate the context in the middle of its
      actions running (waiting for which was adandoned since Result is False). }
    if Result then
      FreeAndNIL(Hook.Context)
      else
        LLErr('Context of %s hook wasn''t NIL when unhooking, IsAfterCall = %s.',
              [Hook.Proc, BoolToStr(Hook.Context.IsAfterCall, True)]);

  { Undoing VirtualProtect in ResetLowLevel in bulk because this function changes
    access mode of the entire page region and we might have more hooked functions
    belonging to the same page that are yet to be unhooked. }
end;

function UnhookImportProc(var Hook: TProcHook): Boolean;
begin
  LLDbg('Restoring Import Table record of %s from %.8X (Jumper) -> %.8X (OrigAddr)...',
        [Hook.Proc, DWord(@Hook.Jumper[0]), DWord(Hook.OrigAddr)]);

  Result := PatchImport(@Hook.Jumper[0], Hook.OrigAddr);

  if not Result then
    LLDbg('Could not restore the Import Table record!', []);
end;

function UnhookProc(var Hook: TProcHook): Boolean;
begin
  if Hook.Mode = hmPrologue then
    Result := UnhookPrologueProc(Hook)
    else
      Result := UnhookImportProc(Hook);
end;

{ Exports }

procedure InitVars(const HookImageName: WideString);
var
  Modules: TProcessModules;
  I: Integer;
begin
  PreHookAddr := @PreHook;
  PostHookAddr := @PostHook;
  HookImageEnd := 0;
  Modules := NIL;   // compiler warning.

  SetModuleInfo('self', hInstance, SelfImageBase, SelfImageEnd);

  if HookImageName = '' then
  begin
    SetModuleInfo('main', GetModuleHandle(NIL), HookImageBase, HookImageEnd);
    LLDbg('Restricted hooks to main module at %.8X..%.8X.', [HookImageBase, HookImageEnd]);
  end
    else if HookImageName = '*' then
      LLDbg('Hooking all callers except for the library itself (HookImageName is ''*'').', [])
      else
      begin
        Modules := GetProcessModules;

        for I := 0 to Length(Modules) - 1 do
          with Modules[I] do
            if PosW(HookImageName, Name) <> 0 then
            begin
              HookImageBase := BaseAddress;
              HookImageEnd := EndAddress;
              LLDbg('Restricted hooks to module %s at %.8X..%.8X.', [Name, BaseAddress, EndAddress]);
              Break;
            end;

        if HookImageEnd = 0 then
          LLErr('No matching module ''%s'' to restrict hooks to; hooking all.', [HookImageName]);
      end;
end;

procedure InitLowLevel(var AScript: TAhScript; var ACatalog: TAhApiCatalog; const HookImageName: WideString);
var
  I: Integer;
begin
  LLDbg('Initializing...', []);

  if ACatalog <> NIL then
  begin
    if Procs <> NIL then
      Procs.Free;
    Procs := ACatalog;
    ACatalog := NIL;
  end
    else if (Procs = NIL) and LLErr('No ACatalog (Procs) passed to InitLowLevel.', []) then
      Exit;

  if AScript <> NIL then
  begin
    if Script <> NIL then
      Script.Free;
    Script := AScript;
    AScript := NIL;
  end
    else if (Script = NIL) and LLErr('No AScript passed to InitLowLevel.', []) then
      Exit;

  Procs.Consts.NotExistingVarCallback := Script.Consts.GetIfExists;

  InitVars(HookImageName);
  LLDbg('Library is loaded at %.8X..%.8X.', [SelfImageBase, SelfImageEnd]);

  SetProcHookCount(Max(InitialProcHookCount, Script.ProcCount));

  for I := 0 to Script.ProcCount - 1 do
    if not HookProc(Script.ProcNames[I]) then
      LLErr('Error hooking procedure %s - might be misspelled or the program doesn''t import it.', [Script.ProcNames[I]]);
end;

procedure ResetLowLevel;
var
  I: Integer;
begin
  LLDbg('Resetting...', []);

  for I := 0 to ProcHookCount - 1 do
    if not UnhookProc(ProcHooks[I]) then
      LLErr('Possible error unhooking procedute %s.', [Script.ProcNames[I]]);

  // See the note in UnhookProc on why we're undoing VirtualProtect here.
  for I := 0 to ProcHookCount - 1 do
    with ProcHooks[I] do
      if not VirtualProtect(OrigAddr, SizeOf(TPrologue), OldPageMode, @OldPageMode) then
        LLErr('Cannot undo VirtualProtect''ion of %s at address %.8X.', [Proc, DWord(OrigAddr)]);

  SetProcHookCount(0);
end;

function IsLowLevelInit: Boolean;
begin
  Result := ProcHookCount > 0;
end;

initialization
  SetLength(ProcModules, 0);

  GlobalSaved := TObjectHash.Create(True);
  // global save names are all upper-case anyway, see TAhHookedContext.IsGlobalSave.
  GlobalSaved.CaseSensitive := True;
  GlobalSaved.Sorted := True;
  GlobalSaved.Duplicates := dupError;

  InitializeCriticalSection(GlobalCritSection);

finalization
  DeleteCriticalSection(GlobalCritSection);
  GlobalSaved.Free;

  if Procs <> NIL then
    Procs.Free;
  if Script <> NIL then
    Script.Free;
end.
