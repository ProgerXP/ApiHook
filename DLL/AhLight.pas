unit AhLight;

interface

uses Windows, SysUtils, Classes, RPNit, FileStreamW, StringsW, StringUtils, Utils, AhCommon,
     AhScript, Lightpath, LpCore, LpModelling, LpExpressions, LpNodeTools, LpAppUtils;

type
  TLightAction = class (TAhRangeAction)
  protected
    FFile, FModel: WideString;

    function Parse(Args: WideString): TWideStringArray; override;
    procedure CheckArgs; override;
    procedure PerformOnRange(Start, Size: Integer); override;
    function Compile: TLpCompiler;
    function BuildOutput(Slicer: TLpSlicer; Level: Integer): WideString;
    function EvalProp(Slicer: TLpSlicer; Spec: TLpSpecialPath): WideString;
  public
    class function OnCreateNode(Node: TLpModelNode; Parent: TLpNode): TLpNode;
    class procedure OnWarning(AObject: TObject; E: Exception); 
  end;

implementation

uses LpTestTracer;

var
  ScriptCache: TObjectHash;   // Key = 'Age=file\path.lp', Value = TLpScript or nil.
  ModelCache: TObjectHash;    // Key = 'ScriptCache.Index=Section', Value = compiled TLpModel.
  // We need to block hashes above plus their contents so that one compiler
  // can't be used in multiple threads.
  CacheCritSection: TRTLCriticalSection;

{ Functions }
             
procedure RemoveCachedModels(Index: Integer);
var
  Name: WideString;
begin
  SetLength(Name, 2);
  Move(Index, Name[1], 4);
  Index := ModelCache.IndexOfName(Name);
  while (Index >= 0) and (ModelCache.Names[Index] = Name) do
    ModelCache.Delete(Index);
end;

procedure RemoveCachedScript(const FN: WideString);
var
  I: Integer;
begin
  for I := 0 to ScriptCache.Count - 1 do
    if ScriptCache.ValueFromIndex[I] = FN then
    begin
      RemoveCachedModels(I);
      ScriptCache.Objects[I] := nil;  // not removing - ModelCache depends on indexes here.
      Exit;
    end;
end;       

{ TLightAction }
            
class function TLightAction.OnCreateNode(Node: TLpModelNode; Parent: TLpNode): TLpNode;
begin
  if PosW('$', Node.Props.Path) > 0 then
    Result := Parent.Add(Node.Props.Path)
  else
    Result := nil;
end;

class procedure TLightAction.OnWarning(AObject: TObject; E: Exception);
begin
  if not (E is ELpmInputLeft) then
    raise E;
end;

function TLightAction.Parse(Args: WideString): TWideStringArray;
begin
  FArgStr := Args;
  Split(Args, ' ', FFile, Args);
  Split(FFile, ':', FFile, FModel);

  if FFile = '' then
    FFile := DefaultFileName('.lp');
  if not FileExists(FFile) and (ExtractFileExt(FFile) = '') then
    FFile := FFile + '.lp';

  Result := inherited Parse(Args);
end;

procedure TLightAction.CheckArgs;
begin
  NeedArgs(2, 'script startAddr..size OR script startAddr--endAddr; script = [file[.lp]]:[subsection], file defaults to .oo''s base name');
end;

procedure TLightAction.PerformOnRange(Start, Size: Integer);
  function ModelName: WideString;
  begin
    if FModel = '' then
      Result := 'first supported'
    else
      Result := '''' + FModel + '''';
  end;

var
  Mem: TAhInMemoryStream;
  Compiler: TLpCompiler;
  Slicer: TLpSlicer;
  Output: WideString;
begin
  EnterCriticalSection(CacheCritSection);
  try
    Compiler := Compile;
    Mem := TAhInMemoryStream.Create(Pointer(Start), Size);
    try
      Slicer := Compiler.Modell(Mem);
      Output := BuildOutput(Slicer, 0);
    finally
      Mem.Free;
    end;
  finally
    LeaveCriticalSection(CacheCritSection);
  end;

  Log(logUser, '%s, %s section:%s', [ExtractFileName(FFile), ModelName, TrimRight(Output)]);
end;

function TLightAction.Compile: TLpCompiler;
var
  Age, ScriptIndex, ModelIndex: Integer;
  Key: WideString;
  Stream: TStream;
  Script: TLpScript;
  Subsection: TLpSubsection;
begin
  Age := FileAge(FFile);
  if Age = -1 then
    Error('No script file %s.', [FFile]);

  Key := '..=' + FFile;                   
  Move(Age, Key[1], 4);
  ScriptIndex := ScriptCache.IndexOf(Key);

  if ScriptIndex = -1 then
  begin
    RemoveCachedScript(FFile);
    Stream := TFileStreamW.Create(FFile, fmOpenRead);
    try
      Script := TLpScript.CreateFromStream(Stream);
    finally
      Stream.Free;
    end;

    ScriptIndex := ScriptCache.AddObject(Key, Script);
  end;

  Key := '..=' + FModel;
  Move(ScriptIndex, Key[1], 4);
  ModelIndex := ModelCache.IndexOf(Key);

  if ModelIndex = -1 then
  begin
    Script := ScriptCache.Objects[ScriptIndex] as TLpScript;

    if FModel = '' then
      Subsection := Script.Models.FirstSupported
    else
      Subsection := Script.Models.First(FModel);

    if Subsection = nil then
      Error('Script %s has no model subsection named ''%s'', only these: %s.', [FFile, FModel, Script.Models.AllKeys]);

    Result := Script.Models.Compile(Subsection.Index);
    Result.OnCreateNode := OnCreateNode;
    Result.OnWarning := OnWarning;
    ModelCache.AddObject(Key, Result);
  end
  else
    Result := ModelCache.Objects[ModelIndex] as TLpCompiler;
end;

function TLightAction.BuildOutput(Slicer: TLpSlicer; Level: Integer): WideString;
var
  Node: TLpNode;
  Spec: TLpSpecialPath;
  I: Integer;
begin
  Spec := TLpSpecialPath.Create(Slicer.BaseNode.Name);
  try
    if not Spec.WithProp then
      Result := Spec.Original
    else
      Result := EvalProp(Slicer, Spec);
  finally
    Spec.Free;
  end;

  Result := StrRepeat('  ', Level) + Result + LogEOLN;
  Inc(Level);
  Node := Slicer.BaseNode;

  for I := 0 to Node.Children.Count - 1 do
  begin
    Slicer.BaseNode := Node.Children[I];
    Result := Result + BuildOutput(Slicer, Level);
  end;
end;

function TLightAction.EvalProp(Slicer: TLpSlicer; Spec: TLpSpecialPath): WideString;
var
  Node: TLpNode;
  Prop: TLpProperty;
  Value: TLpValue;
begin
  Node := Slicer.BaseNode.FirstOnPath(Spec.Path);
  if Node = nil then
  begin
    Result := 'NO REFERENCED NODE: ' + Spec.Path;
    Exit;
  end;

  if Spec.Prop <> '' then
    Prop := Node.Props.TryByKey[Spec.Prop]
  else if Slicer.Length(Node.Props['inner']) <> 0 then
    Prop := Node.Props['inner']
  else
    Prop := Node.Props['start'];

  if Prop = nil then
  begin
    Result := 'NO REFERENCED PROPERTY: ' + Spec.Prop;
    Exit;
  end;

  if Spec.Expr = '' then
    Value := MakeRaw(Slicer.Slice(Prop, 20))
  else
    with TLpExpression.Create(Spec.Expr, Slicer.BaseNode) do
      try
        Stream := Slicer.RestrictedStreamSlice(Prop.Full);
        FreeOnFree(Stream);
        Finder := TLpNodeByNodeFinder.Create;
        FreeOnFree(Finder);

        Value := Evaluate;
      finally
        Free;
      end;

  if ltRaw in Value.Types then
    Result := ShortDump(Value.VRaw)
  else
    Result := RpnValueToStr(LpToRpnValue(Value), '(empty)');
end;

initialization
  ScriptCache := TObjectHash.Create;
  ModelCache := TObjectHash.Create;
  ModelCache.Sorted := True;            
  InitializeCriticalSection(CacheCritSection);
  Classes.RegisterClass(TLightAction);

finalization               
  DeleteCriticalSection(CacheCritSection);
  ModelCache.Free;
  ScriptCache.Free;
end.
