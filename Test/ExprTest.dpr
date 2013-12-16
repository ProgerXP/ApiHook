program ExprTest;

{$APPTYPE CONSOLE}

uses
  RPNit;

type
  TFuncVars = class (TRpnVariables)
  public
    function GetIfExists(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean; override;
  end;

{ TVarFunc }

function TFuncVars.GetIfExists(Eval: TRpnEvaluator; const Name: WideString; out Value: TRpnScalar): Boolean;
begin
  Result := True;

  if Name = '<<' then
    Value := RpnNum(Trunc(Eval.Stack.PopInt) shl Trunc(Eval.Stack.PopInt))
    else if Name = 'CHR' then
      Value := RpnStr(WideChar(Trunc(Eval.Stack.PopInt)))
      else
        Result := False;
end;

const
  Expr: WideString = '1 6 << CHR';
var
  Res: TRpnScalar;
begin
  SetRpnVarChars(RpnVarChars + '<>');

  Res := EvalRPN(Expr, TRpnVariables(TFuncVars.Create));
  WriteLn(RpnKindToStr(Res.Kind), ' = ', Res.Str);
  ReadLn;
end.
