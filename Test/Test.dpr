program Test;

{$APPTYPE CONSOLE}

uses
  Windows, SysUtils;

const
  FN = 'temp.tmp';
  Str = 'Test string.';
var
  Handle: THandle;
  I: DWord;
  Buf: array[0..2047] of Char;
  S: String;
begin
  try
    ChDir(ExtractFilePath(ParamStr(0)));

    Handle := CreateFileA(FN, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NIL, OPEN_ALWAYS, 0, 0);
    if Handle = INVALID_HANDLE_VALUE then
      Halt(1);
    WriteFile(Handle, Str[1], Length(Str), I, NIL);
    SetFilePointer(Handle, 5, NIL, FILE_BEGIN);
    ReadFile(Handle, Buf[0], Length(Buf), I, NIL);

      WriteLn('String read from ', FN, ': "', Buf, '"');
      WriteLn;

      repeat
        Write('Type something to write to "', FN, '" or press Enter to exit... ');
        ReadLn(S);
        WriteFile(Handle, S[1], Length(S), I, NIL);
        WriteLn('  written ', I, ' bytes');;

        SetFilePointer(Handle, -1 * I, NIL, FILE_CURRENT);
        ReadFile(Handle, Buf[0], Length(Buf), I, NIL);
        WriteLn('  read: ', Copy(Buf, 0, I));
      until S = '';

    CloseHandle(Handle);
  except
    on E: Exception do
    begin
      WriteLn('<', E.ClassName, '>');
      WriteLn(E.Message);
    end;
  end;
end.
