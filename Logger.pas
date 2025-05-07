{
  Logger - Simple HTTP Server Component
  Author: Gecko71
  Copyright: 2025

  LICENSE:
  ========
  This code is provided for non-commercial use only. The code is provided "as is"
  without warranty of any kind, either expressed or implied, including but not
  limited to the implied warranties of merchantability and fitness for a particular
  purpose.

  You are free to:
  - Use this code for personal, educational, or non-commercial purposes
  - Modify, adapt, or build upon this code as needed
  - Share the code with others under the same license terms

  You may not:
  - Use this code for commercial purposes without explicit permission
  - Remove this license notice from any copies or derivatives

  THE AUTHOR(S) SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM THE USE
  OF THIS SOFTWARE.

  By using this code, you acknowledge that you have read and understood
  this license and agree to its terms.
}

unit Logger;

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs, System.IOUtils;

type
  TNewLogLineEvent = procedure(Sender: TObject; const LogLine: string) of object;
  TNewLogLineProc = reference to procedure(Sender: TObject; const LogLine: string);

  THttpLogger = class
  private
    FCriticalSection: TCriticalSection;
    FLogDir: string;
    FOnNewLogLine: TNewLogLineEvent;
    FOnNewLogLineProc: TNewLogLineProc;
    function GetLogFileName: string;
    procedure EnsureLogDirExists;
    procedure DoNewLogLine(const Line: string);
  public
    constructor Create(const LogDir: string = 'Log');
    destructor Destroy; override;

    procedure Log(const Msg: string);

    property OnNewLogLine: TNewLogLineEvent read FOnNewLogLine write FOnNewLogLine;
    property OnNewLogLineProc: TNewLogLineProc read FOnNewLogLineProc write FOnNewLogLineProc;
  end;

implementation

{ THttpLogger }

constructor THttpLogger.Create(const LogDir: string);
begin
  inherited Create;
  FCriticalSection := TCriticalSection.Create;
  FLogDir := IncludeTrailingPathDelimiter(TPath.Combine(ExtractFilePath(ParamStr(0)), LogDir));
  EnsureLogDirExists;
end;

destructor THttpLogger.Destroy;
begin
  FCriticalSection.Free;
  inherited;
end;

procedure THttpLogger.EnsureLogDirExists;
begin
  if not DirectoryExists(FLogDir) then
    ForceDirectories(FLogDir);
end;

function THttpLogger.GetLogFileName: string;
begin
  Result := FLogDir + FormatDateTime('yyyy_mm_dd', Now) + '.log';
end;

procedure THttpLogger.DoNewLogLine(const Line: string);
var
  mLine:string;
begin
  mLine := Line;
  while (Length(mLine) > 0) and
        ((mLine[Length(mLine)] = #10) or (mLine[Length(mLine)] = #13)) do
  begin
    SetLength(mLine, Length(mLine) - 1);
  end;

  if Assigned(FOnNewLogLine) then
    FOnNewLogLine(Self, mLine);

  if Assigned(FOnNewLogLineProc) then
    FOnNewLogLineProc(Self, mLine);
end;

procedure THttpLogger.Log(const Msg: string);
var
  Line: string;
  LogStream: TFileStream;
  LogBytes: TBytes;
  LogFileName: string;
begin
  Line := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + ' - ' + Msg + sLineBreak;
  LogBytes := TEncoding.UTF8.GetBytes(Line);
  LogFileName := GetLogFileName;

  FCriticalSection.Acquire;
  try
    if TFile.Exists(LogFileName) then
      LogStream := TFileStream.Create(LogFileName, fmOpenReadWrite or fmShareDenyWrite)
    else
      LogStream := TFileStream.Create(LogFileName, fmCreate);
    try
      LogStream.Seek(0, soEnd);
      LogStream.WriteBuffer(LogBytes, Length(LogBytes));
    finally
      LogStream.Free;
    end;
  finally
    FCriticalSection.Release;
  end;

  DoNewLogLine(Line);
end;

end.

