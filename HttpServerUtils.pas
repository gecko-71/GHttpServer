{
  HttpServerUtils - Simple HTTP Server Component
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

unit HttpServerUtils;
interface
uses
  {$IFDEF MSWINDOWS}
  Windows, WinSock2,
  {$ENDIF}
  {$IFDEF LINUX}
  Libc,
  {$ENDIF}
  SysUtils, Classes, SyncObjs, DateUtils, Generics.Collections, System.Threading,
  Logger;



type
  TIPStatistics = class
  public
    IP: string;
    LastRequestTime: TDateTime;
    RequestCount: Integer;
    FailedAttempts: Integer;
    BlockedUntil: TDateTime;
    constructor Create(const AIP: string);
  end;
  TIPMonitor = class
  private
    FLock: TCriticalSection;
    FMaxRequestsPerMinute: Integer;
    FMaxFailedAttempts: Integer;
    FBlockTime: Integer; // block time in minutes
    FCleanupInterval: Integer; // in minutes
    FLastCleanupTime: TDateTime;
    FMaxIPRecords: Integer; // Maximum number of IP records
    HttpLogger: THttpLogger;
    procedure Log(const Msg: string);
  public
    FIPDict: TObjectDictionary<string, TIPStatistics>;
    constructor Create(AHttpLogger: THttpLogger = nil);
    destructor Destroy; override;
    function RegisterRequest(const IP: string): Boolean;
    procedure RegisterFailedAttempt(const IP: string);
    function IsIPBlocked(const IP: string): Boolean;
    procedure Cleanup;
    property MaxRequestsPerMinute: Integer read FMaxRequestsPerMinute write FMaxRequestsPerMinute;
    property MaxFailedAttempts: Integer read FMaxFailedAttempts write FMaxFailedAttempts;
    property BlockTime: Integer read FBlockTime write FBlockTime;
    property MaxIPRecords: Integer read FMaxIPRecords write FMaxIPRecords;
    property Lock: TCriticalSection read FLock;
  end;

  function BytesPos(const Bytes, Pattern: TBytes): Integer;

implementation

uses GHTTPConstants;

function BytesPos(const Bytes, Pattern: TBytes): Integer;
var
  LPS: array of Integer;
  i, j, N, M: Integer;
begin
  Result := 0;
  N := Length(Bytes);
  M := Length(Pattern);

  if (M = 0) or (N < M) then
    Exit;

  SetLength(LPS, M);
  LPS[0] := 0;
  j := 0;

  i := 1;
  while i < M do
  begin
    if Pattern[i] = Pattern[j] then
    begin
      Inc(j);
      LPS[i] := j;
      Inc(i);
    end
    else
    begin
      if j <> 0 then
        j := LPS[j - 1]
      else
      begin
        LPS[i] := 0;
        Inc(i);
      end;
    end;
  end;

  i := 0;
  j := 0;
  while i < N do
  begin
    if Bytes[i] = Pattern[j] then
    begin
      Inc(i);
      Inc(j);
    end;

    if j = M then
    begin
      Result := i - j + 1;
      Exit;
    end
    else if (i < N) and (Bytes[i] <> Pattern[j]) then
    begin
      if j <> 0 then
        j := LPS[j - 1]
      else
        Inc(i);
    end;
  end;
end;

{ TIPStatistics }
constructor TIPStatistics.Create(const AIP: string);
begin
  inherited Create;
  IP := AIP;
  LastRequestTime := Now;
  RequestCount := 1;
  FailedAttempts := 0;
  BlockedUntil := 0;
end;
{ TIPMonitor }
constructor TIPMonitor.Create( AHttpLogger: THttpLogger = nil);
begin
  HttpLogger := AHttpLogger;
  FIPDict := TObjectDictionary<string, TIPStatistics>.Create([doOwnsValues]);
  FLock := TCriticalSection.Create;
  FMaxRequestsPerMinute := C_DEFAULT_MAX_REQUESTS;  // per minute
  FMaxFailedAttempts := C_DEFAULT_MAX_FAILED;      // 5 failed attempts before blocking
  FBlockTime := C_DEFAULT_BLOCK_TIME;             // 0 minutes of blocking
  FCleanupInterval := C_DEFAULT_CLEANUP_INTERVAL;        // Cleanup every 3 minutes
  FMaxIPRecords := C_DEFAULT_MAX_IP_RECORDS;       // Maximum 10 thousand IP records
  FLastCleanupTime := Now;
  
  TTask.Run(procedure
  begin
    while not TThread.CurrentThread.CheckTerminated do
    begin
      TThread.Sleep(FCleanupInterval * 60 * 1000); // in milliseconds
      Cleanup;
    end;
  end);
end;
destructor TIPMonitor.Destroy;
begin
  FLock.Free;
  FIPDict.Free;
  inherited;
end;
procedure TIPMonitor.Log(const Msg: string);
begin
  HttpLogger.Log(Format(C_LOG_PREFIX, [DateTimeToStr(Now), Msg]));
end;
function TIPMonitor.RegisterRequest(const IP: string): Boolean;
var
  IPStats: TIPStatistics;
  CurrentTime: TDateTime;
begin
  Result := False;
  if IP = '' then
  begin
    Log(C_REGISTER_REQUEST_EMPTY_IP);
    Exit;
  end;
  CurrentTime := Now;
  FLock.Enter;
  try
    if not FIPDict.TryGetValue(IP, IPStats) then
    begin
      if FIPDict.Count >= FMaxIPRecords then
      begin
        Log(Format(C_REGISTER_REQUEST_MAX_RECORDS, [IP, FMaxIPRecords]));
        Exit;
      end;
      IPStats := TIPStatistics.Create(IP);
      FIPDict.Add(IP, IPStats);
      Result := True;
      Log(Format(C_REGISTER_REQUEST_NEW_IP, [IP]));
      Exit;
    end;
    if CurrentTime < IPStats.BlockedUntil then
    begin
      Log(Format(C_REGISTER_REQUEST_BLOCKED, [IP, DateTimeToStr(IPStats.BlockedUntil)]));
      Result := False;
      Exit;
    end;
    if MinutesBetween(CurrentTime, IPStats.LastRequestTime) >= 1 then
    begin
      IPStats.RequestCount := 0;
      Log(Format(C_REGISTER_REQUEST_RESET_COUNT, [IP]));
    end;
    Inc(IPStats.RequestCount);
    IPStats.LastRequestTime := CurrentTime;
    if IPStats.RequestCount > FMaxRequestsPerMinute then
    begin
      IPStats.BlockedUntil := CurrentTime + (FBlockTime / 1440);
      Log(Format(C_REGISTER_REQUEST_BLOCKED_EXCEEDING, [IP, FMaxRequestsPerMinute]));
      Result := False;
    end
    else
    begin
      Result := True;
      Log(Format(C_REGISTER_REQUEST_COUNT, [IP, IPStats.RequestCount]));
    end;
  finally
    FLock.Leave;
  end;
end;
procedure TIPMonitor.RegisterFailedAttempt(const IP: string);
var
  IPStats: TIPStatistics;
begin
  if IP = '' then
  begin
    Log(C_REGISTER_FAILED_EMPTY_IP);
    Exit;
  end;
  FLock.Enter;
  try
    if not FIPDict.TryGetValue(IP, IPStats) then
    begin
      if FIPDict.Count >= FMaxIPRecords then
      begin
        Log(Format(C_REGISTER_FAILED_MAX_RECORDS, [IP, FMaxIPRecords]));
        Exit;
      end;
      IPStats := TIPStatistics.Create(IP);
      FIPDict.Add(IP, IPStats);
    end;
    Inc(IPStats.FailedAttempts);
    Log(Format(C_REGISTER_FAILED_COUNT, [IP, IPStats.FailedAttempts]));
    if IPStats.FailedAttempts >= FMaxFailedAttempts then
    begin
      IPStats.BlockedUntil := Now + (FBlockTime / 1440);
      Log(Format(C_REGISTER_FAILED_BLOCKED, [IP, FMaxFailedAttempts]));
    end;
  finally
    FLock.Leave;
  end;
end;
function TIPMonitor.IsIPBlocked(const IP: string): Boolean;
var
  IPStats: TIPStatistics;
begin
  Result := False;
  if IP = '' then
  begin
    Log(C_IS_IP_BLOCKED_EMPTY);
    Exit;
  end;
  FLock.Enter;
  try
    if FIPDict.TryGetValue(IP, IPStats) then
      Result := Now < IPStats.BlockedUntil;
    if Result then
      Log(Format(C_IS_IP_BLOCKED_UNTIL, [IP, DateTimeToStr(IPStats.BlockedUntil)]))
    else
      Log(Format(C_IS_IP_BLOCKED_NOT, [IP]));
  finally
    FLock.Leave;
  end;
end;
procedure TIPMonitor.Cleanup;
var
  CurrentTime: TDateTime;
  IP: string;
  IPStats: TIPStatistics;
  KeysToRemove: TList<string>;
begin
  CurrentTime := Now;
  FLastCleanupTime := CurrentTime;
  KeysToRemove := TList<string>.Create;
  try
    FLock.Enter;
    try
      for IP in FIPDict.Keys do
      begin
        IPStats := FIPDict[IP];
        if (MinutesBetween(CurrentTime, IPStats.LastRequestTime) > C_DEFAULT_INACTIVE_MINUTES) and
           (CurrentTime > IPStats.BlockedUntil) then
          KeysToRemove.Add(IP);
      end;
      for IP in KeysToRemove do
      begin
        FIPDict.Remove(IP);
        Log(Format(C_CLEANUP_REMOVED_IP, [IP]));
      end;
    finally
      FLock.Leave;
    end;
  finally
    KeysToRemove.Free;
  end;
  Log(Format(C_CLEANUP_SUMMARY, [KeysToRemove.Count, FIPDict.Count]));
end;

end.
