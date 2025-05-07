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

    // Registers new data from a given IP, returns True if data can be processed
    function RegisterRequest(const IP: string): Boolean;

    // Registers failed attempts
    procedure RegisterFailedAttempt(const IP: string);

    // Checks if IP is blocked
    function IsIPBlocked(const IP: string): Boolean;

    // Cleans old entries
    procedure Cleanup;

    property MaxRequestsPerMinute: Integer read FMaxRequestsPerMinute write FMaxRequestsPerMinute;
    property MaxFailedAttempts: Integer read FMaxFailedAttempts write FMaxFailedAttempts;
    property BlockTime: Integer read FBlockTime write FBlockTime;
    property MaxIPRecords: Integer read FMaxIPRecords write FMaxIPRecords;
    property Lock: TCriticalSection read FLock;
  end;


implementation

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

  FMaxRequestsPerMinute := 340;  // per minute
  FMaxFailedAttempts := 5;      // 5 failed attempts before blocking
  FBlockTime := 0;             // 0 minutes of blocking
  FCleanupInterval := 3;        // Cleanup every 3 minutes
  FMaxIPRecords := 10000;       // Maximum 10 thousand IP records
  FLastCleanupTime := Now;
  // Run cyclical cleanup task
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
  HttpLogger.Log(Format('[%s] [TIPMonitor] %s', [DateTimeToStr(Now), Msg]));
end;

function TIPMonitor.RegisterRequest(const IP: string): Boolean;
var
  IPStats: TIPStatistics;
  CurrentTime: TDateTime;
begin
  Result := False;
  if IP = '' then
  begin
    Log('RegisterRequest: Empty IP address');
    Exit;
  end;

  CurrentTime := Now;

  FLock.Enter;
  try
    if not FIPDict.TryGetValue(IP, IPStats) then
    begin
      // Checks record limit
      if FIPDict.Count >= FMaxIPRecords then
      begin
        Log(Format('RegisterRequest: Cannot add IP %s, max records (%d) reached', [IP, FMaxIPRecords]));
        Exit;
      end;
      IPStats := TIPStatistics.Create(IP);
      FIPDict.Add(IP, IPStats);
      Result := True;
      Log(Format('RegisterRequest: New IP %s added', [IP]));
      Exit;
    end;

    // Checks if IP is blocked
    if CurrentTime < IPStats.BlockedUntil then
    begin
      Log(Format('RegisterRequest: IP %s blocked until %s', [IP, DateTimeToStr(IPStats.BlockedUntil)]));
      Result := False;
      Exit;
    end;

    // Reset counter
    if MinutesBetween(CurrentTime, IPStats.LastRequestTime) >= 1 then
    begin
      IPStats.RequestCount := 0;
      Log(Format('RegisterRequest: Reset request count for IP %s', [IP]));
    end;

    // Increase counter
    Inc(IPStats.RequestCount);
    IPStats.LastRequestTime := CurrentTime;

    // Check limit
    if IPStats.RequestCount > FMaxRequestsPerMinute then
    begin
      IPStats.BlockedUntil := CurrentTime + (FBlockTime / 1440);
      Log(Format('RegisterRequest: IP %s blocked for exceeding %d requests/min', [IP, FMaxRequestsPerMinute]));
      Result := False;
    end
    else
    begin
      Result := True;
      Log(Format('RegisterRequest: IP %s request count = %d', [IP, IPStats.RequestCount]));
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
    Log('RegisterFailedAttempt: Empty IP address');
    Exit;
  end;

  FLock.Enter;
  try
    if not FIPDict.TryGetValue(IP, IPStats) then
    begin
      if FIPDict.Count >= FMaxIPRecords then
      begin
        Log(Format('RegisterFailedAttempt: Cannot add IP %s, max records (%d) reached', [IP, FMaxIPRecords]));
        Exit;
      end;
      IPStats := TIPStatistics.Create(IP);
      FIPDict.Add(IP, IPStats);
    end;

    Inc(IPStats.FailedAttempts);
    Log(Format('RegisterFailedAttempt: IP %s failed attempts = %d', [IP, IPStats.FailedAttempts]));

    if IPStats.FailedAttempts >= FMaxFailedAttempts then
    begin
      IPStats.BlockedUntil := Now + (FBlockTime / 1440);
      Log(Format('RegisterFailedAttempt: IP %s blocked for %d failed attempts', [IP, FMaxFailedAttempts]));
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
    Log('IsIPBlocked: Empty IP address');
    Exit;
  end;

  FLock.Enter;
  try
    if FIPDict.TryGetValue(IP, IPStats) then
      Result := Now < IPStats.BlockedUntil;
    if Result then
      Log(Format('IsIPBlocked: IP %s is blocked until %s', [IP, DateTimeToStr(IPStats.BlockedUntil)]))
    else
      Log(Format('IsIPBlocked: IP %s is not blocked', [IP]));
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
        if (MinutesBetween(CurrentTime, IPStats.LastRequestTime) > 30) and
           (CurrentTime > IPStats.BlockedUntil) then
          KeysToRemove.Add(IP);
      end;

      for IP in KeysToRemove do
      begin
        FIPDict.Remove(IP);
        Log(Format('Cleanup: Removed IP %s', [IP]));
      end;
    finally
      FLock.Leave;
    end;
  finally
    KeysToRemove.Free;
  end;

  Log(Format('Cleanup: Removed %d records, current count = %d', [KeysToRemove.Count, FIPDict.Count]));
end;

end.
