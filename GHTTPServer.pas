{
  GHTTPServer - Simple HTTP Server Component
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

unit GHTTPServer;

interface

uses
  {$IFDEF MSWINDOWS}
  WinSock, Windows,
  {$ENDIF}
  {$IFDEF LINUX}
  Posix.SysSocket, Posix.NetinetIn, Posix.ArpaInet, Posix.Unistd, Posix.NetDB,
  {$ENDIF}
  SysUtils, Classes, SyncObjs, System.Threading, Logger, System.StrUtils,
  HttpServerUtils, HTTPResponseBuilder, HTTPRequest;

type
  TClientInfo = record
    IP: string;
    StartTime: TDateTime;
    TotalBytesReceived: Integer;
    HeaderEndPos: Integer;
    ContentLength: Integer;
    ContentLengthValid: Boolean;
    HasContentLength: Boolean;
    PostDataReceived: Integer;
    ConnectionClosed: Boolean;
    IsHTTP10: Boolean;
    TimeoutValue: Double;
  end;
  // Forward declarations
  TGHTTPServer = class;

  // Event types for endpoints
  TEndpointEvent = procedure(Sender: TObject;
                        ARequestParser: THTTPRequestParser;
                        AResponseBuilder: THTTPResponseBuilder;
                        ASerwer:TGHTTPServer) of object;
  TEndpointEventProc = reference to procedure(Sender: TObject;
                        ARequestParser: THTTPRequestParser;
                        AResponseBuilder: THTTPResponseBuilder; ASerwer:TGHTTPServer) ;

  // Endpoint item
  TEndpointItem = class(TCollectionItem)
  private
    FEndpoint: string;
    FMethod: string;
    FOnRequest: TEndpointEvent;
    FOnRequestProc: TEndpointEventProc;
    procedure SetEndpoint(const Value: string);
    procedure SetMethod(const Value: string);
  protected
    function GetDisplayName: string; override;
  public
    constructor Create(Collection: TCollection); override;
  published
    property Endpoint: string read FEndpoint write SetEndpoint;
    property Method: string read FMethod write SetMethod;
    property OnRequest: TEndpointEvent read FOnRequest write FOnRequest;
    property OnRequestProc: TEndpointEventProc read FOnRequestProc write FOnRequestProc;
  end;

  // Endpoint collection
  TEndpointCollection = class(TCollection)
  private
    FOwner: TGHTTPServer;
    function GetItem(Index: Integer): TEndpointItem;
    procedure SetItem(Index: Integer; Value: TEndpointItem);
  protected
    function GetOwner: TPersistent; override;
  public
    constructor Create(AOwner: TGHTTPServer);
    function Add: TEndpointItem;
    function FindEndpoint(const AEndpoint, AMethod: string): TEndpointItem;
    property Items[Index: Integer]: TEndpointItem read GetItem write SetItem; default;
  end;

  TGHTTPServer = class(TComponent)
  private
    FPort: Integer;
    FMaxConnections: Integer;
    FListening: Boolean;
    FServerSocket: TSocket;
    FActiveConnections: Integer;
    FConnectionLock: TCriticalSection;
    FThreadPool: TThreadPool;
    HttpLogger: THttpLogger;
    FBaseDirectory: string;
    FTmpBaseDirectory: string;
    FMimeTypes: TStringList;
    FMaxHeaderSize: Integer;
    FMaxRequestTime: Double;
    FMaxPostSize: Integer;
    FMaxWorkerThreads: Integer;
    FMinWorkerThreads: Integer;
    FBufferSize: Integer;
    FSendTimeout: Integer;
    FFileTransferTimeout: Double;
    FEndpoints:TEndpointCollection;
    FGlobalIPMonitor: TIPMonitor;

    procedure SetServerSocket(const Value: TSocket);
    function CreateResponseNew(const Request: TBytes; ClientSocket: TSocket;
                  out Response: TBytes; AClientIP:String): Boolean;
    procedure ProcessClientRequestNew(ClientSocket: TSocket);
    function ExtractUserAgent(const Request: string): string;
    function IsSuspiciousUserAgent(const UserAgent: string): Boolean;
    function GetMimeType(const FileName: string): string;
    procedure InitializeMimeTypes;
    function WaitForSocketReady(Socket: TSocket; ForReading: Boolean; TimeoutMs: Integer): Boolean;
    procedure SetMaxWorkerThreads(const Value: Integer);
    procedure SetMinWorkerThreads(const Value: Integer);
    procedure SetBaseDirectory(const Value: string);
    procedure SetTmpBaseDirectory(const Value: string);
    function SanitizeFilePath(const FilePath: string): string;
    function IsAllowedFileExtension(const FileName: string): Boolean;
    function GenerateSecurityHeaders: string;
    function SaveUploadedFile(const FileData: TBytes; const FileName: string;
      const ContentType: string): string;
    procedure SetEndpoints(const Value: TEndpointCollection);
    procedure ParseHeaders(const Request: string; Headers: TStringList);
  public
    constructor Create(AOwner: TComponent; Port: Integer; MaxConnections: Integer = 100; AHttpLogger: THttpLogger = nil);reintroduce;
    destructor Destroy; override;
    function AcceptConnection(var ClientAddr: TSockAddrIn): TSocket;
    procedure SetSocketNonBlocking(Socket: TSocket);
    procedure InitializeSocketLibrary;
    procedure FinalizeSocketLibrary;
    procedure IncrementConnections;
    procedure DecrementConnections;
    procedure WriteLog(log: string);
    procedure HandleClient(ClientSocket: TSocket); virtual;
    function GetMimeTypeFromFileExt(FileExt: string): string;
    function ExtractBoundary(const ContentType: string): string;
    procedure Start;virtual;
    procedure Stop;virtual;
    function GetActiveConnections: Integer;
    function AddEndpoint(const AEndpoint, AMethod: string; AHandler: TEndpointEvent): TEndpointItem;
    function AddEndpointProc(const AEndpoint, AMethod: string; AHandler: TEndpointEventProc): TEndpointItem;
    property ServerSocket: TSocket read FServerSocket write SetServerSocket;
    property GlobalIPMonitor: TIPMonitor read FGlobalIPMonitor;
    property ThreadPool: TThreadPool read FThreadPool;
    property Port: Integer read FPort write FPort;
    property MaxConnections: Integer read FMaxConnections write FMaxConnections;
    property BaseDirectory: string read FBaseDirectory write SetBaseDirectory;
    property TmpBaseDirectory: string read FTmpBaseDirectory write SetTmpBaseDirectory;
    property MaxHeaderSize: Integer read FMaxHeaderSize write FMaxHeaderSize;
    property MaxRequestTime: Double read FMaxRequestTime write FMaxRequestTime;
    property MaxPostSize: Integer read FMaxPostSize write FMaxPostSize;
    property MaxWorkerThreads: Integer read FMaxWorkerThreads write SetMaxWorkerThreads;
    property MinWorkerThreads: Integer read FMinWorkerThreads write SetMinWorkerThreads;
    property BufferSize: Integer read FBufferSize write FBufferSize;
    property SendTimeout: Integer read FSendTimeout write FSendTimeout;
    property FileTransferTimeout: Double read FFileTransferTimeout write FFileTransferTimeout;
    property Endpoints: TEndpointCollection read FEndpoints write SetEndpoints;
    property Listening: Boolean  read FListening write FListening;
  end;

  // Helper functions
  function FindBytes(const Haystack, Needle: TBytes; StartPos: Integer = 0): Integer;
  function FindHeaderEnd(const Data: TBytes; StartPos, EndPos: Integer): Integer;

implementation

uses
  System.IOUtils, System.Generics.Collections;

function FindBytes(const Haystack, Needle: TBytes; StartPos: Integer = 0): Integer;
var
  i, j: Integer;
begin
  Result := -1;
  if (Length(Needle) = 0) or (Length(Haystack) = 0) or
     (StartPos + Length(Needle) > Length(Haystack)) then
    Exit;

  for i := StartPos to Length(Haystack) - Length(Needle) do
  begin
    j := 0;
    while (j < Length(Needle)) and (Haystack[i + j] = Needle[j]) do
      Inc(j);

    if j = Length(Needle) then
    begin
      Result := i;
      Exit;
    end;
  end;
end;

function FindHeaderEnd(const Data: TBytes; StartPos, EndPos: Integer): Integer;
var
  i: Integer;
begin
  Result := -1;
  for i := StartPos to EndPos - 4 do
  begin
    if (Data[i] = 13) and (Data[i + 1] = 10) and
       (Data[i + 2] = 13) and (Data[i + 3] = 10) then
    begin
      Result := i;
      Exit;
    end;
  end;
end;

{ TEndpointItem }
constructor TEndpointItem.Create(Collection: TCollection);
begin
  inherited Create(Collection);
  FEndpoint := '/';
  FMethod := 'GET';
  FOnRequest := nil;
  FOnRequestProc := nil;
end;

procedure TEndpointItem.SetEndpoint(const Value: string);
begin
  if FEndpoint <> Value then
  begin
    FEndpoint := Value;
    Changed(False);
  end;
end;

procedure TEndpointItem.SetMethod(const Value: string);
begin
  if FMethod <> Value then
  begin
    FMethod := UpperCase(Value);
    Changed(False);
  end;
end;

function TEndpointItem.GetDisplayName: string;
begin
  Result := Format('%s %s', [FMethod, FEndpoint]);
end;

{ TEndpointCollection }

constructor TEndpointCollection.Create(AOwner: TGHTTPServer);
begin
  inherited Create(TEndpointItem);
  FOwner := AOwner;
end;

function TEndpointCollection.GetOwner: TPersistent;
begin
   Result := FOwner;
end;

function TEndpointCollection.GetItem(Index: Integer): TEndpointItem;
begin
  Result := TEndpointItem(inherited GetItem(Index));
end;

procedure TEndpointCollection.SetItem(Index: Integer; Value: TEndpointItem);
begin
  inherited SetItem(Index, Value);
end;

function TEndpointCollection.Add: TEndpointItem;
begin
  Result := TEndpointItem(inherited Add);
end;

function TEndpointCollection.FindEndpoint(const AEndpoint, AMethod: string): TEndpointItem;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to Count - 1 do
  begin
    if (Items[I].Endpoint = AEndpoint) and (Items[I].Method = AMethod) then
    begin
      Result := Items[I];
      Break;
    end;
  end;
end;

{ TGHTTPServer }

constructor TGHTTPServer.Create(AOwner: TComponent; Port: Integer;
           MaxConnections: Integer = 100; AHttpLogger: THttpLogger = nil);
begin
  inherited Create(AOwner);
  FEndpoints := TEndpointCollection.Create(self);
  FGlobalIPMonitor := TIPMonitor.Create(AHttpLogger);
  HttpLogger := AHttpLogger;
  FPort := Port;
  FMaxConnections := MaxConnections;
  FListening := False;
  FActiveConnections := 0;
  FConnectionLock := TCriticalSection.Create;
  FThreadPool := TThreadPool.Create;

  // Default values for server parameters
  FMaxWorkerThreads := 100;
  FMinWorkerThreads := 10;
  FMaxHeaderSize := 8192;
  FMaxRequestTime := 30 / (24 * 3600); // 30 seconds for headers
  FFileTransferTimeout := 300 / (24 * 3600); // 5 minutes for file transfers
  FMaxPostSize := 100 * 1024 * 1024; // 100 MB
  FBufferSize := 65536; // 64KB chunks
  FSendTimeout := 10000; // 10 seconds

  // Initialize thread pool with default values
  FThreadPool.SetMaxWorkerThreads(FMaxWorkerThreads);
  FThreadPool.SetMinWorkerThreads(FMinWorkerThreads);

  FBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Files');
  FTmpBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Tmp');

  if not TDirectory.Exists(FBaseDirectory) then
  begin
    if not ForceDirectories(FBaseDirectory) then
      raise Exception.Create('Failed to create directory: ' + FBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FBaseDirectory);

  if not TDirectory.Exists(FTmpBaseDirectory) then
  begin
    if not ForceDirectories(FTmpBaseDirectory) then
      raise Exception.Create('Failed to create directory: ' + FTmpBaseDirectory);
  end;

  // Dodanie trailing delimiter na ko cu  cie ki
  FTmpBaseDirectory := IncludeTrailingPathDelimiter(FTmpBaseDirectory);

  FMimeTypes := TStringList.Create;
  InitializeMimeTypes;
end;

destructor TGHTTPServer.Destroy;
begin
  Stop;
  FConnectionLock.Free;
  FThreadPool.Free;
  FMimeTypes.Free;
  GlobalIPMonitor.Free;
  FEndpoints.Free;
  inherited;
end;

function TGHTTPServer.SanitizeFilePath(const FilePath: string): string;
var
  CleanPath: string;
  FullPath: string;
begin
  // Remove any path traversal attempts
  CleanPath := StringReplace(FilePath, '../', '', [rfReplaceAll]);
  CleanPath := StringReplace(CleanPath, '..\', '', [rfReplaceAll]);
  CleanPath := StringReplace(CleanPath, '..', '', [rfReplaceAll]);

  // Remove any absolute path references
  if (Length(CleanPath) > 0) and ((CleanPath[1] = '/') or (CleanPath[1] = '\')) then
    CleanPath := Copy(CleanPath, 2, MaxInt);

  // Remove multiple slashes
  CleanPath := StringReplace(CleanPath, '//', '/', [rfReplaceAll]);
  CleanPath := StringReplace(CleanPath, '\\', '\', [rfReplaceAll]);

  // Get the full path
  FullPath := TPath.GetFullPath(TPath.Combine(FBaseDirectory, CleanPath));

  // Ensure the resulting path is within the base directory
  if not StartsText(FBaseDirectory, FullPath) then
    raise Exception.Create('Path traversal attempt detected');

  Result := CleanPath;
end;

function TGHTTPServer.IsAllowedFileExtension(const FileName: string): Boolean;
const
  AllowedExtensions: array[0..11] of string = (
    '.txt', '.html', '.htm', '.js', '.jpg',
    '.jpeg', '.png', '.gif', '.pdf', '.xml', '.json',
    '.dcu'
  );
var
  Ext: string;
  I: Integer;
begin
  Result := False;
  Ext := LowerCase(ExtractFileExt(FileName));
  for I := Low(AllowedExtensions) to High(AllowedExtensions) do
  begin
    if Ext = AllowedExtensions[I] then
    begin
      Result := True;
      Break;
    end;
  end;
end;

function TGHTTPServer.GenerateSecurityHeaders: string;
begin
  Result :=
    'X-Content-Type-Options: nosniff' + #13#10 +
    'X-Frame-Options: DENY' + #13#10 +
    'X-XSS-Protection: 1; mode=block' + #13#10 +
    'Referrer-Policy: strict-origin-when-cross-origin' + #13#10 +
    'Permissions-Policy: geolocation=(), microphone=(), camera=()' + #13#10 +
    'Content-Security-Policy: default-src ''self''; script-src ''self''; style-src ''self''; img-src ''self'' data:; connect-src ''self''; frame-ancestors ''none''; base-uri ''self''; form-action ''self'';' + #13#10 +
    'Strict-Transport-Security: max-age=31536000; includeSubDomains' + #13#10;
end;

procedure TGHTTPServer.SetServerSocket(const Value: TSocket);
begin
  FServerSocket := Value;
end;

procedure TGHTTPServer.SetBaseDirectory(const Value: string);
begin
  FBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Files');

  if not TDirectory.Exists(FBaseDirectory) then
  begin
    if not ForceDirectories(FBaseDirectory) then
      raise Exception.Create('Failed to create directory: ' + FBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FBaseDirectory);

  WriteLog(Format('Base directory set to: %s', [FBaseDirectory]));
end;

procedure TGHTTPServer.SetTmpBaseDirectory(const Value: string);
begin
  FTmpBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Files');

  if not TDirectory.Exists(FTmpBaseDirectory) then
  begin
    if not ForceDirectories(FTmpBaseDirectory) then
      raise Exception.Create('Failed to create directory: ' + FTmpBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FTmpBaseDirectory);

  WriteLog(Format('Base directory set to: %s', [FTmpBaseDirectory]));
end;

procedure TGHTTPServer.SetEndpoints(const Value: TEndpointCollection);
begin
  FEndpoints.Assign(Value);
end;

procedure TGHTTPServer.SetMaxWorkerThreads(const Value: Integer);
begin
  if Value > 0 then
  begin
    FMaxWorkerThreads := Value;
    if Assigned(FThreadPool) then
      FThreadPool.SetMaxWorkerThreads(Value);
  end;
end;

procedure TGHTTPServer.SetMinWorkerThreads(const Value: Integer);
begin
  if Value > 0 then
  begin
    FMinWorkerThreads := Value;
    if Assigned(FThreadPool) then
      FThreadPool.SetMinWorkerThreads(Value);
  end;
end;

procedure TGHTTPServer.SetSocketNonBlocking(Socket: TSocket);
{$IFDEF MSWINDOWS}
var
  NonBlocking: u_long;
{$ENDIF}
{$IFDEF LINUX}
var
  Flags: Integer;
{$ENDIF}
begin
  {$IFDEF MSWINDOWS}
  NonBlocking := 1;
  ioctlsocket(Socket, FIONBIO, NonBlocking);
  {$ENDIF}

  {$IFDEF LINUX}
  Flags := fcntl(Socket, F_GETFL, 0);
  fcntl(Socket, F_SETFL, Flags or O_NONBLOCK);
  {$ENDIF}
end;

function TGHTTPServer.WaitForSocketReady(Socket: TSocket; ForReading: Boolean; TimeoutMs: Integer): Boolean;
var
  FDSet: TFDSet;
  TimeVal: TTimeVal;
  SelectResult: Integer;
begin
  FD_ZERO(FDSet);
  FD_SET(Socket, FDSet);

  TimeVal.tv_sec := TimeoutMs div 1000;
  TimeVal.tv_usec := (TimeoutMs mod 1000) * 1000;

  if ForReading then
    SelectResult := select(Socket + 1, @FDSet, nil, nil, @TimeVal)
  else
    SelectResult := select(Socket + 1, nil, @FDSet, nil, @TimeVal);

  Result := SelectResult > 0;
end;

procedure TGHTTPServer.InitializeSocketLibrary;
{$IFDEF MSWINDOWS}
var
  WSAData: TWSAData;
{$ENDIF}
begin
  {$IFDEF MSWINDOWS}
  if WSAStartup($202, WSAData) <> 0 then
    raise Exception.Create('WSAStartup failed');
  {$ENDIF}
end;

procedure TGHTTPServer.FinalizeSocketLibrary;
begin
  {$IFDEF MSWINDOWS}
  WSACleanup;
  {$ENDIF}
end;

procedure TGHTTPServer.WriteLog(log: string);
begin
  try
    HttpLogger.Log(log);
  except
  end;
end;

procedure TGHTTPServer.Start;
var
  ServerAddr: TSockAddrIn;
  ClientAddr: TSockAddrIn;
  OptVal: Integer;
begin
  InitializeSocketLibrary;

  FServerSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if FServerSocket = INVALID_SOCKET then
    raise Exception.Create('Socket creation failed');

  // Set SO_REUSEADDR option
  OptVal := 1;
  setsockopt(FServerSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

  ServerAddr.sin_family := AF_INET;
  ServerAddr.sin_addr.s_addr := INADDR_ANY;
  ServerAddr.sin_port := htons(FPort);

  if bind(FServerSocket, ServerAddr, SizeOf(ServerAddr)) = SOCKET_ERROR then
    raise Exception.Create('Bind failed');

  if listen(FServerSocket, SOMAXCONN) = SOCKET_ERROR then
    raise Exception.Create('Listen failed');

  FListening := True;
  WriteLog(Format('Server started on port %d', [FPort]));

  while FListening do
  begin
    var ClientSocket := AcceptConnection(ClientAddr);
    if ClientSocket = INVALID_SOCKET then
      Continue;

    SetSocketNonBlocking(ClientSocket);

    if GetActiveConnections >= FMaxConnections then
    begin
      WriteLog('Too many connections, rejecting');
      {$IFDEF MSWINDOWS}
      closesocket(ClientSocket);
      {$ENDIF}
      {$IFDEF LINUX}
      __close(ClientSocket);
      {$ENDIF}
      Continue;
    end;

    HandleClient(ClientSocket);
  end;
end;

function TGHTTPServer.AcceptConnection(var ClientAddr: TSockAddrIn): TSocket;
{$IFDEF MSWINDOWS}
var
  AddrLen: Integer;
{$ENDIF}
{$IFDEF LINUX}
type
  socklen_t = UInt32;
var
  AddrLen: socklen_t;
{$ENDIF}
begin
  AddrLen := SizeOf(ClientAddr);
  Result := accept(FServerSocket, @ClientAddr, @AddrLen);
end;

procedure TGHTTPServer.HandleClient(ClientSocket: TSocket);
begin
  IncrementConnections;

  TTask.Run(procedure
  begin
    try
      ProcessClientRequestNew(ClientSocket);
    finally
      DecrementConnections;
      {$IFDEF MSWINDOWS}
      closesocket(ClientSocket);
      {$ENDIF}
      {$IFDEF LINUX}
      __close(ClientSocket);
      {$ENDIF}
    end;
  end, FThreadPool);
end;

procedure TGHTTPServer.IncrementConnections;
begin
  FConnectionLock.Enter;
  try
    Inc(FActiveConnections);
  finally
    FConnectionLock.Leave;
  end;
end;

procedure TGHTTPServer.DecrementConnections;
begin
  FConnectionLock.Enter;
  try
    Dec(FActiveConnections);
  finally
    FConnectionLock.Leave;
  end;
end;

procedure TGHTTPServer.Stop;
begin
  FListening := False;
  if FServerSocket <> INVALID_SOCKET then
  begin
    {$IFDEF MSWINDOWS}
    shutdown(FServerSocket, SD_BOTH);
    closesocket(FServerSocket);
    {$ENDIF}
    {$IFDEF LINUX}
    shutdown(FServerSocket, SHUT_RDWR);
    __close(FServerSocket);
    {$ENDIF}
    FServerSocket := INVALID_SOCKET;
  end;

  FinalizeSocketLibrary;
  WriteLog('Server stopped');
end;

function TGHTTPServer.GetActiveConnections: Integer;
begin
  FConnectionLock.Enter;
  try
    Result := FActiveConnections;
  finally
    FConnectionLock.Leave;
  end;
end;

function TGHTTPServer.ExtractBoundary(const ContentType: string): string;
var
  BoundaryPos: Integer;
begin
  Result := '';
  BoundaryPos := Pos('boundary=', ContentType);
  if BoundaryPos > 0 then
  begin
    Result := Copy(ContentType, BoundaryPos + 9, MaxInt);
    // Remove quotes if present
    if (Result <> '') and (Result[1] = '"') then
      Result := Copy(Result, 2, Length(Result) - 2);
  end;
end;

function TGHTTPServer.SaveUploadedFile(const FileData: TBytes; const FileName: string;
 const ContentType: string): string;
var
 FilePath: string;
 FileStream: TFileStream;
 SafeFileName: string;
 Extension: string;
 BaseFileName: string;
 Counter: Integer;
begin
 try
   SafeFileName := SanitizeFilePath(FileName);

   SafeFileName := TPath.GetFileName(SafeFileName);

   if not IsAllowedFileExtension(SafeFileName) then
     raise Exception.Create('File type not allowed');

   Extension := ExtractFileExt(SafeFileName);
   BaseFileName := ChangeFileExt(SafeFileName, '');

   FilePath := TPath.Combine(FTmpBaseDirectory, SafeFileName);
   Counter := 1;
   while FileExists(FilePath) do
   begin
     SafeFileName := BaseFileName + '_' + IntToStr(Counter) + Extension;
     FilePath := TPath.Combine(FTmpBaseDirectory, SafeFileName);
     Inc(Counter);
   end;

   if not TDirectory.Exists(FTmpBaseDirectory) then
     TDirectory.CreateDirectory(FTmpBaseDirectory);

   FileStream := TFileStream.Create(FilePath, fmCreate);
   try
     if Length(FileData) > 0 then
       FileStream.WriteBuffer(FileData[0], Length(FileData));
   finally
     FileStream.Free;
   end;

   Result := SafeFileName;
   WriteLog(Format('File uploaded: %s (%d bytes)', [SafeFileName, Length(FileData)]));
 except
   on E: Exception do
   begin
     WriteLog(Format('Error saving uploaded file: %s', [E.Message]));
     Result := '';
   end;
 end;
end;

function TGHTTPServer.AddEndpoint(const AEndpoint, AMethod: string; AHandler: TEndpointEvent): TEndpointItem;
begin
 Result := FEndpoints.Add;
 Result.Endpoint := AEndpoint;
 Result.Method := AMethod;
 Result.OnRequest := AHandler;
end;

function TGHTTPServer.AddEndpointProc(const AEndpoint, AMethod: string; AHandler: TEndpointEventProc): TEndpointItem;
begin
 Result := FEndpoints.Add;
 Result.Endpoint := AEndpoint;
 Result.Method := AMethod;
 Result.OnRequestProc := AHandler;
end;

procedure TGHTTPServer.ParseHeaders(const Request: string; Headers: TStringList);
var
  HeaderEndPos, LineStart, LineEnd: Integer;
  HeaderLine, HeaderName, HeaderValue: string;
  ColonPos: Integer;
begin
  Headers.Clear;

  // Find the end of headers (empty line)
  HeaderEndPos := Pos(#13#10#13#10, Request);
  if HeaderEndPos = 0 then
    Exit;

  // Skip the first line (request line with method, path, etc.)
  LineStart := Pos(#13#10, Request);
  if LineStart = 0 then
    Exit;

  LineStart := LineStart + 2; // Move past the #13#10

  // Parse each header line
  while LineStart < HeaderEndPos do
  begin
    LineEnd := PosEx(#13#10, Request, LineStart);
    if LineEnd = 0 then
      LineEnd := HeaderEndPos;

    HeaderLine := Copy(Request, LineStart, LineEnd - LineStart);
    ColonPos := Pos(':', HeaderLine);

    if ColonPos > 0 then
    begin
      HeaderName := Trim(Copy(HeaderLine, 1, ColonPos - 1));
      HeaderValue := Trim(Copy(HeaderLine, ColonPos + 1, MaxInt));

      if (HeaderName <> '') and (HeaderValue <> '') then
        Headers.Values[HeaderName] := HeaderValue;
    end;

    LineStart := LineEnd + 2;
  end;
end;


procedure TGHTTPServer.ProcessClientRequestNew(ClientSocket: TSocket);
const
  BUFFER_SIZE = 65535;
var
  Request: TBytes;
  Response: TBytes;
  ClientInfo: TClientInfo;

  function AppendBytes(const Bytes1, Bytes2: TBytes): TBytes;
  var
    LenBytes1, LenBytes2: Integer;
  begin
    LenBytes1 := Length(Bytes1);
    LenBytes2 := Length(Bytes2);
    SetLength(Result, LenBytes1 + LenBytes2);
    if LenBytes1 > 0 then
      Move(Bytes1[0], Result[0], LenBytes1);
    if LenBytes2 > 0 then
      Move(Bytes2[0], Result[LenBytes1], LenBytes2);
  end;

  function SocketErrorToString(ErrorCode: Integer): string;
  begin
    case ErrorCode of
      WSAEWOULDBLOCK: Result := 'Operation would block (WSAEWOULDBLOCK)';
      WSAENETDOWN: Result := 'Network is down (WSAENETDOWN)';
      WSAENOTSOCK: Result := 'Not a socket (WSAENOTSOCK)';
      WSAEOPNOTSUPP: Result := 'Operation not supported (WSAEOPNOTSUPP)';
      WSAESHUTDOWN: Result := 'Socket shutdown (WSAESHUTDOWN)';
      WSAECONNABORTED: Result := 'Connection aborted (WSAECONNABORTED)';
      WSAECONNRESET: Result := 'Connection reset (WSAECONNRESET)';
      WSAETIMEDOUT: Result := 'Connection timed out (WSAETIMEDOUT)';
      WSAEHOSTUNREACH: Result := 'Host unreachable (WSAEHOSTUNREACH)';
      else Result := Format('Socket Error (%d)', [ErrorCode]);
    end;
  end;

  procedure GetClientIP;
  var
    SockAddr: TSockAddr;
    AddrLen: Integer;
    IPAddrStr: PAnsiChar;
  begin
    AddrLen := SizeOf(SockAddr);
    ClientInfo.IP := '0.0.0.0';

    if getpeername(ClientSocket, SockAddr, AddrLen) = 0 then
    begin
      if SockAddr.sa_family = AF_INET then
      begin
        IPAddrStr := inet_ntoa(PSockAddrIn(@SockAddr)^.sin_addr);
        ClientInfo.IP := string(IPAddrStr);
      end
      else
      begin
        ClientInfo.IP := 'Unknown';
      end;
    end;

    WriteLog(Format('Task: Connection from IP %s', [ClientInfo.IP]));
  end;



  procedure SendErrorResponse(StatusCode: Integer; Message: string; ExtraHeaders: string = '');
  var
    ResponseText: string;
    ResponseBytes: TBytes;
    ErrorCode: Integer;
  begin
    ResponseText := Format('HTTP/1.1 %d %s'#13#10 +
                          'Content-Type: text/plain'#13#10 +
                          'Content-Length: %d'#13#10 +
                          'Connection: close'#13#10, [StatusCode, Message, Length(Message)]);

    if ExtraHeaders <> '' then
      ResponseText := ResponseText + ExtraHeaders + #13#10;

    ResponseText := ResponseText + #13#10 + Message;
    ResponseBytes := TEncoding.ASCII.GetBytes(ResponseText);

    ErrorCode := send(ClientSocket, ResponseBytes[0], Length(ResponseBytes), 0);
    if ErrorCode = SOCKET_ERROR then
      WriteLog(Format('Error sending %d response', [StatusCode]));
  end;

    function IsIPAllowed: Boolean;
  begin
    Result := True;

    // Check blocked IPs
    if GlobalIPMonitor.IsIPBlocked(ClientInfo.IP) then
    begin
      WriteLog(Format('Task: Blocked connection from IP %s', [ClientInfo.IP]));
      SendErrorResponse(429, 'Too Many Requests', 'Retry-After: 600');
      Result := False;
      Exit;
    end;

    // Check rate limits
    if not GlobalIPMonitor.RegisterRequest(ClientInfo.IP) then
    begin
      WriteLog(Format('Task: Rate limit exceeded for IP %s', [ClientInfo.IP]));
      SendErrorResponse(429, 'Too Many Requests', 'Retry-After: 60');
      Result := False;
    end;
  end;

  function ProcessContentLengthHeader(const HeaderLine: string; const RequestStr: string): Boolean;
  begin
    Result := False;

    if not HeaderLine.StartsWith('Content-Length:', True) then
      Exit;

    ClientInfo.HasContentLength := True;
    Result := True;

    // Extract and validate Content-Length value
    var ValueStr := HeaderLine.Substring(15).Trim;
    if ValueStr.IsEmpty then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format('Task: Empty Content-Length from IP %s', [ClientInfo.IP]));
      SendErrorResponse(400, 'Invalid Content-Length value');
      Exit;
    end;

    if not TryStrToInt(ValueStr, ClientInfo.ContentLength) then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format('Task: Invalid Content-Length from IP %s: "%s"', [ClientInfo.IP, ValueStr]));
      SendErrorResponse(400, 'Invalid Content-Length value');
      Exit;
    end;

    if ClientInfo.ContentLength < 0 then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format('Task: Negative Content-Length from IP %s: %d', [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(400, 'Negative Content-Length value');
      Exit;
    end;

    if ClientInfo.ContentLength > FMaxPostSize then
    begin
      WriteLog(Format('Task: Content-Length too large from IP %s: %d', [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(413, 'Payload Too Large');
      Exit;
    end;
  end;

  function ValidateUserAgent(const RequestStr: string): Boolean;
  var
    UserAgent: string;
  begin
    Result := True;
    UserAgent := ExtractUserAgent(RequestStr);

    if IsSuspiciousUserAgent(UserAgent) then
    begin
      WriteLog(Format('Task: Suspicious User-Agent detected from IP %s: %s', [ClientInfo.IP, UserAgent]));
      GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
      SendErrorResponse(403, 'Forbidden');
      Result := False;
    end;
  end;


  // Error handling procedures
  procedure HandleRequestTimeout(const RequestStr: string);
  begin
    WriteLog(Format('Task: Timeout for IP %s (%.1f seconds)',
            [ClientInfo.IP, (Now - ClientInfo.StartTime) * 86400]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    SendErrorResponse(408, 'Request Timeout');
  end;

  procedure HandleIncompletePostData(const RequestStr: string);
  begin
    WriteLog(Format('Task: Incomplete POST data from IP %s. Expected: %d, Got: %d',
            [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
    SendErrorResponse(400, 'Incomplete request body');
  end;

  procedure HandleSocketError(const RequestStr: string; ErrorCode: Integer);
  begin
    WriteLog(Format('Task: Receive failed for IP %s, error %d - %s',
            [ClientInfo.IP, ErrorCode, SocketErrorToString(ErrorCode)]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);

    if (ClientInfo.HeaderEndPos > 0) and RequestStr.StartsWith('POST ') and
       ClientInfo.HasContentLength and (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
    begin
      WriteLog(Format('Task: Connection error while receiving POST data from IP %s. Expected: %d, Got: %d',
              [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
      SendErrorResponse(400, 'Incomplete request body');
    end;
  end;

  procedure HandleClientClosedConnection(const RequestStr: string);
  begin
    WriteLog(Format('Task: Client closed connection from IP %s', [ClientInfo.IP]));
    ClientInfo.ConnectionClosed := True;

    if (ClientInfo.HeaderEndPos > 0) and RequestStr.StartsWith('POST ') and
       ClientInfo.HasContentLength and (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
    begin
      WriteLog(Format('Task: Incomplete POST data from IP %s. Expected: %d, Got: %d',
              [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
      SendErrorResponse(400, 'Incomplete request body');
    end;
  end;

  procedure HandleHeaderSizeLimitExceeded(const RequestStr: string);
  begin
    WriteLog(Format('Task: Header size limit exceeded for IP %s', [ClientInfo.IP]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    SendErrorResponse(431, 'Request Header Fields Too Large');
  end;

  // Procedure for reading and processing data from a socket
  function ReadSocketData(var RequestStr: string): Boolean;
  var
    Buffer: array[0..BUFFER_SIZE] of Byte;
    TempBytes: TBytes;
    BytesReceived, ErrorCode: Integer;
  begin
    Result := False;

    // Odczytanie danych z gniazda
    BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);

    // Reading data from the socket
    if BytesReceived = SOCKET_ERROR then
    begin
      ErrorCode := WSAGetLastError;
      if ErrorCode = WSAEWOULDBLOCK then
      begin
        Sleep(10);
        Result := True;
        Exit;
      end;
      HandleSocketError(RequestStr, ErrorCode);
      Exit;
    end;

    // Handling connection closure
    if BytesReceived = 0 then
    begin
      HandleClientClosedConnection(RequestStr);
      if ClientInfo.ConnectionClosed then
        Exit;
      Result := False;
      Exit;
    end;

    // Updating the received byte counter
    ClientInfo.TotalBytesReceived := ClientInfo.TotalBytesReceived + BytesReceived;

    // Adding the received data to the Request
    SetLength(TempBytes, BytesReceived);
    Move(Buffer[0], TempBytes[0], BytesReceived);
    Request := AppendBytes(Request, TempBytes);


    RequestStr := TEncoding.ASCII.GetString(Request);

    // Resetting the TimeOut counter
    ClientInfo.StartTime := Now;

    Result := True;
  end;

  function ReceiveHttpRequest: Boolean;
  var
    Buffer: array[0..BUFFER_SIZE] of Byte;
    TempBytes: TBytes;
    BytesReceived, ErrorCode: Integer;
    RequestStr: string;
    HeaderEndPos: Integer;
    RequestHeaders: TStringList;
    HeadersText, Line: string;
    i: Integer;
    ConsecutiveEmptyReads: Integer;
  begin
    Result := False;
    SetLength(Request, 0);
    ClientInfo.TotalBytesReceived := 0;
    ClientInfo.StartTime := Now;
    ClientInfo.HeaderEndPos := 0;
    ConsecutiveEmptyReads := 0;
    RequestStr := '';
    while True do
    begin
      if (Now - ClientInfo.StartTime) > ClientInfo.TimeoutValue then
      begin
        HandleRequestTimeout(RequestStr);
        Exit;
      end;
      if not WaitForSocketReady(ClientSocket, True, 100) then
      begin
        Inc(ConsecutiveEmptyReads);
        if (ClientInfo.HeaderEndPos > 0) and (ConsecutiveEmptyReads > 10) then
        begin
          if RequestStr.StartsWith('POST ') and ClientInfo.HasContentLength and
             (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
          begin
            HandleIncompletePostData(RequestStr);
            Exit;
          end;
        end;
        Continue;
      end;
      ConsecutiveEmptyReads := 0;
      /////////////////////////////////////////////////////////////////
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
      /////////////////////////////////////////////////////////////////
      if BytesReceived = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        if ErrorCode = WSAEWOULDBLOCK then
        begin
          Sleep(10);
          Continue;
        end;
        HandleSocketError(RequestStr, ErrorCode);
        Exit;
      end;
      if BytesReceived = 0 then
      begin
        HandleClientClosedConnection(RequestStr);
        if ClientInfo.ConnectionClosed then
          Exit;
        Break;
      end;

      ClientInfo.TotalBytesReceived := ClientInfo.TotalBytesReceived + BytesReceived;
      SetLength(TempBytes, BytesReceived);
      Move(Buffer[0], TempBytes[0], BytesReceived);
      Request := AppendBytes(Request, TempBytes);
      RequestStr := TEncoding.ASCII.GetString(Request);
      ClientInfo.StartTime := Now;

      // Parse headers once we have them completely
      if ClientInfo.HeaderEndPos = 0 then
      begin
        ClientInfo.HeaderEndPos := Pos(#13#10#13#10, RequestStr);
        if ClientInfo.HeaderEndPos > 0 then
        begin
          ClientInfo.IsHTTP10 := Pos('HTTP/1.0', RequestStr) > 0;
          RequestHeaders := TStringList.Create;
          try
            HeadersText := Copy(RequestStr, 1, ClientInfo.HeaderEndPos);
            RequestHeaders.Text := HeadersText;
            ClientInfo.HasContentLength := False;
            ClientInfo.ContentLengthValid := True;
            for i := 0 to RequestHeaders.Count - 1 do
            begin
              Line := RequestHeaders[i];
              if ProcessContentLengthHeader(Line, RequestStr) then
                Break;
            end;
          finally
            RequestHeaders.Free;
          end;
        end;
      end;
      // Process complete request
      if ClientInfo.HeaderEndPos > 0 then
      begin
        ClientInfo.PostDataReceived := Length(RequestStr) - ClientInfo.HeaderEndPos - 3;
        if RequestStr.StartsWith('POST ') then
        begin
          if ClientInfo.HasContentLength and ClientInfo.ContentLengthValid then
          begin
            if ClientInfo.PostDataReceived >= ClientInfo.ContentLength then
            begin
              WriteLog(Format('Task: Complete POST request received for IP %s (%d bytes)',
                      [ClientInfo.IP, ClientInfo.TotalBytesReceived]));
              if not ValidateUserAgent(RequestStr) then
                Exit;
              Result := True;
              Break;
            end;
          end;
        end
        else // Non-POST request
        begin
          if not ValidateUserAgent(RequestStr) then
            Exit;
          Result := True;
          Break;
        end;
      end
      else if ClientInfo.TotalBytesReceived > FMaxHeaderSize then
      begin
        HandleHeaderSizeLimitExceeded(RequestStr);
        Exit;
      end;
    end;
  end;

  function GenerateResponse: Boolean;
  var
    TextResponseBytes: TBytes;
    Sent, ErrorCode: Integer;
  begin
    Result := False;

    try
      if CreateResponseNew(Request, ClientSocket, TextResponseBytes, ClientInfo.IP) then
      begin
        Result := True;
        Exit;
      end;

      Response := TextResponseBytes;
    except
      on E: Exception do
      begin
        WriteLog(Format('Task: Error creating response for IP %s: %s', [ClientInfo.IP, E.Message]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
        SendErrorResponse(500, 'Internal Server Error');
        Exit;
      end;
    end;

    if Length(Response) > 0 then
    begin
      Sent := send(ClientSocket, Response[0], Length(Response), 0);
      if Sent = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        WriteLog(Format('Task: Send failed for IP %s, error %d - %s',
                 [ClientInfo.IP, ErrorCode, SocketErrorToString(ErrorCode)]));
      end
      else
      begin
        WriteLog(Format('Task: Response sent for IP %s (%d bytes)', [ClientInfo.IP, Sent]));
        Result := True;
      end;
    end;
  end;

begin
  try
    ClientInfo.IP := '';
    ClientInfo.StartTime := Now;
    ClientInfo.ContentLength := 0;
    ClientInfo.ContentLengthValid := True;
    ClientInfo.HasContentLength := False;
    ClientInfo.PostDataReceived := 0;
    ClientInfo.ConnectionClosed := False;
    ClientInfo.IsHTTP10 := False;
    ClientInfo.TimeoutValue := FMaxRequestTime;

    GetClientIP;
    if not IsIPAllowed then
      Exit;

    if not ReceiveHttpRequest then
      Exit;

    GenerateResponse;
  except
    on E: Exception do
    begin
      WriteLog(Format('Task: Exception for IP %s: %s', [ClientInfo.IP, E.Message]));
      try
        SendErrorResponse(500, 'Internal Server Error');
      except
        on E: Exception do
          WriteLog('Error while sending error response');
      end;

      if ClientInfo.IP <> '' then
        GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    end;
  end;
end;


function TGHTTPServer.CreateResponseNew(const Request: TBytes; ClientSocket: TSocket;
  out Response: TBytes; AClientIP: String): Boolean;
var
  RequestParser: THTTPRequestParser;
  ResponseBuilder: THTTPResponseBuilder;
  PathParams: TDictionary<string, string>;
  FileStream: TFileStream;
  UploadedFileObj: THTTPUploadedFile;
begin
  Result := False;
  RequestParser := THTTPRequestParser.Create(Request);
  ResponseBuilder := THTTPResponseBuilder.Create;
  try
    if not RequestParser.IsValid then
    begin
      Response := THTTPResponseBuilder.CreateBadRequestResponse.ToBytes;
      Exit;
    end;


    var EndpointItem: TEndpointItem := FEndpoints.FindEndpoint(RequestParser.Path, RequestParser.Method);
    if Assigned(EndpointItem) and (Assigned(EndpointItem.OnRequest) or Assigned(EndpointItem.OnRequestProc)) then
    begin
      try
        if Assigned(EndpointItem.OnRequest) then
          EndpointItem.OnRequest(EndpointItem,RequestParser,
                      ResponseBuilder,Self)
        else if Assigned(EndpointItem.OnRequestProc) then
          EndpointItem.OnRequestProc(EndpointItem,RequestParser,
                      ResponseBuilder,Self);
      except
        on E: Exception do
        begin
          WriteLog(Format('Error in endpoint handler %s: %s', [RequestParser.Path, E.Message]));
          ResponseBuilder.SetStatus(500, 'Method Not Allowed');
          ResponseBuilder.AddTextContent('error', 'text/plain', '500 Internal Server Error');
        end;
      end;
    end
    else
    begin
      ResponseBuilder.SetStatus(404, '404 Not Found');
      ResponseBuilder.AddTextContent('error', 'text/plain', '404 Not Found');
    end;

    ResponseBuilder.AddHeader('Server', 'WebServer');

    ResponseBuilder.AddHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    ResponseBuilder.AddHeader('X-Content-Type-Options', 'nosniff');
    ResponseBuilder.AddHeader('X-Frame-Options', 'SAMEORIGIN');

    ResponseBuilder.AddHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    ResponseBuilder.AddHeader('Pragma', 'no-cache');
    ResponseBuilder.AddHeader('Expires', '0');

    Response := ResponseBuilder.ToBytes;
    Result := false;
  finally
    RequestParser.Free;
    ResponseBuilder.Free;
  end;
end;

function TGHTTPServer.ExtractUserAgent(const Request: string): string;
var
 Lines: TStringList;
 Line: string;
 I: Integer;
begin
 Result := '';
 Lines := TStringList.Create;
 try
   Lines.Text := Request;

   for I := 0 to Lines.Count - 1 do
   begin
     Line := Trim(Lines[I]);
     if Pos('User-Agent:', Line) = 1 then
     begin
       Result := Trim(Copy(Line, Length('User-Agent:') + 1, MaxInt));
       Break;
     end;
   end;
 finally
   Lines.Free;
 end;
end;

function TGHTTPServer.IsSuspiciousUserAgent(const UserAgent: string): Boolean;
begin
 Result := False;

 if (UserAgent = '') or (Length(UserAgent) < 5) then
 begin
   Result := True;
   Exit;
 end;

 if Pos('MSIE 6.0', UserAgent) > 0 then
 begin
   Result := True;
   Exit;
 end;

 if (Pos('sqlmap', LowerCase(UserAgent)) > 0) or
    (Pos('fuzz', LowerCase(UserAgent)) > 0) or
    (Pos('<script>', LowerCase(UserAgent)) > 0) or
    (Pos('SELECT', UpperCase(UserAgent)) > 0) then
 begin
   Result := True;
   Exit;
 end;

 if Length(UserAgent) > 512 then
 begin
   Result := True;
   Exit;
 end;
end;

function TGHTTPServer.GetMimeType(const FileName: string): string;
var
 Ext: string;
begin
 Ext := LowerCase(ExtractFileExt(FileName));
 if (Ext <> '') and (Ext[1] = '.') then
   Ext := Copy(Ext, 2, MaxInt);

 Result := FMimeTypes.Values[Ext];
 if Result = '' then
   Result := 'application/octet-stream';
end;

procedure TGHTTPServer.InitializeMimeTypes;
begin
 FMimeTypes.CaseSensitive := False;
 FMimeTypes.Add('txt=text/plain');
 FMimeTypes.Add('html=text/html');
 FMimeTypes.Add('htm=text/html');
 FMimeTypes.Add('css=text/css');
 FMimeTypes.Add('js=application/javascript');
 FMimeTypes.Add('json=application/json');
 FMimeTypes.Add('jpg=image/jpeg');
 FMimeTypes.Add('jpeg=image/jpeg');
 FMimeTypes.Add('png=image/png');
 FMimeTypes.Add('gif=image/gif');
 FMimeTypes.Add('svg=image/svg+xml');
 FMimeTypes.Add('pdf=application/pdf');
 FMimeTypes.Add('zip=application/zip');
 FMimeTypes.Add('exe=application/octet-stream');
 FMimeTypes.Add('bin=application/octet-stream');
 FMimeTypes.Add('mp4=video/mp4');
 FMimeTypes.Add('mp3=audio/mpeg');
 FMimeTypes.Add('xml=application/xml');
 FMimeTypes.Add('docx=application/vnd.openxmlformats-officedocument.wordprocessingml.document');
 FMimeTypes.Add('xlsx=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
 FMimeTypes.Add('ico=image/x-icon');
end;

function TGHTTPServer.GetMimeTypeFromFileExt(FileExt: string): string;
begin
  if FileExt = '.pdf' then
    Result := 'application/pdf'
  else if FileExt = '.zip' then
    Result := 'application/zip'
  else if FileExt = '.docx' then
    Result := 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  else if FileExt = '.xlsx' then
    Result := 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  else if FileExt = '.pptx' then
    Result := 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  else if (FileExt = '.jpg') or (FileExt = '.jpeg') then
    Result := 'image/jpeg'
  else if FileExt = '.png' then
    Result := 'image/png'
  else if FileExt = '.gif' then
    Result := 'image/gif'
  else if FileExt = '.txt' then
    Result := 'text/plain'
  else if (FileExt = '.html') or (FileExt = '.htm') then
    Result := 'text/html'
  else if FileExt = '.css' then
    Result := 'text/css'
  else if FileExt = '.js' then
    Result := 'application/javascript'
  else if FileExt = '.json' then
    Result := 'application/json'
  else if FileExt = '.xml' then
    Result := 'application/xml'
  else if FileExt = '.mp3' then
    Result := 'audio/mpeg'
  else if FileExt = '.mp4' then
    Result := 'video/mp4'
  else
    Result := 'application/octet-stream';
end;

end.
