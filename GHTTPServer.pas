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
  HttpServerUtils, HTTPResponseBuilder, HTTPRequest, System.JSON, System.NetEncoding,
  System.DateUtils, System.Hash;

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

  // JWT Authorization types
  TAuthorizationType = (atNone, atJWTBearer);

  // JWT Token Structure
  TJWTToken = record
    Header: string;
    Payload: string;
    Signature: string;
    Raw: string;
    Decoded: TJSONObject;
    ExpirationTime: TDateTime;
    IsValid: Boolean;
    Subject: string;
    Issuer: string;
    function GetClaim(const Name: string): string;
  end;

  // JWT Authentication Manager
  TJWTManager = class
  private
    FSecretKey: string;
    FIssuer: string;
    FTokenExpiration: Integer; // in minutes
  public
    constructor Create(const ASecretKey, AIssuer: string; ATokenExpiration: Integer = 60);
    function ValidateToken(const Token: string; out JWT: TJWTToken): Boolean;
    function CreateToken(const Subject: string; const CustomClaims: TJSONObject = nil): string;
    function ExtractTokenFromAuthHeader(const AuthHeader: string): string;
    property SecretKey: string read FSecretKey write FSecretKey;
    property Issuer: string read FIssuer write FIssuer;
    property TokenExpiration: Integer read FTokenExpiration write FTokenExpiration;
  end;

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
    FAuthorizationType: TAuthorizationType;
    FRoles: TStringList;
    procedure SetEndpoint(const Value: string);
    procedure SetMethod(const Value: string);
  protected
    function GetDisplayName: string; override;
  public
    constructor Create(Collection: TCollection); override;
    destructor Destroy; override;
  published
    property Endpoint: string read FEndpoint write SetEndpoint;
    property Method: string read FMethod write SetMethod;
    property OnRequest: TEndpointEvent read FOnRequest write FOnRequest;
    property OnRequestProc: TEndpointEventProc read FOnRequestProc write FOnRequestProc;
    property AuthorizationType: TAuthorizationType read FAuthorizationType write FAuthorizationType default atNone;
    property Roles: TStringList read FRoles;
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
    FJWTManager: TJWTManager;

    procedure SetServerSocket(const Value: TSocket);
    procedure SetMaxWorkerThreads(const Value: Integer);
    procedure SetMinWorkerThreads(const Value: Integer);
    procedure SetBaseDirectory(const Value: string);
    procedure SetTmpBaseDirectory(const Value: string);
    procedure SetEndpoints(const Value: TEndpointCollection);
  protected
    procedure ProcessClientRequestNew(ClientSocket: TSocket); virtual;
    function GetClientIP(ClientSocket: TSocket): string; virtual;
    procedure DoHandleClient(ClientSocket: TSocket); virtual;
    function ExtractUserAgent(const Request: TBytes): string; virtual;
    function IsSuspiciousUserAgent(const UserAgent: string): Boolean; virtual;
    function WaitForSocketReady(Socket: TSocket; ForReading: Boolean; TimeoutMs: Integer): Boolean; virtual;
    procedure InitializeMimeTypes; virtual;
    function CreateResponseNew(const Request: TBytes; ClientSocket: TSocket;
                  out Response: TBytes; AClientIP:String): Boolean; virtual;
    function SocketErrorToString(ErrorCode: Integer): string;
    procedure SendErrorResponse(ClientSocket: TSocket; StatusCode: Integer; Message: string; ExtraHeaders: string = ''); virtual;
  public
    constructor Create(AOwner: TComponent; Port: Integer; MaxConnections: Integer = 100; AHttpLogger: THttpLogger = nil);reintroduce; virtual;
    destructor Destroy; override;
    function GetMimeType(const FileName: string): string; virtual;
    function AcceptConnection(var ClientAddr: TSockAddrIn): TSocket; virtual;
    procedure SetSocketNonBlocking(Socket: TSocket); virtual;
    procedure InitializeSocketLibrary; virtual;
    procedure FinalizeSocketLibrary; virtual;
    procedure IncrementConnections; virtual;
    procedure DecrementConnections; virtual;
    procedure WriteLog(log: string); virtual;
    procedure HandleClient(ClientSocket: TSocket); virtual;
    function ExtractBoundary(const ContentType: string): string; virtual;
    procedure Start; virtual;
    procedure Stop; virtual;
    function GetActiveConnections: Integer; virtual;
    function AddEndpoint(const AEndpoint, AMethod: string;
                                      const AHandler: TEndpointEvent;
                                      const AAuthorizationType: TAuthorizationType;
                                      const ARoles: array of string): TEndpointItem; virtual;
    function AddEndpointProc(const AEndpoint, AMethod: string;
                                      const AHandler: TEndpointEventProc;
                                      const AAuthorizationType: TAuthorizationType;
                                      const ARoles: array of string): TEndpointItem; virtual;
    procedure ConfigureJWT(const ASecretKey, AIssuer: string; AExpirationMinutes: Integer);
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
    property JWTManager: TJWTManager read FJWTManager;
  end;

  // Helper functions
  function FindBytes(const Haystack, Needle: TBytes; StartPos: Integer = 0): Integer;
  function FindHeaderEnd(const Data: TBytes; StartPos, EndPos: Integer): Integer;
  function AppendBytes(const Source: TBytes; Buffer: Pointer; BytesCount: Integer): TBytes;
  function BytesStartWith(const Bytes, Pattern: TBytes): Boolean;
  function BytesContains(const Bytes, Pattern: TBytes): Boolean;


implementation

uses
  System.IOUtils, System.Generics.Collections,
  GHTTPConstants;

function BytesStartWith(const Bytes, Pattern: TBytes): Boolean;
var
  i: Integer;
begin
  Result := False;
  if Length(Pattern) > Length(Bytes) then
    Exit;

  Result := True;
  for i := 0 to Length(Pattern) - 1 do
    if Bytes[i] <> Pattern[i] then
    begin
      Result := False;
      Break;
    end;
end;

function BytesContains(const Bytes, Pattern: TBytes): Boolean;
begin
  Result := BytesPos(Bytes, Pattern) > 0;
end;


function FindBytes(const Haystack, Needle: TBytes; StartPos: Integer = 0): Integer;
var
  SkipTable: array[0..255] of Integer;
  i, j, NeedleLen, HaystackLen: Integer;
begin
  Result := -1;
  HaystackLen := Length(Haystack);
  NeedleLen := Length(Needle);

  if (NeedleLen = 0) or (HaystackLen = 0) or
     (StartPos + NeedleLen > HaystackLen) then
    Exit;

  for i := 0 to 255 do
    SkipTable[i] := NeedleLen;

  for i := 0 to NeedleLen - 2 do
    SkipTable[Needle[i]] := NeedleLen - 1 - i;
  i := StartPos;
  while i <= HaystackLen - NeedleLen do
  begin
    j := NeedleLen - 1;

    while (j >= 0) and (Haystack[i + j] = Needle[j]) do
      Dec(j);

    if j < 0 then
    begin
      Result := i;
      Exit;
    end;

    Inc(i, SkipTable[Haystack[i + NeedleLen - 1]]);
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

function AppendBytes(const Source: TBytes; Buffer: Pointer; BytesCount: Integer): TBytes;
var
  SourceLen, NewSize: Integer;
begin
  SourceLen := Length(Source);
  NewSize := SourceLen + BytesCount;
  SetLength(Result, NewSize);
  if SourceLen > 0 then
    Move(Source[0], Result[0], SourceLen);
  if BytesCount > 0 then
    Move(Buffer^, Result[SourceLen], BytesCount);
end;

{ TJWTToken }
function TJWTToken.GetClaim(const Name: string): string;
var
  Value: TJSONValue;
begin
  Result := '';
  if Assigned(Decoded) then
  begin
    Value := Decoded.FindValue(Name);
    if Assigned(Value) then
      Result := Value.Value;
  end;
end;

{ TJWTManager }
constructor TJWTManager.Create(const ASecretKey, AIssuer: string; ATokenExpiration: Integer);
begin
  inherited Create;
  FSecretKey := ASecretKey;
  FIssuer := AIssuer;
  FTokenExpiration := ATokenExpiration;
end;

function TJWTManager.ExtractTokenFromAuthHeader(const AuthHeader: string): string;
begin
  Result := '';
  if StartsText('Bearer ', AuthHeader) then
    Result := Trim(Copy(AuthHeader, 8, MaxInt));
end;

function TJWTManager.ValidateToken(const Token: string; out JWT: TJWTToken): Boolean;
var
  TokenParts: TArray<string>;
  HeaderStr, PayloadStr, SignatureStr: string;
  ExpectedSignature: string;
  PayloadObj: TJSONObject;
  ExpClaim, IssuerClaim, SubjectClaim: TJSONValue;
  ExpTime: Int64;
  IssuerValue, SubjectValue: string;
  PayloadBytes: TBytes;
  JsonStr: string;
begin
  Result := False;
  JWT.IsValid := False;
  JWT.Raw := Token;
  JWT.Decoded := nil;
  TokenParts := Token.Split(['.']);
  if Length(TokenParts) <> 3 then
    Exit;
  HeaderStr := TokenParts[0];
  PayloadStr := TokenParts[1];
  SignatureStr := TokenParts[2];
  try
    ExpectedSignature := TNetEncoding.Base64Url.EncodeBytesToString(
      THashSHA2.GetHashBytes(HeaderStr + '.' + PayloadStr + FSecretKey, THashSHA2.TSHA2Version.SHA256));
  except
    Exit;
  end;
  if ExpectedSignature <> SignatureStr then
    Exit;
  JWT.Signature := SignatureStr;
  try
    JWT.Header := HeaderStr;
    JWT.Payload := PayloadStr;
    PayloadBytes := TNetEncoding.Base64Url.DecodeStringToBytes(PayloadStr);
    JsonStr := '';
    try
      JsonStr := TEncoding.UTF8.GetString(PayloadBytes);
    except
      on E: EEncodingError do
      begin
        JsonStr := TEncoding.ANSI.GetString(PayloadBytes);
      end;
    end;
  except
    on E: Exception do
    begin
      Exit;
    end;
  end;

  PayloadObj := nil;
  try
    try
      PayloadObj := TJSONObject.ParseJSONValue(JsonStr) as TJSONObject;
      if not Assigned(PayloadObj) then
        Exit;
      ExpClaim := PayloadObj.FindValue('exp');
      if Assigned(ExpClaim) and ExpClaim.TryGetValue<Int64>(ExpTime) then
      begin
        JWT.ExpirationTime := UnixToDateTime(ExpTime);
        if Now > JWT.ExpirationTime then
          Exit;
      end;
      IssuerValue := '';
      SubjectValue := '';
      IssuerClaim := PayloadObj.FindValue('iss');
      if Assigned(IssuerClaim) then
        IssuerValue := IssuerClaim.Value;
      SubjectClaim := PayloadObj.FindValue('sub');
      if Assigned(SubjectClaim) then
        SubjectValue := SubjectClaim.Value;
      if (FIssuer <> '') and (IssuerValue <> FIssuer) then
        Exit;
      JWT.Decoded := PayloadObj;
      JWT.Subject := SubjectValue;
      JWT.Issuer := IssuerValue;
      JWT.IsValid := True;
      Result := True;
      if Result then
        PayloadObj := nil;
    except
      on E: Exception do
      begin
        Result := False;
      end;
    end;
  finally
    if Assigned(PayloadObj) then
      FreeAndNil(PayloadObj);
  end;
end;

function TJWTManager.CreateToken(const Subject: string; const CustomClaims: TJSONObject): string;
var
  Header, Payload: TJSONObject;
  HeaderBase64, PayloadBase64, Signature: string;
begin
  Header := TJSONObject.Create;
  Payload := TJSONObject.Create;
  try
    Header.AddPair('alg', 'HS256');
    Header.AddPair('typ', 'JWT');
    Payload.AddPair('sub', Subject);
    Payload.AddPair('iss', FIssuer);
    Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(Now)));
    Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(Now, FTokenExpiration))));
    if Assigned(CustomClaims) then
    begin
      for var Pair in CustomClaims do
        Payload.AddPair(Pair.JsonString.Value, Pair.JsonValue.Clone as TJSONValue);
    end;
    HeaderBase64 := TNetEncoding.Base64Url.Encode(Header.ToString);
    PayloadBase64 := TNetEncoding.Base64Url.Encode(Payload.ToString);
    Signature := TNetEncoding.Base64Url.EncodeBytesToString(
      THashSHA2.GetHashBytes(HeaderBase64 + '.' + PayloadBase64 + FSecretKey, THashSHA2.TSHA2Version.SHA256));
    Result := HeaderBase64 + '.' + PayloadBase64 + '.' + Signature;
  finally
    Header.Free;
    Payload.Free;
  end;
end;

{ TEndpointItem }
constructor TEndpointItem.Create(Collection: TCollection);
begin
  inherited Create(Collection);
  FEndpoint := ENDPOINT_DEFAULT;
  FMethod := HTTP_METHOD_GET;
  FOnRequest := nil;
  FOnRequestProc := nil;
  FAuthorizationType := atNone;
  FRoles := TStringList.Create;
  FRoles.Sorted := True;
  FRoles.Duplicates := dupIgnore;
end;

destructor TEndpointItem.Destroy;
begin
  FRoles.Free;
  inherited;
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

  FJWTManager := TJWTManager.Create('DefaultSecretKey', 'GHTTPServer', 60);

  FMaxWorkerThreads := 100;
  FMinWorkerThreads := 10;
  FMaxHeaderSize := 8192;
  FMaxRequestTime := 30 / (24 * 3600); // 30 seconds for headers
  FFileTransferTimeout := 300 / (24 * 3600); // 5 minutes for file transfers
  FMaxPostSize := 100 * 1024 * 1024; // 100 MB
  FBufferSize := 65536; // 64KB chunks
  FSendTimeout := 10000; // 10 seconds

  FThreadPool.SetMaxWorkerThreads(FMaxWorkerThreads);
  FThreadPool.SetMinWorkerThreads(FMinWorkerThreads);

  FBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_FILES_DIR);
  FTmpBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_TMP_DIR);

  if not TDirectory.Exists(FBaseDirectory) then
  begin
    if not ForceDirectories(FBaseDirectory) then
      raise Exception.Create(ERROR_DIRECTORY_CREATE_FAILED + FBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FBaseDirectory);

  if not TDirectory.Exists(FTmpBaseDirectory) then
  begin
    if not ForceDirectories(FTmpBaseDirectory) then
      raise Exception.Create(ERROR_DIRECTORY_CREATE_FAILED + FTmpBaseDirectory);
  end;

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
  FJWTManager.Free;
  GlobalIPMonitor.Free;
  FEndpoints.Free;
  inherited;
end;

procedure TGHTTPServer.SetServerSocket(const Value: TSocket);
begin
  FServerSocket := Value;
end;

procedure TGHTTPServer.SetBaseDirectory(const Value: string);
begin
  FBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_FILES_DIR);

  if not TDirectory.Exists(FBaseDirectory) then
  begin
    if not ForceDirectories(FBaseDirectory) then
      raise Exception.Create(ERROR_DIRECTORY_CREATE_FAILED + FBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FBaseDirectory);

  WriteLog(Format(MSG_BASE_DIRECTORY_SET, [FBaseDirectory]));
end;

procedure TGHTTPServer.SetTmpBaseDirectory(const Value: string);
begin
  FTmpBaseDirectory := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_FILES_DIR);

  if not TDirectory.Exists(FTmpBaseDirectory) then
  begin
    if not ForceDirectories(FTmpBaseDirectory) then
      raise Exception.Create(ERROR_DIRECTORY_CREATE_FAILED + FTmpBaseDirectory);
  end;

  FBaseDirectory := IncludeTrailingPathDelimiter(FTmpBaseDirectory);

  WriteLog(Format(MSG_BASE_DIRECTORY_SET, [FTmpBaseDirectory]));
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
    raise Exception.Create(ERROR_WSA_STARTUP);
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

function TGHTTPServer.GetClientIP(ClientSocket: TSocket): string;
var
  SockAddr: TSockAddr;
  AddrLen: Integer;
  IPAddrStr: PAnsiChar;
begin
  AddrLen := SizeOf(SockAddr);
  Result := IP_ANY_ADDRESS;

  if getpeername(ClientSocket, SockAddr, AddrLen) = 0 then
  begin
    if SockAddr.sa_family = AF_INET then
    begin
      IPAddrStr := inet_ntoa(PSockAddrIn(@SockAddr)^.sin_addr);
      Result := string(IPAddrStr);
    end
    else
    begin
      Result := IP_VALUE_UNKNOWN;
    end;
  end;

  WriteLog(Format(LOG_CONNECTION_FROM_IP, [Result]));
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
    raise Exception.Create(ERROR_SOCKET_CREATION);

  OptVal := 1;
  setsockopt(FServerSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

  ServerAddr.sin_family := AF_INET;
  ServerAddr.sin_addr.s_addr := INADDR_ANY;
  ServerAddr.sin_port := htons(FPort);

  if bind(FServerSocket, ServerAddr, SizeOf(ServerAddr)) = SOCKET_ERROR then
    raise Exception.Create(ERROR_BIND_FAILED);

  if listen(FServerSocket, SOMAXCONN) = SOCKET_ERROR then
    raise Exception.Create(ERROR_LISTEN_FAILED);

  FListening := True;
  WriteLog(Format(LOG_SERVER_STARTED, [FPort]));

  while FListening do
  begin
    var ClientSocket := AcceptConnection(ClientAddr);
    if ClientSocket = INVALID_SOCKET then
      Continue;

    SetSocketNonBlocking(ClientSocket);

    if GetActiveConnections >= FMaxConnections then
    begin
      WriteLog(LOG_TOO_MANY_CONNECTIONS);
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
  DoHandleClient(ClientSocket);
end;

procedure TGHTTPServer.DoHandleClient(ClientSocket: TSocket);
begin
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
  WriteLog(LOG_SERVER_STOPPED);
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
  BoundaryPos := Pos(HEADER_BOUNDARY_PREFIX, ContentType);
  if BoundaryPos > 0 then
  begin
    Result := Copy(ContentType, BoundaryPos + 9, MaxInt);
    if (Result <> '') and (Result[1] = '"') then
      Result := Copy(Result, 2, Length(Result) - 2);
  end;
end;


function TGHTTPServer.AddEndpoint(const AEndpoint, AMethod: string;
                                      const AHandler: TEndpointEvent;
                                      const AAuthorizationType: TAuthorizationType;
                                      const ARoles: array of string): TEndpointItem;
begin
 Result := FEndpoints.Add;
 Result.Endpoint := AEndpoint;
 Result.Method := AMethod;
 Result.OnRequest := AHandler;
 Result.AuthorizationType := AAuthorizationType;

 for var Role in ARoles do
    Result.Roles.Add(Role);
end;

function TGHTTPServer.AddEndpointProc(const AEndpoint, AMethod: string;
                                      const AHandler: TEndpointEventProc;
                                      const AAuthorizationType: TAuthorizationType;
                                      const ARoles: array of string): TEndpointItem;
begin
 Result := FEndpoints.Add;
 Result.Endpoint := AEndpoint;
 Result.Method := AMethod;
 Result.OnRequestProc := AHandler;
 Result.AuthorizationType := AAuthorizationType;

 for var Role in ARoles do
    Result.Roles.Add(Role);
end;

procedure TGHTTPServer.ConfigureJWT(const ASecretKey, AIssuer: string; AExpirationMinutes: Integer);
begin
  FJWTManager.SecretKey := ASecretKey;
  FJWTManager.Issuer := AIssuer;
  FJWTManager.TokenExpiration := AExpirationMinutes;
end;

procedure TGHTTPServer.SendErrorResponse(ClientSocket: TSocket; StatusCode: Integer; Message: string; ExtraHeaders: string = '');
var
  ResponseText: string;
  ResponseBytes: TBytes;
  ErrorCode: Integer;
begin
  ResponseText := Format(HTTP_RESPONSE_FORMAT,
                    [StatusCode, Message, Length(Message)]);

  if ExtraHeaders <> '' then
    ResponseText := ResponseText + ExtraHeaders + #13#10;

  ResponseText := ResponseText + #13#10 + Message;
  ResponseBytes := TEncoding.ASCII.GetBytes(ResponseText);

  ErrorCode := send(ClientSocket, ResponseBytes[0], Length(ResponseBytes), 0);
  if ErrorCode = SOCKET_ERROR then
     WriteLog(Format(LOG_ERROR_SENDING_RESPONSE, [StatusCode]));
end;


procedure TGHTTPServer.ProcessClientRequestNew(ClientSocket: TSocket);
const
  BUFFER_SIZE = 65535;
var
  Request: TBytes;
  Response: TBytes;
  ClientInfo: TClientInfo;

  function IsIPAllowed: Boolean;
  begin
    Result := True;

    if GlobalIPMonitor.IsIPBlocked(ClientInfo.IP) then
    begin
      WriteLog(Format(LOG_BLOCKED_CONNECTION , [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, 429, HTTP_MSG_TOO_MANY_REQUESTS, RETRY_AFTER_600);
      Result := False;
      Exit;
    end;

    if not GlobalIPMonitor.RegisterRequest(ClientInfo.IP) then
    begin
      WriteLog(Format(LOG_RATE_LIMIT_EXCEEDED , [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, 429, HTTP_MSG_TOO_MANY_REQUESTS, RETRY_AFTER_600);
      Result := False;
    end;
  end;

  function ProcessContentLengthHeader(const HeaderLine: string; const RequestStr: string): Boolean;
  begin
    Result := False;

    if not HeaderLine.StartsWith(CONTENT_LENGTH_HEADER, True) then
      Exit;

    ClientInfo.HasContentLength := True;
    Result := True;

    var ValueStr := HeaderLine.Substring(15).Trim;
    if ValueStr.IsEmpty then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_EMPTY_CONTENT_LENGTH, [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if not TryStrToInt(ValueStr, ClientInfo.ContentLength) then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_INVALID_CONTENT_LENGTH, [ClientInfo.IP, ValueStr]));
      SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if ClientInfo.ContentLength < 0 then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_NEGATIVE_CONTENT_LENGTH, [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if ClientInfo.ContentLength > FMaxPostSize then
    begin
      WriteLog(Format(LOG_CONTENT_LENGTH_LARGE, [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(ClientSocket, 413, HTTP_MSG_PAYLOAD_TOO_LARGE);
      Exit;
    end;
  end;

  function ValidateUserAgent(const Request: TBytes): Boolean;
  begin
    Result := True;
    var UserAgent := ExtractUserAgent(Request);

    if IsSuspiciousUserAgent(UserAgent) then
    begin
      WriteLog(Format(LOG_SUSPICIOUS_USER_AGENT, [ClientInfo.IP, UserAgent]));
      GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
      SendErrorResponse(ClientSocket, HTTP_STATUS_FORBIDDEN, HTTP_MSG_FORBIDDEN);
      Result := False;
    end;
  end;

  procedure HandleRequestTimeout(const Request: TBytes);
  begin
    WriteLog(Format(LOG_TIMEOUT, [ClientInfo.IP, (Now - ClientInfo.StartTime) * 86400]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    SendErrorResponse(ClientSocket, HTTP_STATUS_REQUEST_TIMEOUT, HTTP_MSG_REQUEST_TIMEOUT);
  end;

  procedure HandleIncompletePostData();
  begin
    WriteLog(Format(LOG_INCOMPLETE_POST, [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
    SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INCOMPLETE);
  end;


  procedure HandleSocketError(const Request: TBytes; ErrorCode: Integer);
  var
    HTTPPostBytes: TBytes;
  begin
    WriteLog(Format(LOG_RECEIVE_FAILED, [ClientInfo.IP, ErrorCode, SocketErrorToString(ErrorCode)]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);

    HTTPPostBytes := TEncoding.ASCII.GetBytes(HTTP_POST);

    if (ClientInfo.HeaderEndPos > 0) and BytesStartWith(Request, HTTPPostBytes) and
       ClientInfo.HasContentLength and (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
    begin
      WriteLog(Format(ERR_CONNECTION_ERROR, [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INCOMPLETE);
    end;
  end;

  procedure HandleClientClosedConnection(const Request: TBytes);
  var
    HTTPPostBytes: TBytes;
  begin
    WriteLog(Format(LOG_CLIENT_CLOSED, [ClientInfo.IP]));
    ClientInfo.ConnectionClosed := True;

    HTTPPostBytes := TEncoding.ASCII.GetBytes(HTTP_POST);

    if (ClientInfo.HeaderEndPos > 0) and BytesStartWith(Request, HTTPPostBytes) and
       ClientInfo.HasContentLength and (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
    begin
      WriteLog(Format(LOG_INCOMPLETE_POST, [ClientInfo.IP, ClientInfo.ContentLength, ClientInfo.PostDataReceived]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INCOMPLETE);
    end;
  end;

  procedure HandleHeaderSizeLimitExceeded(const Request: TBytes);
  begin
    WriteLog(Format(LOG_HEADER_SIZE_EXCEEDED, [ClientInfo.IP]));
    GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    SendErrorResponse(ClientSocket, HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE, HTTP_MSG_REQUEST_HEADER_FIELDS_TOO_LARGE);
  end;

  function ProcessTransferEncodingHeader(const HeaderLine: string;
                                const RequestStr: string): Boolean;
  begin
    Result := False;

    if not HeaderLine.StartsWith('Transfer-Encoding:', True) then
      Exit;

    Result := True;

    var ValueStr := HeaderLine.Substring(18).Trim.ToLower;
    if (ValueStr = 'chunked') or (Pos('chunked', ValueStr) > 0) then
    begin
      WriteLog(Format(LOG_CHUNKED_ENCODING_REJECTED, [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, 415, HTTP_MSG_UNSUPPORTED_MEDIA_TYPE,
             'This server does not support Transfer-Encoding: chunked');
      Exit;
    end;
  end;

  function ReceiveHttpRequest: Boolean;
  var
    Buffer: array[0..BUFFER_SIZE] of Byte;
    BytesReceived, ErrorCode: Integer;
    i, StartPos, EndPos, LineStartPos: Integer;
    ConsecutiveEmptyReads: Integer;
    HasChunkedEncoding: Boolean;
    HeaderEndBytes, CRLFBytes, HTTP10Bytes, HTTPPostBytes, TransferEncodingBytes, ContentLengthBytes, ChunkedBytes: TBytes;
    CurrentLine: TBytes;
    LineCount: Integer;
  begin
    Result := False;
    SetLength(Request, 0);
    ClientInfo.TotalBytesReceived := 0;
    ClientInfo.StartTime := Now;
    ClientInfo.HeaderEndPos := 0;
    ConsecutiveEmptyReads := 0;
    HasChunkedEncoding := False;

    HeaderEndBytes := TEncoding.ASCII.GetBytes(#13#10#13#10);
    CRLFBytes := TEncoding.ASCII.GetBytes(#13#10);
    HTTP10Bytes := TEncoding.ASCII.GetBytes(HTTP_VERSION_1_0);
    HTTPPostBytes := TEncoding.ASCII.GetBytes(HTTP_POST);
    TransferEncodingBytes := TEncoding.ASCII.GetBytes('Transfer-Encoding:');
    ContentLengthBytes := TEncoding.ASCII.GetBytes('Content-Length:');
    ChunkedBytes := TEncoding.ASCII.GetBytes('chunked');

    while True do
    begin
      if (Now - ClientInfo.StartTime) > ClientInfo.TimeoutValue then
      begin
        HandleRequestTimeout(Request);
        Exit;
      end;

      if not WaitForSocketReady(ClientSocket, True, 100) then
      begin
        Inc(ConsecutiveEmptyReads);
        if (ClientInfo.HeaderEndPos > 0) and (ConsecutiveEmptyReads > 10) then
        begin
          if BytesStartWith(Request, HTTPPostBytes) and
             ClientInfo.HasContentLength and
             (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
          begin
            HandleIncompletePostData();
            Exit;
          end;
        end;
        Continue;
      end;

      ConsecutiveEmptyReads := 0;
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);

      if BytesReceived = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        if ErrorCode = WSAEWOULDBLOCK then
        begin
          Sleep(10);
          Continue;
        end;
        HandleSocketError(Request, ErrorCode);
        Exit;
      end;

      if BytesReceived = 0 then
      begin
        HandleClientClosedConnection(Request);
        if ClientInfo.ConnectionClosed then
          Exit;
        Break;
      end;

      Inc(ClientInfo.TotalBytesReceived, BytesReceived);
      Request := AppendBytes(Request, @Buffer[0], BytesReceived);
      ClientInfo.StartTime := Now;

      if ClientInfo.HeaderEndPos = 0 then
      begin
        ClientInfo.HeaderEndPos := FindBytes(Request, HeaderEndBytes);
        if ClientInfo.HeaderEndPos > 0 then
        begin
          ClientInfo.IsHTTP10 := FindBytes(Request, HTTP10Bytes) > 0;
          ClientInfo.HasContentLength := False;
          ClientInfo.ContentLengthValid := True;
          LineStartPos := 0;
          LineCount := 0;

          while LineStartPos < ClientInfo.HeaderEndPos do
          begin
            EndPos := FindBytes(Request, CRLFBytes, LineStartPos);
            if EndPos < 0 then
              Break;

            SetLength(CurrentLine, EndPos - LineStartPos);
            if EndPos > LineStartPos then
              Move(Request[LineStartPos], CurrentLine[0], EndPos - LineStartPos);

            Inc(LineCount);
            if (FindBytes(CurrentLine, TransferEncodingBytes) >= 0) and
               (FindBytes(CurrentLine, ChunkedBytes) >= 0) then
            begin
              HasChunkedEncoding := True;
              WriteLog(Format('Rejected chunked encoding request from %s', [ClientInfo.IP]));
              SendErrorResponse(ClientSocket, 415, 'Unsupported Media Type',
                'Transfer-Encoding: chunked is not supported');
              Exit;
            end;

            StartPos := FindBytes(CurrentLine, ContentLengthBytes);
            if StartPos >= 0 then
            begin
              ClientInfo.HasContentLength := True;
              StartPos := StartPos + Length(ContentLengthBytes);
              while (StartPos < Length(CurrentLine)) and
                    ((CurrentLine[StartPos] = 32) or (CurrentLine[StartPos] = 9)) do
                Inc(StartPos);
              ClientInfo.ContentLength := 0;
              i := StartPos;
              if i >= Length(CurrentLine) then
              begin
                ClientInfo.ContentLengthValid := False;
                WriteLog(Format(LOG_EMPTY_CONTENT_LENGTH, [ClientInfo.IP]));
                SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
                Exit;
              end;

               while (i < Length(CurrentLine)) and (CurrentLine[i] >= 48) and (CurrentLine[i] <= 57) do
              begin
                ClientInfo.ContentLength := ClientInfo.ContentLength * 10 + (CurrentLine[i] - 48);
                Inc(i);
              end;
             if i = StartPos then
              begin
                ClientInfo.ContentLengthValid := False;
                WriteLog(Format(LOG_INVALID_CONTENT_LENGTH, [ClientInfo.IP,
                                TEncoding.ASCII.GetString(Copy(CurrentLine, StartPos, Length(CurrentLine) - StartPos))]));
                SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
                Exit;
              end;

              if ClientInfo.ContentLength < 0 then
              begin
                ClientInfo.ContentLengthValid := False;
                WriteLog(Format(LOG_NEGATIVE_CONTENT_LENGTH, [ClientInfo.IP, ClientInfo.ContentLength]));
                SendErrorResponse(ClientSocket, 400, STATUS_400_INVALID_LENGTH);
                Exit;
              end;

              if ClientInfo.ContentLength > FMaxPostSize then
              begin
                WriteLog(Format(LOG_CONTENT_LENGTH_LARGE, [ClientInfo.IP, ClientInfo.ContentLength]));
                SendErrorResponse(ClientSocket, 413, HTTP_MSG_PAYLOAD_TOO_LARGE);
                Exit;
              end;
            end;

            LineStartPos := EndPos + 2;
          end;

          if HasChunkedEncoding then
            Exit;
        end;
      end;

      if ClientInfo.HeaderEndPos > 0 then
      begin
        ClientInfo.PostDataReceived := Length(Request) - ClientInfo.HeaderEndPos - 4;

        if BytesStartWith(Request, HTTPPostBytes) then
        begin
          if ClientInfo.HasContentLength and ClientInfo.ContentLengthValid then
          begin
            if ClientInfo.PostDataReceived >= ClientInfo.ContentLength then
            begin
              WriteLog(Format(LOG_POST_REQUEST_RECEIVED,
                      [ClientInfo.IP, ClientInfo.TotalBytesReceived]));
              if not ValidateUserAgent(Request) then
                Exit;
              Result := True;
              Break;
            end;
          end;
        end
        else
        begin
          if not ValidateUserAgent(Request) then
            Exit;
          Result := True;
          Break;
        end;
      end
      else if ClientInfo.TotalBytesReceived > FMaxHeaderSize then
      begin
        HandleHeaderSizeLimitExceeded(Request);
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
        WriteLog(Format(LOG_ERROR_CREATING_RESPONSE, [ClientInfo.IP, E.Message]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
        SendErrorResponse(ClientSocket, 500, HTTP_MSG_INTERNAL_SERVER_ERROR);
        Exit;
      end;
    end;

    if Length(Response) > 0 then
    begin
      Sent := send(ClientSocket, Response[0], Length(Response), 0);
      if Sent = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        WriteLog(Format(LOG_SEND_FAILED,
                 [ClientInfo.IP, ErrorCode, SocketErrorToString(ErrorCode)]));
      end
      else
      begin
        WriteLog(Format(LOG_RESPONSE_SENT, [ClientInfo.IP, Sent]));
        Result := True;
      end;
    end;
  end;

begin
  try
    ClientInfo.IP := GetClientIP(ClientSocket);
    ClientInfo.StartTime := Now;
    ClientInfo.ContentLength := 0;
    ClientInfo.ContentLengthValid := True;
    ClientInfo.HasContentLength := False;
    ClientInfo.PostDataReceived := 0;
    ClientInfo.ConnectionClosed := False;
    ClientInfo.IsHTTP10 := False;
    ClientInfo.TimeoutValue := FMaxRequestTime;

    if not IsIPAllowed then
      Exit;

    if not ReceiveHttpRequest then
      Exit;

    GenerateResponse;
  except
    on E: Exception do
    begin
      WriteLog(Format(LOG_EXCEPTION, [ClientInfo.IP, E.Message]));
      try
        SendErrorResponse(ClientSocket, 500, HTTP_MSG_INTERNAL_SERVER_ERROR);
      except
        on E: Exception do
          WriteLog(LOG_ERROR_SENDING_ERROR);
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
  JWT: TJWTToken;
  AuthHeader, TokenStr: string;
  IsAuthorized: Boolean;
begin
  Result := False;
  RequestParser := THTTPRequestParser.Create(Request, HttpLogger);
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
        if EndpointItem.AuthorizationType = atJWTBearer then
        begin
          IsAuthorized := False;

          AuthHeader := RequestParser.GetHeader('Authorization');
          if AuthHeader <> '' then
          begin
            TokenStr := FJWTManager.ExtractTokenFromAuthHeader(AuthHeader);
            if TokenStr <> '' then
            begin
              if FJWTManager.ValidateToken(TokenStr, JWT) then
              begin
                if EndpointItem.Roles.Count > 0 then
                begin
                  var RolesClaim := JWT.GetClaim('roles');
                  if RolesClaim <> '' then
                  begin
                    var TokenRoles := TJSONObject.ParseJSONValue(RolesClaim) as TJSONArray;
                    if Assigned(TokenRoles) then
                    try
                      for var i := 0 to TokenRoles.Count - 1 do
                      begin
                        var Role := TokenRoles.Items[i].Value;
                        if EndpointItem.Roles.IndexOf(Role) >= 0 then
                        begin
                          IsAuthorized := True;
                          Break;
                        end;
                      end;
                    finally
                      TokenRoles.Free;
                    end;
                  end;
                end
                else
                  IsAuthorized := True;
              end;

              if Assigned(JWT.Decoded) then
                JWT.Decoded.Free;
            end;
          end;

          if not IsAuthorized then
          begin
            ResponseBuilder.SetStatus(401, 'Unauthorized');
            ResponseBuilder.AddHeader('WWW-Authenticate', 'Bearer realm="GHTTPServer"');
            ResponseBuilder.AddTextContent('{"error":"Unauthorized access"}', MIME_TYPE_JSON, 'Authentication required');
          end else
          begin
            if Assigned(EndpointItem.OnRequest) then
              EndpointItem.OnRequest(EndpointItem, RequestParser, ResponseBuilder, Self)
            else if Assigned(EndpointItem.OnRequestProc) then
              EndpointItem.OnRequestProc(EndpointItem, RequestParser, ResponseBuilder, Self);
          end;
        end else
        begin
          if Assigned(EndpointItem.OnRequest) then
            EndpointItem.OnRequest(EndpointItem, RequestParser, ResponseBuilder, Self)
          else if Assigned(EndpointItem.OnRequestProc) then
            EndpointItem.OnRequestProc(EndpointItem, RequestParser, ResponseBuilder, Self);
        end;
      except
        on E: Exception do
        begin
          WriteLog(Format(ERR_ENDPOINT_HANDLER, [RequestParser.Path, E.Message]));
          ResponseBuilder.SetStatus(500, HTTP_MSG_METHOD_NOT_ALLOWED);
          ResponseBuilder.AddTextContent(ERR_ERROR, MIME_TYPE_TEXT, ERR_INTERNAL_SERVER);
        end;
      end;
    end
    else
    begin
      ResponseBuilder.SetStatus(404, ERR_NOT_FOUND_ENDPOINT);
      ResponseBuilder.AddTextContent(ERR_ERROR, MIME_TYPE_TEXT, ERR_NOT_FOUND_ENDPOINT);
    end;

    ResponseBuilder.AddHeader(HDR_SERVER, HDR_SERVER_VALUE);

    ResponseBuilder.AddHeader(HTTP_HEADER_STRICT_TRANSPORT_SECURITY, HTTP_VALUE_HSTS);
    ResponseBuilder.AddHeader(HTTP_HEADER_X_CONTENT_TYPE_OPTIONS, HTTP_VALUE_NOSNIFF);
    ResponseBuilder.AddHeader(HTTP_HEADER_X_FRAME_OPTIONS, HTTP_VALUE_SAMEORIGIN);
    ResponseBuilder.AddHeader(HTTP_HEADER_X_XSS_PROTECTION, HTTP_VALUE_XSS_MODE_BLOCK);
    ResponseBuilder.AddHeader(HTTP_HEADER_REFERRER_POLICY, HTTP_VALUE_POLICY);


    ResponseBuilder.AddHeader(HTTP_HEADER_CONTENT_SECURITY_POLICY, HTTP_VALUE_XSS);

    ResponseBuilder.AddHeader(HTTP_HEADER_CACHE_CONTROL, HTTP_VALUE_NO_CACHE_FULL);

    ResponseBuilder.AddHeader(HDR_PRAGMA, HTTP_VALUE_NO_CACHE);
    ResponseBuilder.AddHeader(HDR_EXPIRES, VAL_EXPIRES_ZERO);

    Response := ResponseBuilder.ToBytes;
    Result := False;
  finally
    RequestParser.Free;
    ResponseBuilder.Free;
  end;
end;

function TGHTTPServer.ExtractUserAgent(const Request: TBytes): string;
var
  HeaderBytes: TBytes;
  CharJump: array[0..255] of Integer;
  HeaderPos, HeaderLen, RequestLen, I, J, StartPos, EndPos: Integer;
  ResultBytes: TBytes;
begin
  Result := '';
  RequestLen := Length(Request);
  HeaderBytes := TEncoding.ASCII.GetBytes(HDR_USER_AGENT);
  HeaderLen := Length(HeaderBytes);

  if (HeaderLen = 0) or (RequestLen < HeaderLen) then
    Exit;
  for I := 0 to 255 do
    CharJump[I] := HeaderLen;

  for I := 0 to HeaderLen - 2 do
    CharJump[HeaderBytes[I]] := HeaderLen - 1 - I;
  HeaderPos := 0;
  while HeaderPos <= RequestLen - HeaderLen do
  begin
    J := HeaderLen - 1;
    while (J >= 0) and (HeaderBytes[J] = Request[HeaderPos + J]) do
      Dec(J);
    if J < 0 then
    begin
      StartPos := HeaderPos + HeaderLen;
      while (StartPos < RequestLen) and ((Request[StartPos] = 32) or (Request[StartPos] = 9)) do
        Inc(StartPos);
      EndPos := StartPos;
      while (EndPos < RequestLen) and (Request[EndPos] <> 13) and (Request[EndPos] <> 10) do
        Inc(EndPos);

      SetLength(ResultBytes, EndPos - StartPos);
      if EndPos > StartPos then
        Move(Request[StartPos], ResultBytes[0], EndPos - StartPos);

      Result := TEncoding.ASCII.GetString(ResultBytes);
      Exit;
    end;
    HeaderPos := HeaderPos + CharJump[Request[HeaderPos + HeaderLen - 1]];
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

  if Pos(BROWSER_MSIE_60, UserAgent) > 0 then
  begin
    Result := True;
    Exit;
  end;

  if (Pos(THREAT_SQLMAP, LowerCase(UserAgent)) > 0) or
     (Pos(THREAT_FUZZ, LowerCase(UserAgent)) > 0) or
     (Pos(THREAT_SCRIPT_TAG, LowerCase(UserAgent)) > 0) or
     (Pos(THREAT_SQL_SELECT, UpperCase(UserAgent)) > 0) then
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
   Result := MIME_TYPE_BIN;
end;

procedure TGHTTPServer.InitializeMimeTypes;
begin
  FMimeTypes.CaseSensitive := False;
  FMimeTypes.Add(FEXT_TXT + '=' + MIME_TYPE_TEXT);
  FMimeTypes.Add(FEXT_HTML + '=' + MIME_TYPE_HTML);
  FMimeTypes.Add(FEXT_HTM + '=' + MIME_TYPE_HTML);
  FMimeTypes.Add(FEXT_CSS + '=' + MIME_TYPE_CSS);
  FMimeTypes.Add(FEXT_JS + '=' + MIME_TYPE_JAVASCRIPT);
  FMimeTypes.Add(FEXT_JSON + '=' + MIME_TYPE_JSON);
  FMimeTypes.Add(FEXT_JPG + '=' + MIME_TYPE_JPEG);
  FMimeTypes.Add(FEXT_JPEG + '=' + MIME_TYPE_JPEG);
  FMimeTypes.Add(FEXT_PNG + '=' + MIME_TYPE_PNG);
  FMimeTypes.Add(FEXT_GIF + '=' + MIME_TYPE_GIF);
  FMimeTypes.Add(FEXT_SVG + '=' + MIME_TYPE_SVG);
  FMimeTypes.Add(FEXT_PDF + '=' + MIME_TYPE_PDF);
  FMimeTypes.Add(FEXT_ZIP + '=' + MIME_TYPE_ZIP);
  FMimeTypes.Add(FEXT_EXE + '=' + MIME_TYPE_BIN);
  FMimeTypes.Add(FEXT_BIN + '=' + MIME_TYPE_BIN);
  FMimeTypes.Add(FEXT_MP4 + '=' + MIME_TYPE_MP4);
  FMimeTypes.Add(FEXT_MP3 + '=' + MIME_TYPE_MP3);
  FMimeTypes.Add(FEXT_XML + '=' + MIME_TYPE_XML);
  FMimeTypes.Add(FEXT_DOCX + '=' + MIME_TYPE_DOCX);
  FMimeTypes.Add(FEXT_XLSX + '=' + MIME_TYPE_XLSX);
  FMimeTypes.Add(FEXT_ICO + '=' + MIME_TYPE_ICO);
end;


function TGHTTPServer.SocketErrorToString(ErrorCode: Integer): string;
  begin
    case ErrorCode of
      WSAEWOULDBLOCK: Result := MSG_WSAEWOULDBLOCK;
      WSAENETDOWN: Result := MSG_WSAENETDOWN;
      WSAENOTSOCK: Result := MSG_WSAENOTSOCK;
      WSAEOPNOTSUPP: Result := MSG_WSAEOPNOTSUPP;
      WSAESHUTDOWN: Result := MSG_WSAESHUTDOWN;
      WSAECONNABORTED: Result := MSG_WSAECONNABORTED;
      WSAECONNRESET: Result := MSG_WSAECONNRESET;
      WSAETIMEDOUT: Result := MSG_WSAETIMEDOUT;
      WSAEHOSTUNREACH: Result := MSG_WSAEHOSTUNREACH ;
      else Result := Format(MSG_SOCKET_UNKNOWN, [ErrorCode]);
    end;
end;

end.
