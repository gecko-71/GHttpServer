{
  GHTTPSServer - Simple HTTP Server Component
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
unit GHTTPSServer;

interface

uses
  {$IFDEF MSWINDOWS}
  WinSock, Windows,
  {$ENDIF}
  {$IFDEF LINUX}
  Posix.SysSocket, Posix.NetinetIn, Posix.ArpaInet, Posix.Unistd, Posix.NetDB,
  {$ENDIF}
  SysUtils, Classes, SyncObjs, System.Threading, Logger, System.StrUtils,
  System.Generics.Collections, System.Net.URLClient,
  HttpServerUtils, HTTPResponseBuilder, HTTPRequest, GHTTPServer, OpenSSLWrapper;

type
  // HTTPS Server class
  TGHTTPSServer = class(TGHTTPServer)
  private
    FCertificatePath: string;
    FPrivateKeyPath: string;
    FIsSecure: Boolean;
    FSSLWrapper: TOpenSSLWrapper;

    procedure SecureHandleClient(ClientSocket: TSocket);
    procedure ProcessSecureClientRequest(ClientSocket: TSocket);
    function CreateSSLResponse(const Request: TBytes; ClientSocket: TSocket; out Response: TBytes; AClientIP: String): Boolean;

  protected
    procedure InternalHandleClient(ClientSocket: TSocket);

  public
    constructor Create(AOwner: TComponent; Port: Integer; MaxConnections: Integer = 100;
                      AHttpLogger: THttpLogger = nil); reintroduce;
    destructor Destroy; override;
    procedure Start; override;
    procedure Stop; override;

    property CertificatePath: string read FCertificatePath write FCertificatePath;
    property PrivateKeyPath: string read FPrivateKeyPath write FPrivateKeyPath;
    property IsSecure: Boolean read FIsSecure write FIsSecure;
  end;

implementation

uses
  System.IOUtils;

constructor TGHTTPSServer.Create(AOwner: TComponent; Port: Integer;
                                MaxConnections: Integer = 100; AHttpLogger: THttpLogger = nil);
begin
  inherited Create(AOwner, Port, MaxConnections, AHttpLogger);
  FIsSecure := True;

  // Create the OpenSSL wrapper
  FSSLWrapper := TOpenSSLWrapper.Create(AHttpLogger);

  // Default certificate paths (relative to application directory)
  FCertificatePath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'cert.pem');
  FPrivateKeyPath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'key.pem');
end;

destructor TGHTTPSServer.Destroy;
begin
  Stop;
  FSSLWrapper.Free;
  inherited;
end;

procedure TGHTTPSServer.InternalHandleClient(ClientSocket: TSocket);
begin
  if FIsSecure then
    SecureHandleClient(ClientSocket)
  else
    inherited HandleClient(ClientSocket);
end;

procedure TGHTTPSServer.SecureHandleClient(ClientSocket: TSocket);
begin
  // Create SSL object for this connection
  if not FSSLWrapper.CreateSSLObject(ClientSocket) then
  begin
    closesocket(ClientSocket);
    Exit;
  end;

  // Perform SSL handshake
  if not FSSLWrapper.PerformSSLHandshake(ClientSocket) then
  begin
    FSSLWrapper.CleanupSSLConnection(ClientSocket);
    closesocket(ClientSocket);
    Exit;
  end;

  // Process the client in a thread
  IncrementConnections;
  TTask.Run(procedure
  begin
    try
      ProcessSecureClientRequest(ClientSocket);
    finally
      DecrementConnections;
      FSSLWrapper.CleanupSSLConnection(ClientSocket);
      closesocket(ClientSocket);
    end;
  end, ThreadPool);
end;

procedure TGHTTPSServer.ProcessSecureClientRequest(ClientSocket: TSocket);
var
  Buffer: array[0..8191] of Byte;
  Request: TBytes;
  TempBytes: TBytes;
  BytesReceived: Integer;
  Response: TBytes;
  TotalBytesReceived: Integer;
  ClientIP: string;
  SockAddr: TSockAddr;
  AddrLen: Integer;
  StartTime: TDateTime;
  BytesSent: Integer;
  HeaderEnd: Integer;
  RequestStr: string;

  function AppendBytes(const Bytes1, Bytes2: TBytes): TBytes;
  var
    Len1, Len2: Integer;
  begin
    Len1 := Length(Bytes1);
    Len2 := Length(Bytes2);
    SetLength(Result, Len1 + Len2);
    if Len1 > 0 then
      Move(Bytes1[0], Result[0], Len1);
    if Len2 > 0 then
      Move(Bytes2[0], Result[Len1], Len2);
  end;

begin
  try
    // Get client IP
    AddrLen := SizeOf(SockAddr);
    ClientIP := '0.0.0.0';
    if getpeername(ClientSocket, SockAddr, AddrLen) = 0 then
    begin
      if SockAddr.sa_family = AF_INET then
      begin
        with PSockAddrIn(@SockAddr)^ do
          ClientIP := Format('%d.%d.%d.%d', [
            Byte(sin_addr.S_addr),
            Byte(sin_addr.S_addr shr 8),
            Byte(sin_addr.S_addr shr 16),
            Byte(sin_addr.S_addr shr 24)
          ]);
      end;
    end;

    WriteLog(Format('Secure connection from IP %s', [ClientIP]));

    // Check if IP is blocked
    if GlobalIPMonitor.IsIPBlocked(ClientIP) then
    begin
      WriteLog(Format('Blocked connection from IP %s', [ClientIP]));
      Exit;
    end;

    // Register request
    if not GlobalIPMonitor.RegisterRequest(ClientIP) then
    begin
      WriteLog(Format('Rate limit exceeded for IP %s', [ClientIP]));
      Exit;
    end;

    // Initialize
    TotalBytesReceived := 0;
    StartTime := Now;
    SetLength(Request, 0);

    // Read request
    while True do
    begin
      // Check for timeout
      if (Now - StartTime) > MaxRequestTime then
      begin
        WriteLog(Format('Request timeout for IP %s', [ClientIP]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientIP);
        Exit;
      end;

      // Read data using the SSL wrapper
      BytesReceived := FSSLWrapper.SSLRead(ClientSocket, Buffer, SizeOf(Buffer));
      if BytesReceived = 0 then
      begin
        // Socket might not be ready, wait a bit
        Sleep(10);
        Continue;
      end
      else if BytesReceived < 0 then
      begin
        // Error
        WriteLog(Format('SSL read error for IP %s', [ClientIP]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientIP);
        Exit;
      end;

      // Append received data
      TotalBytesReceived := TotalBytesReceived + BytesReceived;
      SetLength(TempBytes, BytesReceived);
      Move(Buffer, TempBytes[0], BytesReceived);
      Request := AppendBytes(Request, TempBytes);

      // Check if we have received complete headers
      RequestStr := TEncoding.ASCII.GetString(Request);
      HeaderEnd := Pos(#13#10#13#10, RequestStr);
      if HeaderEnd > 0 then
      begin
        // Headers received, check if we have complete request
        if RequestStr.StartsWith('GET ') or RequestStr.StartsWith('HEAD ') then
        begin
          // For GET and HEAD, we're done once we have headers
          Break;
        end
        else if RequestStr.StartsWith('POST ') then
        begin
          // For POST, we need to check Content-Length
          var ContentLength := 0;
          var ContentLengthStr := '';
          var ContentLengthPos := Pos('Content-Length:', RequestStr);
          if ContentLengthPos > 0 then
          begin
            var EndOfLine := PosEx(#13#10, RequestStr, ContentLengthPos);
            if EndOfLine > 0 then
            begin
              ContentLengthStr := Copy(RequestStr, ContentLengthPos + 15, EndOfLine - (ContentLengthPos + 15));
              ContentLengthStr := Trim(ContentLengthStr);
              if not TryStrToInt(ContentLengthStr, ContentLength) then
                ContentLength := 0;
            end;
          end;

          var BodyLength := Length(RequestStr) - (HeaderEnd + 3);
          if BodyLength >= ContentLength then
            Break;
        end
        else
        begin
          // For other methods, we're done
          Break;
        end;
      end;

      // Check for max header size
      if (HeaderEnd = 0) and (TotalBytesReceived > MaxHeaderSize) then
      begin
        WriteLog(Format('Header size exceeded for IP %s', [ClientIP]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientIP);
        Exit;
      end;
    end;

    WriteLog(Format('Request received from IP %s (%d bytes)', [ClientIP, TotalBytesReceived]));

    // Process request
    try
      if CreateSSLResponse(Request, ClientSocket, Response, ClientIP) then
        Exit;
    except
      on E: Exception do
      begin
        WriteLog(Format('Error creating response: %s', [E.Message]));
        GlobalIPMonitor.RegisterFailedAttempt(ClientIP);
        Exit;
      end;
    end;

    // Send response using the SSL wrapper
    if Length(Response) > 0 then
    begin
      var Offset := 0;
      var Remaining := Length(Response);
      while Remaining > 0 do
      begin
        BytesSent := FSSLWrapper.SSLWrite(ClientSocket, Response[Offset], Remaining);
        if BytesSent <= 0 then
        begin
          WriteLog('SSL write error');
          Break;
        end;
        Inc(Offset, BytesSent);
        Dec(Remaining, BytesSent);
      end;
      WriteLog(Format('Response sent to IP %s (%d bytes)', [ClientIP, Length(Response)]));
    end;
  except
    on E: Exception do
    begin
      WriteLog(Format('Exception processing secure request: %s', [E.Message]));
      GlobalIPMonitor.RegisterFailedAttempt(ClientIP);
    end;
  end;
end;

function TGHTTPSServer.CreateSSLResponse(const Request: TBytes; ClientSocket: TSocket;
                                     out Response: TBytes; AClientIP: String): Boolean;
var
  RequestParser: THTTPRequestParser;
  ResponseBuilder: THTTPResponseBuilder;
  EndpointItem: TEndpointItem;
begin
  Result := False;
  RequestParser := THTTPRequestParser.Create(Request);
  ResponseBuilder := THTTPResponseBuilder.Create;
  try
    // Check if request is valid
    if not RequestParser.IsValid then
    begin
      Response := THTTPResponseBuilder.CreateBadRequestResponse.ToBytes;
      Exit;
    end;

    // Check if endpoint exists
    EndpointItem := Endpoints.FindEndpoint(RequestParser.Path, RequestParser.Method);
    if Assigned(EndpointItem) and (Assigned(EndpointItem.OnRequest) or Assigned(EndpointItem.OnRequestProc)) then
    begin
      // Call endpoint handler
      try
        if Assigned(EndpointItem.OnRequest) then
          EndpointItem.OnRequest(EndpointItem, RequestParser, ResponseBuilder, Self)
        else if Assigned(EndpointItem.OnRequestProc) then
          EndpointItem.OnRequestProc(EndpointItem, RequestParser, ResponseBuilder, Self);
      except
        on E: Exception do
        begin
          WriteLog(Format('Error in endpoint handler %s: %s', [RequestParser.Path, E.Message]));
          ResponseBuilder.SetStatus(500, 'Internal Server Error');
          ResponseBuilder.AddTextContent('error', 'text/plain', '500 Internal Server Error');
        end;
      end;
    end
    else
    begin
      // No endpoint found - return 404
      ResponseBuilder.SetStatus(404, 'Not Found');
      ResponseBuilder.AddTextContent('error', 'text/plain', '404 Not Found');
    end;

    ResponseBuilder.AddHeader('Server', 'WebServer'); // Generic value

    // Add additional security headers
    ResponseBuilder.AddHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    ResponseBuilder.AddHeader('X-Content-Type-Options', 'nosniff');
    ResponseBuilder.AddHeader('X-Frame-Options', 'SAMEORIGIN');

    ResponseBuilder.AddHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    ResponseBuilder.AddHeader('Pragma', 'no-cache');
    ResponseBuilder.AddHeader('Expires', '0');

    // Convert response to bytes
    Response := ResponseBuilder.ToBytes;
    Result := False; // Let the main loop send the response
  finally
    RequestParser.Free;
    ResponseBuilder.Free;
  end;
end;

procedure TGHTTPSServer.Start;
var
  ServerAddr: TSockAddrIn;
  ClientAddr: TSockAddrIn;
  ClientSocket: TSocket;
  OptVal: Integer;
begin
  // Initialize SSL if secure mode is enabled
  if FIsSecure then
  begin
    try
      // Configure SSL wrapper with certificate paths
      FSSLWrapper.CertificatePath := FCertificatePath;
      FSSLWrapper.PrivateKeyPath := FPrivateKeyPath;
      FSSLWrapper.Initialize;
    except
      on E: Exception do
      begin
        WriteLog(Format('Failed to initialize SSL: %s', [E.Message]));
        raise;
      end;
    end;
  end;

  // Initialize socket library
  InitializeSocketLibrary;

  // Create server socket
  ServerSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if ServerSocket = INVALID_SOCKET then
    raise Exception.Create('Socket creation failed');

  // Set socket options
  OptVal := 1;
  setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

  // Bind socket
  ServerAddr.sin_family := AF_INET;
  ServerAddr.sin_addr.s_addr := INADDR_ANY;
  ServerAddr.sin_port := htons(Port);
  if bind(ServerSocket, ServerAddr, SizeOf(ServerAddr)) = SOCKET_ERROR then
    raise Exception.Create('Bind failed');

  // Start listening
  if listen(ServerSocket, SOMAXCONN) = SOCKET_ERROR then
    raise Exception.Create('Listen failed');

  Listening := True;
  WriteLog(Format('Server started on port %d with %s', [Port,
          IfThen(FIsSecure, 'HTTPS (SSL/TLS)', 'HTTP')]));

  // Main server loop
  while Listening do
  begin
    // Accept new connection
    ClientSocket := AcceptConnection(ClientAddr);
    if ClientSocket = INVALID_SOCKET then
      Continue;

    // Check connection limit
    if GetActiveConnections >= MaxConnections then
    begin
      WriteLog('Too many connections, rejecting');
      closesocket(ClientSocket);
      Continue;
    end;

    // Handle client connection
    InternalHandleClient(ClientSocket);
  end;
end;

procedure TGHTTPSServer.Stop;
begin
  // Stop listening
  Listening := False;

  // Close server socket
  if ServerSocket <> INVALID_SOCKET then
  begin
    shutdown(ServerSocket, SD_BOTH);
    closesocket(ServerSocket);
    ServerSocket := INVALID_SOCKET;
  end;

  // Finalize socket library
  FinalizeSocketLibrary;

  // Finalize SSL if in secure mode
  if FIsSecure and FSSLWrapper.Initialized then
    FSSLWrapper.Finalize;

  WriteLog('Server stopped');
end;

end.
