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
  HttpServerUtils, HTTPResponseBuilder, HTTPRequest,
  GHTTPServer, OpenSSLWrapper;



type
  TGHTTPSServer = class(TGHTTPServer)
  private
    FCertificatePath: string;
    FPrivateKeyPath: string;
    FIsSecure: Boolean;
    FSSLWrapper: TOpenSSLWrapper;
    FSecureProtocols: TSecureProtocols;
  protected
    procedure ProcessClientRequestNew(ClientSocket: TSocket); override;
    function CreateResponseNew(const Request: TBytes; ClientSocket: TSocket;
                              out Response: TBytes; AClientIP: String): Boolean; override;

    function SSLRead(ClientSocket: TSocket; var Buffer; BufferSize: Integer): Integer;
    function SSLWrite(ClientSocket: TSocket; const Buffer; BufferSize: Integer): Integer;
    function ExtractUserAgent(const Request: TBytes): string; override;
    function IsSuspiciousUserAgent(const UserAgent: string): Boolean; override;
    function WaitForSocketReady(Socket: TSocket; ForReading: Boolean; TimeoutMs: Integer): Boolean; override;
    procedure SendErrorResponse(ClientSocket: TSocket; StatusCode: Integer; Message: string; ExtraHeaders: string = '');
  public
    constructor Create(AOwner: TComponent; Port: Integer; MaxConnections: Integer = 100;
                      AHttpLogger: THttpLogger = nil); reintroduce;
    destructor Destroy; override;
    procedure Start; override;
    procedure Stop; override;
    procedure HandleClient(ClientSocket: TSocket); override;
    property CertificatePath: string read FCertificatePath write FCertificatePath;
    property PrivateKeyPath: string read FPrivateKeyPath write FPrivateKeyPath;
    property IsSecure: Boolean read FIsSecure write FIsSecure;
    property SecureProtocols: TSecureProtocols read FSecureProtocols write FSecureProtocols;
  end;
implementation
uses
  System.IOUtils, GHTTPConstants;

constructor TGHTTPSServer.Create(AOwner: TComponent; Port: Integer;
                                MaxConnections: Integer = 100; AHttpLogger: THttpLogger = nil);
begin
  inherited Create(AOwner, Port, MaxConnections, AHttpLogger);
  FIsSecure := True;
  FSSLWrapper := TOpenSSLWrapper.Create(AHttpLogger);
  FCertificatePath := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_CERT_FILE);
  FPrivateKeyPath := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_KEY_FILE);
  FSecureProtocols := [spTLS12, spTLS13];
end;

destructor TGHTTPSServer.Destroy;
begin
  if FIsSecure and Assigned(FSSLWrapper) and FSSLWrapper.Initialized then
    FSSLWrapper.Finalize;
  FSSLWrapper.Free;
  inherited;
end;

procedure TGHTTPSServer.HandleClient(ClientSocket: TSocket);
begin
  if not FIsSecure then
  begin
    inherited HandleClient(ClientSocket);
    Exit;
  end;
  if not FSSLWrapper.CreateSSLObject(ClientSocket) then
  begin
    {$IFDEF MSWINDOWS}
    closesocket(ClientSocket);
    {$ENDIF}
    {$IFDEF LINUX}
    __close(ClientSocket);
    {$ENDIF}
    Exit;
  end;
  if not FSSLWrapper.PerformSSLHandshake(ClientSocket) then
  begin
    FSSLWrapper.CleanupSSLConnection(ClientSocket);
    {$IFDEF MSWINDOWS}
    closesocket(ClientSocket);
    {$ENDIF}
    {$IFDEF LINUX}
    __close(ClientSocket);
    {$ENDIF}
    Exit;
  end;
  IncrementConnections;
  TTask.Run(procedure
  begin
    try
      ProcessClientRequestNew(ClientSocket);
    finally
      DecrementConnections;
      FSSLWrapper.CleanupSSLConnection(ClientSocket);
      {$IFDEF MSWINDOWS}
      closesocket(ClientSocket);
      {$ENDIF}
      {$IFDEF LINUX}
      __close(ClientSocket);
      {$ENDIF}
    end;
  end, ThreadPool);
end;

function TGHTTPSServer.SSLRead(ClientSocket: TSocket; var Buffer; BufferSize: Integer): Integer;
begin
  if FIsSecure then
    Result := FSSLWrapper.SSLRead(ClientSocket, Buffer, BufferSize)
  else
    Result := recv(ClientSocket, Buffer, BufferSize, 0);
end;

function TGHTTPSServer.SSLWrite(ClientSocket: TSocket; const Buffer; BufferSize: Integer): Integer;
begin
  if FIsSecure then
    Result := FSSLWrapper.SSLWrite(ClientSocket, Buffer, BufferSize)
  else
    Result := send(ClientSocket, Buffer, BufferSize, 0);
end;

procedure TGHTTPSServer.SendErrorResponse(ClientSocket: TSocket; StatusCode: Integer; Message: string; ExtraHeaders: string = '');
var
  ResponseText: string;
  ResponseBytes: TBytes;
  ErrorCode: Integer;
begin
  ResponseText := Format(HTTP_RESPONSE_FORMAT, [StatusCode, Message, Length(Message)]);
  if ExtraHeaders <> '' then
    ResponseText := ResponseText + ExtraHeaders + #13#10;
  ResponseText := ResponseText + #13#10 + Message;
  ResponseBytes := TEncoding.ASCII.GetBytes(ResponseText);
  if FIsSecure then
    ErrorCode := SSLWrite(ClientSocket, ResponseBytes[0], Length(ResponseBytes))
  else
    ErrorCode := send(ClientSocket, ResponseBytes[0], Length(ResponseBytes), 0);
  if ErrorCode = SOCKET_ERROR then
    WriteLog(Format(LOG_ERROR_SENDING_RESPONSE, [StatusCode]));
end;

procedure TGHTTPSServer.ProcessClientRequestNew(ClientSocket: TSocket);
var
  Request: TBytes;
  Response: TBytes;
  ClientInfo: TClientInfo;

  function IsIPAllowed: Boolean;
  begin
    Result := True;
    if GlobalIPMonitor.IsIPBlocked(ClientInfo.IP) then
    begin
      WriteLog(Format(LOG_BLOCKED_CONNECTION, [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_TOO_MANY_REQUESTS, HTTP_MSG_TOO_MANY_REQUESTS, RETRY_AFTER_600);
      Result := False;
      Exit;
    end;
    if not GlobalIPMonitor.RegisterRequest(ClientInfo.IP) then
    begin
      WriteLog(Format(LOG_RATE_LIMIT_EXCEEDED, [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_TOO_MANY_REQUESTS, HTTP_MSG_TOO_MANY_REQUESTS, RETRY_AFTER_60);
      Result := False;
    end;
  end;

  function ProcessContentLengthHeader(const HeaderLine: TBytes; const Request: TBytes): Boolean;
  var
    HeaderLineStr: string;
    ContentLengthHeaderBytes: TBytes;
    I: Integer;
    HeaderStartsWith: Boolean;
    ValueStr: string;
  begin
    Result := False;
    ContentLengthHeaderBytes := TEncoding.ASCII.GetBytes(CONTENT_LENGTH_HEADER);
    if Length(HeaderLine) < Length(ContentLengthHeaderBytes) then
      Exit;
    HeaderStartsWith := True;
    for I := 0 to Length(ContentLengthHeaderBytes) - 1 do
    begin
      if (HeaderLine[I] <> ContentLengthHeaderBytes[I]) and
         (Abs(Integer(HeaderLine[I]) - Integer(ContentLengthHeaderBytes[I])) <> 32) then
      begin
        HeaderStartsWith := False;
        Break;
      end;
    end;

    if not HeaderStartsWith then
      Exit;

    ClientInfo.HasContentLength := True;
    Result := True;

    HeaderLineStr := TEncoding.ASCII.GetString(HeaderLine);
    ValueStr := HeaderLineStr.Substring(15).Trim;

    if ValueStr.IsEmpty then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_EMPTY_CONTENT_LENGTH, [ClientInfo.IP]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if not TryStrToInt(ValueStr, ClientInfo.ContentLength) then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_INVALID_CONTENT_LENGTH, [ClientInfo.IP, ValueStr]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if ClientInfo.ContentLength < 0 then
    begin
      ClientInfo.ContentLengthValid := False;
      WriteLog(Format(LOG_NEGATIVE_CONTENT_LENGTH, [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_BAD_REQUEST, STATUS_400_INVALID_LENGTH);
      Exit;
    end;

    if ClientInfo.ContentLength > MaxPostSize then
    begin
      WriteLog(Format(LOG_CONTENT_LENGTH_LARGE, [ClientInfo.IP, ClientInfo.ContentLength]));
      SendErrorResponse(ClientSocket, HTTP_STATUS_PAYLOAD_TOO_LARGE, HTTP_MSG_PAYLOAD_TOO_LARGE);
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

  function ReceiveHttpRequest: Boolean;
  var
    Buffer: array[0..DEFAULT_BUFFER_SIZE] of Byte;
    BytesReceived, ErrorCode: Integer;
    i: Integer;
    ConsecutiveEmptyReads: Integer;
    HeaderEndBytes: TBytes;
    HTTPPostBytes: TBytes;
    HTTP10VersionBytes: TBytes;
  begin
    Result := False;
    SetLength(Request, 0);
    ClientInfo.TotalBytesReceived := 0;
    ClientInfo.StartTime := Now;
    ClientInfo.HeaderEndPos := 0;
    ConsecutiveEmptyReads := 0;

    HeaderEndBytes := TEncoding.ASCII.GetBytes(HEADER_END);
    HTTPPostBytes := TEncoding.ASCII.GetBytes(HTTP_POST);
    HTTP10VersionBytes := TEncoding.ASCII.GetBytes(HTTP_VERSION_1_0);

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
          if BytesStartWith(Request, HTTPPostBytes) and ClientInfo.HasContentLength and
             (ClientInfo.PostDataReceived < ClientInfo.ContentLength) then
          begin
            HandleIncompletePostData();
            Exit;
          end;
        end;
        Continue;
      end;

      ConsecutiveEmptyReads := 0;
      BytesReceived := SSLRead(ClientSocket, Buffer, SizeOf(Buffer));
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
        ClientInfo.HeaderEndPos := BytesPos(Request, HeaderEndBytes);
        if ClientInfo.HeaderEndPos > 0 then
        begin
          ClientInfo.IsHTTP10 := BytesContains(Request, HTTP10VersionBytes);
          ClientInfo.HasContentLength := False;
          ClientInfo.ContentLengthValid := True;
          var LineStart, LineEnd: Integer;
          var HeaderLine: string;
          LineStart := 0;
          while LineStart < ClientInfo.HeaderEndPos do
          begin
            LineEnd := LineStart;
            while (LineEnd < ClientInfo.HeaderEndPos) and
                  not ((Request[LineEnd] = 13) and (Request[LineEnd + 1] = 10)) do
              Inc(LineEnd);

            if LineEnd >= ClientInfo.HeaderEndPos then
              Break;
            var Line: TBytes;
            SetLength(Line, LineEnd - LineStart);
            if LineEnd > LineStart then
              Move(Request[LineStart], Line[0], LineEnd - LineStart);
            if ProcessContentLengthHeader(Line, Request) then
              Break;
            LineStart := LineEnd + 2;
          end;

        end;
      end;

      if ClientInfo.HeaderEndPos > 0 then
      begin
        ClientInfo.PostDataReceived := Length(Request) - ClientInfo.HeaderEndPos - 3;
        if BytesStartWith(Request, HTTPPostBytes) then
        begin
          if ClientInfo.HasContentLength and ClientInfo.ContentLengthValid then
          begin
            if ClientInfo.PostDataReceived >= ClientInfo.ContentLength then
            begin
              WriteLog(Format(LOG_POST_REQUEST_RECEIVED, [ClientInfo.IP, ClientInfo.TotalBytesReceived]));
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
      else if ClientInfo.TotalBytesReceived > MaxHeaderSize then
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
        SendErrorResponse(ClientSocket, HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_MSG_INTERNAL_SERVER_ERROR);
        Exit;
      end;
    end;
    if Length(Response) > 0 then
    begin
      if FIsSecure then
        Sent := SSLWrite(ClientSocket, Response[0], Length(Response))
      else
        Sent := send(ClientSocket, Response[0], Length(Response), 0);
      if Sent = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        WriteLog(Format(LOG_SEND_FAILED, [ClientInfo.IP, ErrorCode, SocketErrorToString(ErrorCode)]));
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
    ClientInfo.TimeoutValue := MaxRequestTime;
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
        SendErrorResponse(ClientSocket, HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_MSG_INTERNAL_SERVER_ERROR);
      except
        on E: Exception do
          WriteLog(LOG_ERROR_SENDING_ERROR);
      end;
      if ClientInfo.IP <> '' then
        GlobalIPMonitor.RegisterFailedAttempt(ClientInfo.IP);
    end;
  end;
end;

function TGHTTPSServer.ExtractUserAgent(const Request: TBytes): string;
begin
  Result := inherited ExtractUserAgent(Request);

  if FIsSecure and (Result <> '') then
    WriteLog(Format(LOG_HTTPS_USER_AGENT, [Result]));
end;

function TGHTTPSServer.IsSuspiciousUserAgent(const UserAgent: string): Boolean;
begin
  Result := inherited IsSuspiciousUserAgent(UserAgent);
  if FIsSecure and Result then
    WriteLog(Format(LOG_SUSPICIOUS_HTTPS_USER_AGENT, [UserAgent]));
end;

function TGHTTPSServer.WaitForSocketReady(Socket: TSocket; ForReading: Boolean; TimeoutMs: Integer): Boolean;
var
  FDSet: TFDSet;
  TimeVal: TTimeVal;
  SelectResult: Integer;
begin
  if not FIsSecure then
  begin
    Result := inherited WaitForSocketReady(Socket, ForReading, TimeoutMs);
    Exit;
  end;
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

function TGHTTPSServer.CreateResponseNew(const Request: TBytes; ClientSocket: TSocket;
  out Response: TBytes; AClientIP: String): Boolean;
begin
  Result := inherited CreateResponseNew(Request, ClientSocket, Response, AClientIP);
end;

procedure TGHTTPSServer.Start;
begin
  if FIsSecure then
  begin
    try
      FSSLWrapper.CertificatePath := FCertificatePath;
      FSSLWrapper.PrivateKeyPath := FPrivateKeyPath;
      FSSLWrapper.SecureProtocols := FSecureProtocols;
      FSSLWrapper.Initialize;
    except
      on E: Exception do
      begin
        WriteLog(Format(ERROR_SSL_INITIALIZATION, [E.Message]));
        raise;
      end;
    end;
  end;
  inherited Start;
end;

procedure TGHTTPSServer.Stop;
begin
  inherited Stop;
  if FIsSecure and Assigned(FSSLWrapper) and FSSLWrapper.Initialized then
    FSSLWrapper.Finalize;
end;

end.
