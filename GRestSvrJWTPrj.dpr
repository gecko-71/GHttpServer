program GRestSvrJWTPrj;


{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  GHTTPConstants in 'GHTTPConstants.pas',
  GHTTPServer in 'GHTTPServer.pas',
  HTTPRequest in 'HTTPRequest.pas',
  HTTPResponseBuilder in 'HTTPResponseBuilder.pas',
  HttpServerUtils in 'HttpServerUtils.pas',
  Logger in 'Logger.pas';

type
  TGHttpJWTServer = class
  private
    FServer: TGHTTPServer;
    HttpLogger : THttpLogger;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Start;
    procedure HandleTokenRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
    procedure HandleProtectedEndpoint(Sender: TObject;
                                   ARequestParser: THTTPRequestParser;
                                   AResponseBuilder: THTTPResponseBuilder;
                                   AServer: TGHTTPServer);
  end;

var
  Application: TGHttpJWTServer;



constructor TGHttpJWTServer.Create;
begin
  inherited Create;

  HttpLogger := THttpLogger.Create();
  HttpLogger.OnNewLogLineProc :=
           procedure(Sender: TObject; const LogLine: string)
           begin
             WriteLn(LogLine);
           end;
  FServer := TGHTTPServer.Create(nil, 3042, 200, HttpLogger);

  FServer.ConfigureJWT('1234567890abc', 'GHttpJWTServer', 60);

  FServer.AddEndpoint('/api/token', 'POST', HandleTokenRequest,atNone,[]);

  FServer.AddEndpoint('/api/autotest', 'GET', HandleProtectedEndpoint,atNone,[]);
end;

destructor TGHttpJWTServer.Destroy;
begin
  FServer.Free;
  HttpLogger.free;
  inherited;
end;

procedure TGHttpJWTServer.HandleTokenRequest(Sender: TObject;
  ARequestParser: THTTPRequestParser; AResponseBuilder: THTTPResponseBuilder;
  AServer: TGHTTPServer);
var
  RequestBody: string;
  RequestJson, ResponseJson: TJSONObject;
  Username, Password: string;
  CustomClaims: TJSONObject;
  RolesArray: TJSONArray;
  Token: string;
begin
  try

    RequestBody := ARequestParser.BodyValue;
    if RequestBody = '' then
    begin
      AResponseBuilder.SetStatus(400, 'Bad Request');
      AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Empty request body"}');
      Exit;
    end;

    try
      RequestJson := TJSONObject.ParseJSONValue(RequestBody) as TJSONObject;
      if not Assigned(RequestJson) then
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', '{"error":"Invalid JSON"}', 'application/json');
        Exit;
      end;

      try
        Username := RequestJson.GetValue<string>('username', '');
        Password := RequestJson.GetValue<string>('password', '');

        if (Username = 'admin') and (Password = 'admin') then
        begin
          CustomClaims := TJSONObject.Create;
          RolesArray := TJSONArray.Create;
          try
            RolesArray.Add('admin');
            RolesArray.Add('user');
            CustomClaims.AddPair('roles', RolesArray);

            Token := AServer.JWTManager.CreateToken(Username, CustomClaims);

            ResponseJson := TJSONObject.Create;
            try
              ResponseJson.AddPair('token', Token);
              ResponseJson.AddPair('token_type', 'Bearer');
              ResponseJson.AddPair('expires_in', TJSONNumber.Create(60 * 60)); // 60 minut w sekundach

              AResponseBuilder.SetStatus(200, 'OK');
              AResponseBuilder.AddTextContent('response', 'application/json', ResponseJson.ToString);
            finally
              ResponseJson.Free;
            end;
          finally
            CustomClaims.Free;
          end;
        end
        else
        begin
          AResponseBuilder.SetStatus(401, 'Unauthorized');
          AResponseBuilder.AddTextContent( 'error', '{"error":"Invalid username or password"}', 'application/json');
        end;
      finally
        RequestJson.Free;
      end;
    except
      on E: Exception do
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"JSON parsing error: %s"}', [E.Message]));
      end;
    end;
  except
    on E: Exception do
    begin
      AResponseBuilder.SetStatus(500, 'Internal Server Error');
      AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"%s"}', [E.Message]));
    end;
  end;
end;

procedure TGHttpJWTServer.HandleProtectedEndpoint(Sender: TObject;
  ARequestParser: THTTPRequestParser; AResponseBuilder: THTTPResponseBuilder;
  AServer: TGHTTPServer);
var
  ResponseJson: TJSONObject;
  AuthHeader: string;
begin
  AuthHeader := ARequestParser.GetHeader('Authorization');


  ResponseJson := TJSONObject.Create;
  try
    ResponseJson.AddPair('status', 'success');
    ResponseJson.AddPair('message', 'You have successfully accessed the protected endpoint!');
    ResponseJson.AddPair('timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));

    if AuthHeader <> '' then
      ResponseJson.AddPair('auth_header_length', TJSONNumber.Create(Length(AuthHeader)));

    AResponseBuilder.SetStatus(200, 'OK');
    AResponseBuilder.AddTextContent('response', 'application/json', ResponseJson.ToString);
  finally
    ResponseJson.Free;
  end;
end;

procedure TGHttpJWTServer.Start;
begin
  try
    WriteLn('=======================================');
    WriteLn('     GRestSvrJWTPrj');
    WriteLn('=======================================');
    WriteLn('Server running on http://localhost:3042');
    WriteLn;
    WriteLn('Available endpoints:');
    WriteLn('1. POST /api/token - Generate JWT token');
    WriteLn('   - Send JSON body with: {"username":"admin","password":"admin"}');
    WriteLn;
    WriteLn('2. GET /api/autotest - Endpoint requiring authorization');
    WriteLn('   - Requires valid JWT token in Authorization header');
    WriteLn('   - Format: Authorization: Bearer <token>');
    WriteLn;
    WriteLn('Press Ctrl+C to stop the server');
    WriteLn('=======================================');
    WriteLn;

    // Uruchomienie serwera
    FServer.Start;
  except
    on E: Exception do
    begin
      WriteLn('Error starting server: ', E.Message);
    end;
  end;
end;

begin
  try
    Application := TGHttpJWTServer.Create;
    try
      Application.Start;
    finally
      Application.Free;
    end;
  except
    on E: Exception do
      WriteLn(E.ClassName, ': ', E.Message);
  end;
end.
