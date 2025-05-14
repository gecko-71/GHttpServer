program GHttpsRestSvrJWTPrj_2;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Math,
  System.IOUtils,
  System.RegularExpressions,
  System.NetEncoding,
  GHTTPConstants in 'GHTTPConstants.pas',
  HTTPRequest in 'HTTPRequest.pas',
  HTTPResponseBuilder in 'HTTPResponseBuilder.pas',
  HttpServerUtils in 'HttpServerUtils.pas',
  Logger in 'Logger.pas',
  GHTTPSServer in 'GHTTPSServer.pas',
  GHTTPServer in 'GHTTPServer.pas',
  OpenSSLWrapper in 'OpenSSLWrapper.pas';

type
  TGHttpsJWTServer = class
  private
    FServer: TGHTTPSServer;
    HttpLogger : THttpLogger;
    procedure CreateRandomFile(const FileName: string);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Start;
    procedure GetTokenRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
    procedure GetFileListRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
    procedure GetFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
    procedure PostFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
    procedure UpladFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
  end;

var
  Application: TGHttpsJWTServer;

constructor TGHttpsJWTServer.Create;
begin
  inherited Create;

  HttpLogger := THttpLogger.Create();
  HttpLogger.OnNewLogLineProc :=
           procedure(Sender: TObject; const LogLine: string)
           begin
             WriteLn(LogLine);
           end;
  FServer := TGHTTPSServer.Create(nil, 8443, 200, HttpLogger);
  CreateRandomFile(TPath.Combine(FServer.BaseDirectory,'test02.dat'));

  FServer.ConfigureJWT('1234567890abc', 'GHttpsJWTServer', 60);
  FServer.AddEndpoint('/api/token', 'POST', GetTokenRequest,
                                          atNone, []);
  FServer.AddEndpoint('/api/getfilelist', 'GET', GetFileListRequest,
                                           atJWTBearer, []);
  FServer.AddEndpoint('/api/getfile', 'GET', GetFileRequest,
                                           atJWTBearer, []);
  FServer.AddEndpoint('/api/postfile', 'POST', PostFileRequest,
                                           atJWTBearer, []);
  FServer.AddEndpoint('/api/uploadfile', 'POST', UpladFileRequest,
                                           atJWTBearer, []);
end;


destructor TGHttpsJWTServer.Destroy;
begin
  FServer.Free;
  HttpLogger.free;
  inherited;
end;

procedure TGHttpsJWTServer.CreateRandomFile(const FileName: string);
const
  BUFFER_SIZE = 65536;
  TARGET_SIZE = 10 * 1024 * 1024;
var
  FileStream: TFileStream;
  Buffer: array of Byte;
  BytesToWrite: Int64;
  BytesWritten: Integer;
begin
  if not FileExists(FileName) then
  begin
    SetLength(Buffer, BUFFER_SIZE);
    FillChar(Buffer[0], BUFFER_SIZE, 0);
    FileStream := TFileStream.Create(FileName, fmCreate);
    try
      BytesToWrite := TARGET_SIZE;
      while BytesToWrite > 0 do
      begin
        BytesWritten := Min(BytesToWrite, BUFFER_SIZE);
        FileStream.Write(Buffer[0], BytesWritten);
        Dec(BytesToWrite, BytesWritten);
      end;
    finally
      FileStream.Free;
    end;
  end;
end;

procedure TGHttpsJWTServer.GetTokenRequest(Sender: TObject;
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

              AResponseBuilder.SetStatus(200, 'OK');
              var rejson := ResponseJson.Format(2);
              AResponseBuilder.AddTextContent('response', 'application/json', rejson);
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

procedure TGHttpsJWTServer.GetFileListRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
var
  responseJson: TJSONObject;
  fileArray: TJSONArray;
  FileName: string;
begin
  try
    ResponseJson := TJSONObject.Create;
    try
      fileArray := TJSONArray.Create;
      for FileName in TDirectory.GetFiles(AServer.BaseDirectory) do
        fileArray.Add(TPath.GetFileName(FileName));
      ResponseJson.AddPair('filelist', fileArray);
      AResponseBuilder.SetStatus(200, 'OK');
      AResponseBuilder.AddTextContent('response', 'application/json', ResponseJson.Format(2));
    finally
      ResponseJson.Free;
    end;
  except
    on E: Exception do
    begin
      AResponseBuilder.SetStatus(500, 'Internal Server Error');
      AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"%s"}', [E.Message]));
    end;
  end;
end;

procedure TGHttpsJWTServer.GetFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
var
  fileName, filePath: string;
  RegEx: TRegEx;
  FileStream: TFileStream;
  fileSize: Int64;
  fileData: TBytes;
begin
  try
    fileName := ARequestParser.GetParam('filename');
    fileName := TNetEncoding.URL.Decode(fileName);
    RegEx := TRegEx.Create('[<>''"%\\\{\}\[\]\^`]');
    if RegEx.IsMatch(fileName) then
       fileName := ''
    else
      fileName := TPath.GetFileName(fileName);
   if Length(fileName) > 0 then
    begin
      filePath := AServer.BaseDirectory + FileName;
      if not TFile.Exists(filePath) then
      begin
        AResponseBuilder.SetStatus(404, 'File not found in the folder');
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"File does not exist"}');
        exit;
      end;
      FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
      try
        FileSize := FileStream.Size;
        SetLength(FileData, FileSize);
        if FileSize > 0 then
           FileStream.ReadBuffer(FileData[0], FileSize);

        var FileExt := LowerCase(ExtractFileExt(FileName));
        var ContentType := AServer.GetMimeType(FileExt);

        AResponseBuilder.SetStatus(200);
        AResponseBuilder.AddHeader('Content-Disposition', 'attachment; filename="' + FileName + '"');
        AResponseBuilder.AddBinaryContent('file', ContentType, FileData);
      finally
        FileStream.Free;
      end;
    end else
    begin
      AResponseBuilder.SetStatus(400, 'Bad Request');
      AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid parameter"}');
    end;
  except
    on E: Exception do
    begin
      AResponseBuilder.SetStatus(500, 'Internal Server Error');
      AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"%s"}', [E.Message]));
    end;
  end;
end;

procedure TGHttpsJWTServer.PostFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
var
  fileName, filePath: string;
  RegEx: TRegEx;
  FileStream: TFileStream;
  fileSize: Int64;
  fileData: TBytes;
  RequestBody: string;
  JsonObj: TJSONObject;
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
      JsonObj := TJSONObject.ParseJSONValue(RequestBody) as TJSONObject;
      if not Assigned(JsonObj) then
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid JSON format"}');
        Exit;
      end;

      try
        fileName := JsonObj.GetValue<string>('filename', '');
        if fileName = '' then
        begin
          AResponseBuilder.SetStatus(400, 'Bad Request');
          AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Missing filename parameter"}');
          Exit;
        end;
      finally
        JsonObj.Free;
      end;
    except
      on E: Exception do
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"JSON parsing error: %s"}', [E.Message]));
        Exit;
      end;
    end;
    fileName := TNetEncoding.URL.Decode(fileName);
    RegEx := TRegEx.Create('[<>''"%\\\{\}\[\]\^`]');
    if RegEx.IsMatch(fileName) then
       fileName := ''
    else
      fileName := TPath.GetFileName(fileName);
    if Length(fileName) > 0 then
    begin
      filePath := TPath.Combine(AServer.BaseDirectory, FileName);
      if not TFile.Exists(filePath) then
      begin
        AResponseBuilder.SetStatus(404, 'File not found in the folder');
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"File does not exist"}');
        Exit;
      end;
      FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
      try
        FileSize := FileStream.Size;
        SetLength(FileData, FileSize);
        if FileSize > 0 then
           FileStream.ReadBuffer(FileData[0], FileSize);
        var FileExt := LowerCase(ExtractFileExt(FileName));
        var ContentType := AServer.GetMimeType(FileExt);
        AResponseBuilder.SetStatus(200);
        AResponseBuilder.AddHeader('Content-Disposition', 'attachment; filename="' + FileName + '"');
        AResponseBuilder.AddBinaryContent('file', ContentType, FileData);
      finally
        FileStream.Free;
      end;
    end else
    begin
      AResponseBuilder.SetStatus(400, 'Bad Request');
      AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid filename parameter"}');
    end;
  except
    on E: Exception do
    begin
      AResponseBuilder.SetStatus(500, 'Internal Server Error');
      AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"%s"}', [E.Message]));
    end;
  end;
end;


procedure TGHttpsJWTServer.UpladFileRequest(Sender: TObject;
                              ARequestParser: THTTPRequestParser;
                              AResponseBuilder: THTTPResponseBuilder;
                              AServer: TGHTTPServer);
var
  fileName: string;
  RegEx: TRegEx;
  FileStream: TFileStream;
  fileSize: Int64;
  fileData: TBytes;
  info: string;
  JsonObj: TJSONObject;
  UploadedFile: THTTPMultipartFile;
begin
  try
    info := ARequestParser.GetParam('info');
    if info = '' then
    begin
      AResponseBuilder.SetStatus(400, 'Bad Request');
      AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Empty request body"}');
      Exit;
    end;
    try
      JsonObj := TJSONObject.ParseJSONValue(info) as TJSONObject;
      if not Assigned(JsonObj) then
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid JSON format"}');
        Exit;
      end;

      try
        var description := JsonObj.GetValue<string>('description', '');
        if description = '' then
        begin
          AResponseBuilder.SetStatus(400, 'Bad Request');
          AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Missing description"}');
          Exit;
        end;
        var username := JsonObj.GetValue<string>('username', '');
        if description = '' then
        begin
          AResponseBuilder.SetStatus(400, 'Bad Request');
          AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Missing username"}');
          Exit;
        end;

        UploadedFile := ARequestParser.GetFile('file');
        if UploadedFile = nil then
        begin
           AResponseBuilder.SetStatus(404, 'File not found in body');
           AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"File does not exist"}');
           Exit;
        end;
        fileName := UploadedFile.Filename;
        fileName := TNetEncoding.URL.Decode(fileName);
        RegEx := TRegEx.Create('[<>''"%\\\{\}\[\]\^`]');
        if RegEx.IsMatch(fileName) then
           fileName := ''
        else
          fileName := TPath.GetFileName(fileName);
        if Length(fileName) = 0 then
        begin
          AResponseBuilder.SetStatus(404, 'File name not found in body');
          AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"File name not found in body"}');
          Exit;
        end;
        var filepath := TPath.Combine(AServer.BaseDirectory,FileName);
        FileStream := TFileStream.Create(filepath, fmCreate);
        try
          var SuccessMessage := '';
          if UploadedFile.IsStreaming then
          begin
            UploadedFile.Stream.Position := 0;
            FileStream.CopyFrom(UploadedFile.Stream, UploadedFile.Stream.Size);
            SuccessMessage := Format('File %s uploaded successfully (%d bytes).',
                                        [ExtractFileName(FilePath), UploadedFile.Stream.Size]);
          end else
          begin
            if Length(UploadedFile.Data) > 0 then
               FileStream.WriteBuffer(UploadedFile.Data[0], Length(UploadedFile.Data));
            SuccessMessage := Format('File %s uploaded successfully (%d bytes).',
                                        [ExtractFileName(FilePath), Length(UploadedFile.Data)]);
          end;
          var descriptionlist := TStringList.Create();
          try
            descriptionlist.Add('description = ' + description);
            descriptionlist.Add('username = ' + username);
            descriptionlist.SaveToFile(TPath.Combine(AServer.BaseDirectory, filename + '.txt'));
          finally
            descriptionlist.free;
          end;

          AResponseBuilder.SetStatus(200);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', '{"uploadfile": "'+ SuccessMessage +'"}');
        finally
          FileStream.Free;
        end;
      finally
        JsonObj.Free;
      end;
    except
      on E: Exception do
      begin
        AResponseBuilder.SetStatus(400, 'Bad Request');
        AResponseBuilder.AddTextContent('error', 'application/json', Format('{"error":"JSON parsing error: %s"}', [E.Message]));
        Exit;
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

procedure TGHttpsJWTServer.Start;
begin
  try
    WriteLn('=======================================');
    WriteLn('     GRestSvrJWTPrj_2');
    WriteLn('=======================================');
    WriteLn('Server running on https://localhost:8443');
    WriteLn;
    WriteLn('Available endpoints:');
    WriteLn('1. POST /api/token - Generate JWT token');
    WriteLn('   - Send JSON body with: {"username":"admin","password":"admin"}');
    WriteLn('2. GET /api/getfilelist - Get file list');
    WriteLn('   - Send JSON body with: {"filelist":["1.txt","2.txt"]}');
    WriteLn('3. GET /api/getfile - Download file ');
    WriteLn('   - Download file');
    WriteLn('4. POST /api/postfile - Download file ');
    WriteLn('   - Download file');
    WriteLn('5. POST /api/upladfile - Upload file ');
    WriteLn('   - Send file');
    WriteLn;
    WriteLn('Press Ctrl+C to stop the server');
    WriteLn('=======================================');
    WriteLn;

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
    Application := TGHttpsJWTServer.Create;
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
