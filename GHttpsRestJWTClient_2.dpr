program GHttpsRestJWTClient_2;
{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.NetEncoding,
  System.IOUtils,
  System.Math,
  System.Net.Mime,
  IdHTTP,
  IdSSLOpenSSL,
  IdMultipartFormData,
  IdGlobal,
  IdCookieManager;

const
  HOST_URL = 'https://localhost:8443';
  USERNAME = 'admin';
  PASSWORD = 'admin';

type
  TValidate = class
  public
    class procedure ValidateServerCertificate(const Sender: TObject;
      const ARequest: TURLRequest; const Certificate: TCertificate;
      var Accepted: Boolean);
  end;

class procedure TValidate.ValidateServerCertificate(const Sender: TObject;
  const ARequest: TURLRequest; const Certificate: TCertificate;
  var Accepted: Boolean);
begin
  Accepted := True;
end;

function CreateHTTPClient: THTTPClient;
begin
  Result := THTTPClient.Create;
  Result.SecureProtocols := [THTTPSecureProtocol.TLS1, THTTPSecureProtocol.TLS11, THTTPSecureProtocol.TLS12];
  Result.OnValidateServerCertificate := TValidate.ValidateServerCertificate;
  Result.ConnectionTimeout := 14000;
  Result.ResponseTimeout := 14000;
end;

function CreateLoginJSON(const AUsername, APassword: string): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('username', AUsername);
  Result.AddPair('password', APassword);
end;

function GetJWTToken(const AHttpClient: THTTPClient;
  const AHostURL, AUsername, APassword: string): string;
var
  LoginJson, ResponseJson: TJSONObject;
  Response: IHTTPResponse;
begin
  Result := '';

  LoginJson := CreateLoginJSON(AUsername, APassword);
  try
    try
      Response := AHttpClient.Post(
        AHostURL + '/api/token',
        TStringStream.Create(LoginJson.ToJSON),
        nil,
        TNetHeaders.Create(TNameValuePair.Create('Content-Type', 'application/json'))
      );

      WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
      WriteLn('Response: ', Response.ContentAsString);
      WriteLn;

      if Response.StatusCode = 200 then
      begin
        ResponseJson := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
        try
          if Assigned(ResponseJson) then
          begin
            Result := ResponseJson.GetValue<string>('token', '');
            if Result <> '' then
              WriteLn('JWT Token obtained successfully!')
            else
              WriteLn('Error: Token not found in response.');
          end
          else
            WriteLn('Error: Invalid JSON response.');
        finally
          ResponseJson.Free;
        end;
      end
      else
        WriteLn('Error: Could not obtain token. Check if server is running.');
    except
      on E: Exception do
      begin
        WriteLn('Error obtaining token: ', E.Message);
        Result := '';
      end;
    end;
  finally
    LoginJson.Free;
  end;
end;

procedure GetFileListEndpoint(const AHttpClient: THTTPClient;
  const AHostURL, AToken: string; const AEndpoint: string);
var
  Response: IHTTPResponse;
  Headers: TNetHeaders;
begin
  try
    if AToken <> '' then
      Headers := TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer ' + AToken))
    else
      Headers := nil;

    Response := AHttpClient.Get(AHostURL + AEndpoint, nil, Headers);

    WriteLn('-----------------------------------------');
    WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
    WriteLn(Response.StatusText);
    WriteLn('-----------------------------------------');
    WriteLn('Response: ', Response.ContentAsString);
    WriteLn;
  except
    on E: Exception do
      WriteLn('Error endpoint: ', E.Message);
  end;
end;

function GetFileName(const ABasePath, AFileName: string): string;
var
  FileExt, BaseName, NewFileName: string;
  TimeStamp: string;
  Counter: Integer;
begin
  FileExt := ExtractFileExt(AFileName);
  BaseName := ChangeFileExt(AFileName, '');
  TimeStamp := FormatDateTime('yyyymmdd_hhnnss', Now);
  NewFileName := Format('%s_%s%s', [BaseName, TimeStamp, FileExt]);
  Result := TPath.Combine(ABasePath, NewFileName);
  Counter := 1;
  while TFile.Exists(Result) do
  begin
    NewFileName := Format('%s_%s_%d%s', [BaseName, TimeStamp, Counter, FileExt]);
    Result := TPath.Combine(ABasePath, NewFileName);
    Inc(Counter);
  end;
end;

procedure GetFileEndpoint(const AHttpClient: THTTPClient;
  const AHostURL, AToken: string; const AEndpoint: string);
var
  Response: IHTTPResponse;
  Headers: TNetHeaders;
  OutputPath: string;
  DownloadDir: string;
  FileStream: TFileStream;
  ErrorMsg: string;
begin
  try
    if AToken <> '' then
      Headers := TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer ' + AToken))
    else
      Headers := nil;
    Response := AHttpClient.Get(AHostURL + AEndpoint, nil, Headers);
    var FileName := '';
    var StatusCode := Response.StatusCode;
    if StatusCode = 401 then
      WriteLn('Authentication failed. Token may be expired.')
    else if StatusCode = 403 then
      WriteLn('Access denied. Insufficient permissions.')
    else if StatusCode = 404 then
    begin
      WriteLn('File not found on server.');
      ErrorMsg := Response.ContentAsString;
      if ErrorMsg <> '' then
      begin
         WriteLn('Error details: ', ErrorMsg);
      end;
    end
    else if (StatusCode < 200) or (StatusCode >= 300) then
    begin
      ErrorMsg := Response.ContentAsString;
      if ErrorMsg <> '' then
      begin
        WriteLn('Server error: ', StatusCode, ' - ', ErrorMsg)
      end
      else
        WriteLn('Server returned error code: ', StatusCode, ' ', Response.StatusText);
    end
    else if StatusCode = 200 then
    begin
      if not Assigned(Response.ContentStream) then
      begin
        WriteLn('Invalid response: content stream is missing.');
        Exit;
      end;
      for var Header in Response.Headers do
      begin
        if Header.Name.ToLower = 'content-disposition' then
        begin
          var DispositionValue := Header.Value;
          var FileNamePos := Pos('filename="', DispositionValue);
          if FileNamePos > 0 then
          begin
            FileNamePos := FileNamePos + 10;
            var EndQuotePos := Pos('"', DispositionValue, FileNamePos);
            if EndQuotePos > 0 then
              FileName := Copy(DispositionValue, FileNamePos, EndQuotePos - FileNamePos);
          end;
          Break;
        end;
      end;
      DownloadDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'download');
      if not DirectoryExists(DownloadDir) then
        CreateDir(DownloadDir);
      OutputPath := GetFileName(DownloadDir, FileName);
      FileStream := TFileStream.Create(OutputPath, fmCreate);
      try
        if Response.ContentStream.Size > 0 then
        begin
          Response.ContentStream.Position := 0;
          FileStream.CopyFrom(Response.ContentStream, Response.ContentStream.Size);
          WriteLn('File downloaded to: ', OutputPath);
        end
        else
          WriteLn('Warning: file is empty');
      finally
        FileStream.Free;
      end;
    end
    else
      WriteLn('Unexpected response: ', Response.StatusCode, ' ', Response.StatusText);
  except
    on E: Exception do
      WriteLn('Error downloading file: ', E.Message);
  end;
end;

procedure PostFileEndpoint(const AHttpClient: THTTPClient;
  const AHostURL, AToken: string; const AEndpoint: string; const filename:string);
var
  Response: IHTTPResponse;
  Headers: TNetHeaders;
  OutputPath: string;
  DownloadDir: string;
  FileStream: TFileStream;
  ErrorMsg, ErrorJson: string;
  JsonObj: TJSONObject;
  JsonValue: TJSONValue;
  RequestBody: TStringStream;
begin
  try
    RequestBody := TStringStream.Create('{"filename": "' + filename + '"}');
    try
      if AToken <> '' then
      Headers := TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer ' + AToken))
      else
        Headers := nil;
      Response := AHttpClient.Post(AHostURL + AEndpoint, RequestBody, nil, Headers);
      var StatusCode := Response.StatusCode;
      if StatusCode = 401 then
        WriteLn('Authentication failed. Token may be expired.')
      else if StatusCode = 403 then
        WriteLn('Access denied. Insufficient permissions.')
      else if StatusCode = 404 then
      begin
        WriteLn('File not found on server.');
        ErrorJson := Response.ContentAsString;
        if ErrorJson <> '' then
        begin
          try
            JsonObj := TJSONObject.ParseJSONValue(ErrorJson) as TJSONObject;
            if Assigned(JsonObj) then
            begin
              try
                JsonValue := JsonObj.GetValue('error');
                if Assigned(JsonValue) then
                  WriteLn('Error details: ', JsonValue.Value);
              finally
                JsonObj.Free;
              end;
            end;
          except
            WriteLn(ErrorJson);
          end;
        end;
      end
      else if (StatusCode < 200) or (StatusCode >= 300) then
      begin
        ErrorMsg := Response.ContentAsString;
        if ErrorMsg <> '' then
          WriteLn('Server error: ', StatusCode, ' - ', ErrorMsg)
        else
          WriteLn('Server returned error code: ', StatusCode, ' ', Response.StatusText);
      end
      else if StatusCode = 200 then
      begin
        if not Assigned(Response.ContentStream) then
        begin
          WriteLn('Invalid response: content stream is missing.');
          Exit;
        end;

        DownloadDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'download');
        if not DirectoryExists(DownloadDir) then
          CreateDir(DownloadDir);
        OutputPath := GetFileName(DownloadDir, FileName);
        FileStream := TFileStream.Create(OutputPath, fmCreate);
        try
          if Response.ContentStream.Size > 0 then
          begin
            Response.ContentStream.Position := 0;
            FileStream.CopyFrom(Response.ContentStream, Response.ContentStream.Size);
            WriteLn('File downloaded to: ', OutputPath);
          end
          else
            WriteLn('Warning: file is empty');
        finally
          FileStream.Free;
        end;
      end
      else
        WriteLn('Unexpected response: ', Response.StatusCode, ' ', Response.StatusText);
    finally
      RequestBody.Free;
    end;
  except
    on E: Exception do
      WriteLn('Error downloading file: ', E.Message);
  end;
end;

procedure PostUploadFileEndpoint(const AHttpClient: THTTPClient;
  const AHostURL, AToken: string; const AEndpoint: string; const filename: string);
var
  Response: IHTTPResponse;
  Headers: TNetHeaders;
  FilePath: string;
  FileStream: TFileStream;
  FormData: TMultipartFormData;
  FileSize: Int64;
begin
  try
    // Prawid³owo konstruujemy œcie¿kê do pliku
    FilePath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'download');
    FilePath := TPath.Combine(FilePath, filename);

    // Sprawdzamy, czy plik istnieje
    if not FileExists(FilePath) then
    begin
      WriteLn('Error: File not found: ', FilePath);
      Exit;
    end;

    // Sprawdzamy rozmiar pliku
    FileSize := TFile.GetSize(FilePath);
    WriteLn('File size: ', FileSize, ' bytes');
    if FileSize = 0 then
    begin
      WriteLn('Warning: File is empty (0 bytes)');
      // Mo¿esz zdecydowaæ, czy chcesz kontynuowaæ czy nie
    end;

    // Tworzymy nag³ówki z tokenem autoryzacji
    if AToken <> '' then
      Headers := TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer ' + AToken))
    else
      Headers := nil;

    // Tworzymy formularz multipart
    FormData := TMultipartFormData.Create;
    try
      // Otwieramy plik do odczytu
      FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);

      // Dodajemy plik do formularza
      FormData.AddStream('file', FileStream, filename, 'application/octet-stream');

      // Dodajemy dodatkowe informacje
      FormData.AddField('info', '{"description": "test file", "username":"admin"}');

      WriteLn('Sending file: ', filename);
      WriteLn('Endpoint: ', AHostURL + AEndpoint);

      // Wykonujemy ¿¹danie POST
      Response := AHttpClient.Post(AHostURL + AEndpoint, FormData, nil, Headers);

      // Przetwarzamy odpowiedŸ
      WriteLn('Upload Status: ', Response.StatusCode, ' ', Response.StatusText);
      if Response.StatusCode = 200 then
      begin
        WriteLn('File uploaded successfully!');
        WriteLn('Response: ', Response.ContentAsString);
      end
      else
      begin
        WriteLn('Server response: ', Response.ContentAsString);
      end;
    finally
      // FormData automatycznie zwolni FileStream, wiêc nie zwalniamy go rêcznie
      FormData.Free;
    end;
  except
    on E: Exception do
      WriteLn('Error uploading file: ', E.Message);
  end;
end;

procedure RunRestTests;
var
  HttpClient: THTTPClient;
  Token: string;
begin
  HttpClient := CreateHTTPClient;
  try
    WriteLn('=== Test GHttpsRestSvrJWTPrj ===');
    WriteLn;

    WriteLn('1. Getting JWT token...');
    Token := GetJWTToken(HttpClient, HOST_URL, USERNAME, PASSWORD);
    WriteLn('=============================================================');
    if Token <> '' then
    begin
      WriteLn('2. Get file list');
      GetFileListEndpoint(HttpClient, HOST_URL, Token, '/api/getfilelist');
    end;
    WriteLn('=============================================================');
    if Token <> '' then
    begin
      WriteLn('3. Get Download file test02.dat');
      GetFileEndpoint(HttpClient, HOST_URL, Token, '/api/getfile?filename=' +
                                                   TNetEncoding.URL.Encode('test02.dat'));
    end;
    WriteLn('=============================================================');
    if Token <> '' then
    begin
      WriteLn('4. Post Download file test02.dat');
      PostFileEndpoint(HttpClient, HOST_URL, Token, '/api/postfile', 'test02.dat');
    end;
    WriteLn('=============================================================');
    if Token <> '' then
    begin
      WriteLn('5. Post Upload file test01.dat');
      PostUploadFileEndpoint(HttpClient, HOST_URL, Token, '/api/uploadfile', 'test01.dat');
    end;
    WriteLn('=============================================================');


  finally
    HttpClient.Free;
  end;
end;

function CrateDownloadDirectory: boolean;
var
  ExePath, DownloadDir: string;
begin
  Result := false;
  ExePath := ExtractFilePath(ParamStr(0));
  DownloadDir := TPath.Combine(ExePath, 'download');
  if not TDirectory.Exists(DownloadDir) then
  begin
    try
      TDirectory.CreateDirectory(DownloadDir);
      WriteLn('Created download directory: ', DownloadDir);
      Result := true;
    except
      on E: Exception do
      begin
        Result := false;
        WriteLn('Error creating download directory: ', E.Message);
      end;
    end;
  end else Result := true;
end;

procedure CreateRandomFile(const FileName: string);
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


begin
  try
    if not CrateDownloadDirectory() then
       exit;
    var filenamepath := TPath.GetFullPath(TPath.GetDirectoryName(GetModuleName(0)));
    filenamepath := TPath.Combine(filenamepath, 'download');
    filenamepath := TPath.Combine(filenamepath, 'test01.dat');
    CreateRandomFile(filenamepath);
    RunRestTests;

    WriteLn;
    WriteLn('=== End of test ===');
    WriteLn('Press Enter to exit...');
    ReadLn;
  except
    on E: Exception do
    begin
      WriteLn('Unexpected error: ', E.Message);
      ReadLn;
    end;
  end;
end.
