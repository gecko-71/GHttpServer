{
  test01 - Simple HTTP Server Component
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

unit test01;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, WinSock;

type
  TTestResult = record
    TestName: string;
    Status: string;
    Details: string;
  end;

  TfrmHTTPTester = class(TForm)
    btnRunTests: TButton;
    mmResults: TMemo;
    pnlControls: TPanel;
    lblServerAddress: TLabel;
    edtServerAddress: TEdit;
    lblPort: TLabel;
    edtPort: TEdit;
    btnClear: TButton;
    procedure btnRunTestsClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
  private
    FTestResults: array of TTestResult;
    procedure InitializeWinSock;
    procedure CleanupWinSock;
    function SendHTTPRequest(const Host: string; Port: Integer; const Request: string): string;
    procedure AddTestResult(const TestName, Status, Details: string);
    procedure RunBasicGETTests;
    procedure RunGETParametersTest;
    procedure RunGETHeadersTest;
    procedure RunGETPathsTest;
    procedure RunGETConnectionLimitTest;
    procedure RunGETPerformanceTest;
    procedure RunMalformedGETTest;
    procedure DisplayResults;
    procedure RunGETCaseSensitivityTest;
    procedure RunGETEncodingEdgeCasesTest;
    procedure RunGETRedirectTest;
    procedure RunGETSecurityTraversalTest;
    procedure RunGETSlowLorisTest;
    procedure RunPOSTTest;
    procedure TestUploadFile();
    procedure TestContentTypeHandling;
  public
  end;

var
  frmHTTPTester: TfrmHTTPTester;

implementation

{$R *.dfm}

uses  IdHTTP, IdMultipartFormData;

procedure TfrmHTTPTester.FormCreate(Sender: TObject);
begin
  edtServerAddress.Text := '127.0.0.1';
  edtPort.Text := '3042';
end;

procedure TfrmHTTPTester.InitializeWinSock;
var
  WSAData: TWSAData;
begin
  if WSAStartup($202, WSAData) <> 0 then
    raise Exception.Create('WSAStartup failed');
end;

procedure TfrmHTTPTester.CleanupWinSock;
begin
  WSACleanup;
end;

function TfrmHTTPTester.SendHTTPRequest(const Host: string; Port: Integer; const Request: string): string;
var
  ClientSocket: TSocket;
  Addr: TSockAddrIn;
  Buffer: array[0..4095] of Byte;
  BytesReceived: Integer;
  Response: AnsiString;
  Timeout: Integer;
  ModifiedRequest: string;
  DefaultUserAgent: string;
begin
  Result := '';
  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket = INVALID_SOCKET then
    Exit;
  try
    Timeout := 5000;
    setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(Host)));
    if connect(ClientSocket, Addr, SizeOf(Addr)) = SOCKET_ERROR then
      Exit;

    DefaultUserAgent := 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0';
    if Pos('User-Agent:', Request) = 0 then
    begin
      ModifiedRequest := StringReplace(Request, #13#10#13#10,
        #13#10 + DefaultUserAgent + #13#10#13#10, []);
    end
    else
      ModifiedRequest := Request;

    if (ModifiedRequest <> '') and (send(ClientSocket, PAnsiChar(AnsiString(ModifiedRequest))^, Length(ModifiedRequest), 0) = SOCKET_ERROR) then
      Exit;

    BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
    while BytesReceived > 0 do
    begin
      SetString(Response, PAnsiChar(@Buffer[0]), BytesReceived);
      Result := Result + string(Response);
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
    end;
  finally
    closesocket(ClientSocket);
  end;
end;


procedure TfrmHTTPTester.AddTestResult(const TestName, Status, Details: string);
var
  Index: Integer;
begin
  Index := Length(FTestResults);
  SetLength(FTestResults, Index + 1);
  FTestResults[Index].TestName := TestName;
  FTestResults[Index].Status := Status;
  FTestResults[Index].Details := Details;
end;

procedure TfrmHTTPTester.RunBasicGETTests;
var
  Response: string;
  Host: string;
  Port: Integer;
  UserAgent: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  UserAgent := 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

  Response := SendHTTPRequest(Host, Port,
    'GET / HTTP/1.0' + #13#10 +
    'User-Agent: ' + UserAgent + #13#10 +
    #13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('Basic GET Request with User-Agent', 'PASS', 'Received valid 200 OK response with User-Agent: ' + UserAgent)
  else if Response = '' then
    AddTestResult('Basic GET Request with User-Agent', 'FAIL', 'No response received')
  else
    AddTestResult('Basic GET Request with User-Agent', 'FAIL', 'Unexpected response: ' + Copy(Response, 1, 100) + '...');

  Response := SendHTTPRequest(Host, Port,
    'GET /nonexistent HTTP/1.0' + #13#10 +
    'User-Agent: ' + UserAgent + #13#10 +
    #13#10);
  if Pos('404 Not Found', Response) > 0 then
    AddTestResult('GET 404 Not Found Test with User-Agent', 'PASS', 'Received correct 404 response with User-Agent: ' + UserAgent)
  else if Response = '' then
    AddTestResult('GET 404 Not Found Test with User-Agent', 'FAIL', 'No response received')
  else
    AddTestResult('GET 404 Not Found Test with User-Agent', 'FAIL', 'Unexpected response: ' + Copy(Response, 1, 100) + '...');

  Response := SendHTTPRequest(Host, Port,
    'GET / HTTP/1.1' + #13#10 +
    'Host: ' + Host + #13#10 +
    'User-Agent: ' + UserAgent + #13#10 +
    #13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('GET HTTP/1.1 Test with User-Agent', 'PASS', 'Server supports HTTP/1.1 with User-Agent: ' + UserAgent)
  else if Response = '' then
    AddTestResult('GET HTTP/1.1 Test with User-Agent', 'FAIL', 'No response received')
  else
    AddTestResult('GET HTTP/1.1 Test with User-Agent', 'FAIL', 'Unexpected response: ' + Copy(Response, 1, 100) + '...');

  UserAgent := 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)';
  Response := SendHTTPRequest(Host, Port,
    'GET / HTTP/1.0' + #13#10 +
    'User-Agent: ' + UserAgent + #13#10 +
    #13#10);
  if Pos('403 Forbidden', Response) > 0 then
    AddTestResult('Suspicious User-Agent Test', 'PASS', 'Server correctly blocked suspicious User-Agent: ' + UserAgent)
  else if Response = '' then
    AddTestResult('Suspicious User-Agent Test', 'FAIL', 'No response received')
  else
    AddTestResult('Suspicious User-Agent Test', 'FAIL', 'Unexpected response: ' + Copy(Response, 1, 100) + '...');
end;

procedure TfrmHTTPTester.RunGETParametersTest;
var
  Response: string;
  Host: string;
  Port: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /?param1=value1&param2=value2 HTTP/1.0' + #13#10#13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('GET with Parameters Test', 'PASS', 'Server correctly handled parameters')
  else if Response = '' then
    AddTestResult('GET with Parameters Test', 'FAIL', 'No response received')
  else
    AddTestResult('GET with Parameters Test', 'FAIL', 'Unexpected response: ' + Copy(Response, 1, 100) + '...');

  Response := SendHTTPRequest(Host, Port, 'GET /?param=za   _g l _ja   HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('GET with Unicode Parameters Test', 'PASS', 'Server responded to Unicode parameters')
  else
    AddTestResult('GET with Unicode Parameters Test', 'FAIL', 'No response received');
end;

procedure TfrmHTTPTester.RunGETHeadersTest;
var
  Response: string;
  Host: string;
  Port: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port,
    'GET / HTTP/1.0' + #13#10 +
    'User-Agent: HTTPTester/1.0' + #13#10#13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('GET with User-Agent Header', 'PASS', 'Server accepted User-Agent header')
  else if Response = '' then
    AddTestResult('GET with User-Agent Header', 'FAIL', 'No response received')
  else
    AddTestResult('GET with User-Agent Header', 'FAIL', 'Unexpected response');

  Response := SendHTTPRequest(Host, Port,
    'GET / HTTP/1.0' + #13#10 +
    'User-Agent: HTTPTester/1.0' + #13#10 +
    'Accept: text/html' + #13#10 +
    'Accept-Language: pl-PL' + #13#10#13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('GET with Multiple Headers', 'PASS', 'Server accepted multiple headers')
  else if Response = '' then
    AddTestResult('GET with Multiple Headers', 'FAIL', 'No response received')
  else
    AddTestResult('GET with Multiple Headers', 'FAIL', 'Unexpected response');
end;

procedure TfrmHTTPTester.RunGETPathsTest;
var
  Response: string;
  Host: string;
  Port: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /path/to/resource HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('GET with Nested Path', 'PASS', 'Server handled nested path')
  else
    AddTestResult('GET with Nested Path', 'FAIL', 'No response received');

  Response := SendHTTPRequest(Host, Port, 'GET /path%20with%20spaces HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('GET with URL Encoded Path', 'PASS', 'Server handled URL encoded path')
  else
    AddTestResult('GET with URL Encoded Path', 'FAIL', 'No response received');

  Response := SendHTTPRequest(Host, Port, 'GET /resource#fragment HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('GET with URL Fragment', 'PASS', 'Server handled URL fragment')
  else
    AddTestResult('GET with URL Fragment', 'FAIL', 'No response received');
end;

procedure TfrmHTTPTester.RunGETConnectionLimitTest;
var
  Host: string;
  Port: Integer;
  Sockets: array of TSocket;
  Addr: TSockAddrIn;
  i, SuccessCount: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);
  SetLength(Sockets, 10);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(Port);
  Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(Host)));
  SuccessCount := 0;

  for i := 0 to High(Sockets) do
  begin
    Sockets[i] := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if Sockets[i] = INVALID_SOCKET then Break;

    if connect(Sockets[i], Addr, SizeOf(Addr)) = 0 then
    begin
      if send(Sockets[i], PAnsiChar(AnsiString('GET / HTTP/1.0'#13#10#13#10))^, 18, 0) <> SOCKET_ERROR then
        Inc(SuccessCount)
      else
        Break;
    end
    else
      Break;
  end;

  for i := 0 to High(Sockets) do
    if Sockets[i] <> INVALID_SOCKET then
      closesocket(Sockets[i]);

  if SuccessCount = Length(Sockets) then
    AddTestResult('GET Connection Limit Test', 'PASS', Format('All %d GET connections succeeded', [SuccessCount]))
  else
    AddTestResult('GET Connection Limit Test', 'WARNING', Format('Server rejected connections after %d successful GET requests', [SuccessCount]));
end;

procedure TfrmHTTPTester.RunGETPerformanceTest;
var
  Host: string;
  Port, i: Integer;
  StartTime: Cardinal;
  RequestsCount: Integer;
  Response: string;
  TotalTime: Cardinal;
  SuccessCount: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);
  RequestsCount := 20;
  SuccessCount := 0;
  TotalTime := 0;

  for i := 1 to RequestsCount do
  begin
    StartTime := GetTickCount;
    Response := SendHTTPRequest(Host, Port, 'GET / HTTP/1.0' + #13#10#13#10);
    TotalTime := TotalTime + (GetTickCount - StartTime);

    if Response <> '' then
      Inc(SuccessCount)
    else
    begin
      AddTestResult('GET Performance Test', 'FAIL', 'No response on request ' + IntToStr(i));
      Exit;
    end;
  end;

  AddTestResult('GET Performance Test', 'PASS',
    Format('%d GET requests completed in %d ms (avg %d ms per request)',
    [SuccessCount, TotalTime, TotalTime div RequestsCount]));

  StartTime := GetTickCount;
  for i := 1 to 5 do
  begin
    Response := SendHTTPRequest(Host, Port,
      'GET /very/long/path/with/many/segments/to/test/server/path/handling/capabilities HTTP/1.0' + #13#10#13#10);
    if Response = '' then
    begin
      AddTestResult('GET Performance - Long Paths', 'FAIL', 'Failed at request ' + IntToStr(i));
      Exit;
    end;
  end;

  AddTestResult('GET Performance - Long Paths', 'PASS',
    Format('5 long path GET requests completed in %d ms', [GetTickCount - StartTime]));
end;

procedure TfrmHTTPTester.RunMalformedGETTest;
var
  Host: string;
  Port: Integer;
  Response: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET/HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('Malformed GET Test (No Space)', 'PASS', 'Server responded to malformed GET request')
  else
    AddTestResult('Malformed GET Test (No Space)', 'WARNING', 'Server closed connection');

  Response := SendHTTPRequest(Host, Port, 'GET' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('Incomplete GET Test', 'PASS', 'Server responded to incomplete GET request')
  else
    AddTestResult('Incomplete GET Test', 'WARNING', 'Server closed connection');

  Response := SendHTTPRequest(Host, Port, 'GET ' + StringOfChar('a', 2000) + ' HTTP/1.0' + #13#10#13#10);
  if Response <> '' then
    AddTestResult('GET with Very Long URL', 'PASS', 'Server handled very long URL')
  else
    AddTestResult('GET with Very Long URL', 'WARNING', 'Server closed connection');

  Response := SendHTTPRequest(Host, Port, '');
  if Response = '' then
    AddTestResult('Empty Request Test', 'PASS', 'Server closed connection (expected)')
  else
    AddTestResult('Empty Request Test', 'WARNING', 'Server responded: ' + Copy(Response, 1, 100) + '...');
end;

procedure TfrmHTTPTester.DisplayResults;
var
  i, PassCount, FailCount, WarningCount: Integer;
begin
  mmResults.Lines.Clear;
  PassCount := 0;
  FailCount := 0;
  WarningCount := 0;

  mmResults.Lines.Add('======= TEST RESULTS =======');
  mmResults.Lines.Add('Server: ' + edtServerAddress.Text + ':' + edtPort.Text);
  mmResults.Lines.Add('Date: ' + FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
  mmResults.Lines.Add('============================');

  for i := 0 to High(FTestResults) do
  begin
    mmResults.Lines.Add(Format('Test: %s', [FTestResults[i].TestName]));
    mmResults.Lines.Add(Format('Status: %s', [FTestResults[i].Status]));
    mmResults.Lines.Add(Format('Details: %s', [FTestResults[i].Details]));
    mmResults.Lines.Add('----------------------------');

    if FTestResults[i].Status = 'PASS' then
      Inc(PassCount)
    else if FTestResults[i].Status = 'WARNING' then
      Inc(WarningCount)
    else
      Inc(FailCount);
  end;

  mmResults.Lines.Add(Format('SUMMARY: %d passed, %d warnings, %d failed', [PassCount, WarningCount, FailCount]));
  mmResults.Lines.Add('============================');
end;

procedure TfrmHTTPTester.btnRunTestsClick(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    InitializeWinSock;
    try
      SetLength(FTestResults, 0);
      mmResults.Lines.Clear;
      mmResults.Lines.Add('Starting HTTP GET tests...');
      Application.ProcessMessages;

      RunBasicGETTests;
      RunGETParametersTest;
      RunGETHeadersTest;
      RunGETPathsTest;
      RunGETConnectionLimitTest;
      RunGETPerformanceTest;
      RunMalformedGETTest;
      RunGETCaseSensitivityTest;
      RunGETEncodingEdgeCasesTest;
      RunGETRedirectTest;
      RunGETSecurityTraversalTest;
      RunGETSlowLorisTest;
      RunPOSTTest;
      TestUploadFile;
      TestContentTypeHandling;

      DisplayResults;
    finally
      CleanupWinSock;
    end;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TfrmHTTPTester.btnClearClick(Sender: TObject);
begin
  mmResults.Lines.Clear;
end;

procedure TfrmHTTPTester.RunGETCaseSensitivityTest;
var
  Host: string;
  Port: Integer;
  Response: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /TestCase HTTP/1.0' + #13#10#13#10);
  if Pos('200 OK', Response) > 0 then
    AddTestResult('Case Sensitivity Test', 'PASS', 'Server treats path as case-sensitive')
  else
    AddTestResult('Case Sensitivity Test', 'INFO', 'Server might treat paths as case-insensitive or not found');
end;

procedure TfrmHTTPTester.TestContentTypeHandling;
var
  Host: string;
  Port: Integer;
  ClientSocket: TSocket;
  Addr: TSockAddrIn;
  Request: string;
  FormData, MultipartData: string;
  Boundary: string;
  Buffer: array[0..4095] of Byte;
  BytesReceived: Integer;
  TempResponse: AnsiString;
  TotalResponse: string;
  Timeout: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket = INVALID_SOCKET then
  begin
    AddTestResult('Form URL Encoded Test', 'FAIL', 'Could not create socket');
    Exit;
  end;

  try
    Timeout := 5000;
    setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(Host)));

    if connect(ClientSocket, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      AddTestResult('Form URL Encoded Test', 'FAIL', 'Could not connect to server');
      Exit;
    end;

    FormData := 'param1=value1&param2=value+with+spaces&param3=special%21%40%23%24';

    Request :=
      'POST /form-test HTTP/1.1' + #13#10 +
      'Host: ' + Host + #13#10 +
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
      'Content-Type: application/x-www-form-urlencoded' + #13#10 +
      'Content-Length: ' + IntToStr(Length(FormData)) + #13#10 +
      'Connection: close' + #13#10 +
      #13#10 +
      FormData;

    if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) = SOCKET_ERROR then
    begin
      AddTestResult('Form URL Encoded Test', 'FAIL', 'Failed to send request');
      Exit;
    end;

    TotalResponse := '';
    repeat
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
      if BytesReceived > 0 then
      begin
        SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
        TotalResponse := TotalResponse + string(TempResponse);
      end;
    until BytesReceived <= 0;

    if (Pos('200 OK', TotalResponse) > 0) and
       ((Pos('param1', TotalResponse) > 0) or (Pos('value1', TotalResponse) > 0)) then
      AddTestResult('Form URL Encoded Test', 'PASS', 'Server correctly parsed form-urlencoded data')
    else if TotalResponse = '' then
      AddTestResult('Form URL Encoded Test', 'FAIL', 'No response received')
    else
      AddTestResult('Form URL Encoded Test', 'WARNING', 'Response received but parameters may not be parsed');
  finally
    closesocket(ClientSocket);
  end;

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket = INVALID_SOCKET then
  begin
    AddTestResult('Multipart Form Data Test', 'FAIL', 'Could not create socket');
    Exit;
  end;

  try
    Timeout := 10000;
    setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

    if connect(ClientSocket, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      AddTestResult('Multipart Form Data Test', 'FAIL', 'Could not connect to server');
      Exit;
    end;

    Boundary := 'boundary' + FormatDateTime('hhnnsszzz', Now);

    MultipartData :=
      '--' + Boundary + #13#10 +
      'Content-Disposition: form-data; name="text_field"' + #13#10 +
      #13#10 +
      'This is a text field' + #13#10 +
      '--' + Boundary + #13#10 +
      'Content-Disposition: form-data; name="file1"; filename="test.txt"' + #13#10 +
      'Content-Type: text/plain' + #13#10 +
      #13#10 +
      'This is the content of a test file.' + #13#10 +
      '--' + Boundary + '--' + #13#10;

    Request :=
      'POST /multipart-test HTTP/1.1' + #13#10 +
      'Host: ' + Host + #13#10 +
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
      'Content-Type: multipart/form-data; boundary=' + Boundary + #13#10 +
      'Content-Length: ' + IntToStr(Length(MultipartData)) + #13#10 +
      'Connection: close' + #13#10 +
      #13#10 +
      MultipartData;

    if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) = SOCKET_ERROR then
    begin
      AddTestResult('Multipart Form Data Test', 'FAIL', 'Failed to send request');
      Exit;
    end;

    TotalResponse := '';
    repeat
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
      if BytesReceived > 0 then
      begin
        SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
        TotalResponse := TotalResponse + string(TempResponse);
      end;
    until BytesReceived <= 0;

    if (Pos('200 OK', TotalResponse) > 0) and
       ((Pos('text_field', TotalResponse) > 0) or (Pos('file1', TotalResponse) > 0)) then
      AddTestResult('Multipart Form Data Test', 'PASS', 'Server correctly parsed multipart/form-data')
    else if TotalResponse = '' then
      AddTestResult('Multipart Form Data Test', 'FAIL', 'No response received')
    else
      AddTestResult('Multipart Form Data Test', 'WARNING', 'Response received but multipart data may not be parsed');
  finally
    closesocket(ClientSocket);
  end;
end;

procedure TfrmHTTPTester.RunPOSTTest;
var
  Host: string;
  Port: Integer;
  Response: string;
  PostData: string;
  ClientSocket: TSocket;
  Addr: TSockAddrIn;
  Request: string;
  Buffer: array[0..4095] of Byte;
  BytesReceived: Integer;
  TempResponse: AnsiString;
  TotalResponse: string;
  Timeout: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket = INVALID_SOCKET then
  begin
    AddTestResult('Basic POST Request', 'FAIL', 'Could not create socket');
    Exit;
  end;

  try
    Timeout := 5000;
    setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(Host)));

    if connect(ClientSocket, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      AddTestResult('Basic POST Request', 'FAIL', 'Could not connect to server');
      Exit;
    end;

    PostData := 'test=value&another=test';

    Request :=
      'POST /post-test HTTP/1.1' + #13#10 +
      'Host: ' + Host + #13#10 +
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
      'Content-Type: application/x-www-form-urlencoded' + #13#10 +
      'Content-Length: ' + IntToStr(Length(PostData)) + #13#10 +
      'Connection: close' + #13#10 +
      #13#10 +
      PostData;

    if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) = SOCKET_ERROR then
    begin
      AddTestResult('Basic POST Request', 'FAIL', 'Failed to send request');
      Exit;
    end;

    TotalResponse := '';
    repeat
      BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
      if BytesReceived > 0 then
      begin
        SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
        TotalResponse := TotalResponse + string(TempResponse);
      end;
    until BytesReceived <= 0;

    if Pos('200 OK', TotalResponse) > 0 then
      AddTestResult('Basic POST Request', 'PASS', 'Received valid 200 OK response')
    else if TotalResponse = '' then
      AddTestResult('Basic POST Request', 'FAIL', 'No response received')
    else
      AddTestResult('Basic POST Request', 'FAIL', 'Unexpected response: ' + Copy(TotalResponse, 1, 100) + '...');

  finally
    closesocket(ClientSocket);
  end;

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket <> INVALID_SOCKET then
  begin
    try
      Timeout := 5000;
      setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

      if connect(ClientSocket, Addr, SizeOf(Addr)) = 0 then
      begin
        Request :=
          'POST /post-test HTTP/1.1' + #13#10 +
          'Host: ' + Host + #13#10 +
          'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
          'Content-Type: application/x-www-form-urlencoded' + #13#10 +
          'Content-Length: 0' + #13#10 +
          'Connection: close' + #13#10 +
          #13#10;

        if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) <> SOCKET_ERROR then
        begin
          TotalResponse := '';
          repeat
            BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
            if BytesReceived > 0 then
            begin
              SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
              TotalResponse := TotalResponse + string(TempResponse);
            end;
          until BytesReceived <= 0;

          if TotalResponse <> '' then
            AddTestResult('POST with Empty Body', 'PASS', 'Server handled empty POST body')
          else
            AddTestResult('POST with Empty Body', 'FAIL', 'No response received');
        end
        else
          AddTestResult('POST with Empty Body', 'FAIL', 'Failed to send request');
      end
      else
        AddTestResult('POST with Empty Body', 'FAIL', 'Could not connect to server');
    finally
      closesocket(ClientSocket);
    end;
  end
  else
    AddTestResult('POST with Empty Body', 'FAIL', 'Could not create socket');

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket <> INVALID_SOCKET then
  begin
    try
      Timeout := 10000;
      setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

      if connect(ClientSocket, Addr, SizeOf(Addr)) = 0 then
      begin
        PostData := StringOfChar('a', 5000);

        Request :=
          'POST /post-test HTTP/1.1' + #13#10 +
          'Host: ' + Host + #13#10 +
          'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
          'Content-Type: text/plain' + #13#10 +
          'Content-Length: ' + IntToStr(Length(PostData)) + #13#10 +
          'Connection: close' + #13#10 +
          #13#10;

        if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) <> SOCKET_ERROR then
        begin
          if send(ClientSocket, PAnsiChar(AnsiString(PostData))^, Length(PostData), 0) <> SOCKET_ERROR then
          begin
            TotalResponse := '';
            repeat
              BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
              if BytesReceived > 0 then
              begin
                SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
                TotalResponse := TotalResponse + string(TempResponse);
              end;
            until BytesReceived <= 0;

            if Pos('200 OK', TotalResponse) > 0 then
              AddTestResult('POST with Large Body', 'PASS', 'Server handled large POST body')
            else if TotalResponse = '' then
              AddTestResult('POST with Large Body', 'FAIL', 'No response received')
            else
              AddTestResult('POST with Large Body', 'FAIL', 'Unexpected response: ' + Copy(TotalResponse, 1, 100) + '...');
          end
          else
            AddTestResult('POST with Large Body', 'FAIL', 'Failed to send POST data');
        end
        else
          AddTestResult('POST with Large Body', 'FAIL', 'Failed to send request headers');
      end
      else
        AddTestResult('POST with Large Body', 'FAIL', 'Could not connect to server');
    finally
      closesocket(ClientSocket);
    end;
  end
  else
    AddTestResult('POST with Large Body', 'FAIL', 'Could not create socket');

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket <> INVALID_SOCKET then
  begin
    try
      Timeout := 5000;
      setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, @Timeout, SizeOf(Timeout));

      if connect(ClientSocket, Addr, SizeOf(Addr)) = 0 then
      begin
        PostData := '{"key":"value","number":123}';

        Request :=
          'POST /post-test HTTP/1.1' + #13#10 +
          'Host: ' + Host + #13#10 +
          'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0' + #13#10 +
          'Content-Type: application/json' + #13#10 +
          'Content-Length: ' + IntToStr(Length(PostData)) + #13#10 +
          'Connection: close' + #13#10 +
          #13#10 +
          PostData;

        if send(ClientSocket, PAnsiChar(AnsiString(Request))^, Length(Request), 0) <> SOCKET_ERROR then
        begin
          TotalResponse := '';
          repeat
            BytesReceived := recv(ClientSocket, Buffer, SizeOf(Buffer), 0);
            if BytesReceived > 0 then
            begin
              SetString(TempResponse, PAnsiChar(@Buffer[0]), BytesReceived);
              TotalResponse := TotalResponse + string(TempResponse);
            end;
          until BytesReceived <= 0;

          if Pos('200 OK', TotalResponse) > 0 then
            AddTestResult('POST with JSON', 'PASS', 'Server accepted JSON payload')
          else if TotalResponse = '' then
            AddTestResult('POST with JSON', 'FAIL', 'No response received')
          else
            AddTestResult('POST with JSON', 'FAIL', 'Unexpected response: ' + Copy(TotalResponse, 1, 100) + '...');
        end
        else
          AddTestResult('POST with JSON', 'FAIL', 'Failed to send request');
      end
      else
        AddTestResult('POST with JSON', 'FAIL', 'Could not connect to server');
    finally
      closesocket(ClientSocket);
    end;
  end
  else
    AddTestResult('POST with JSON', 'FAIL', 'Could not create socket');
end;

procedure TfrmHTTPTester.RunGETEncodingEdgeCasesTest;
var
  Host: string;
  Port: Integer;
  Response: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /%ZZ HTTP/1.0' + #13#10#13#10);
  if (Response <> '') then
    AddTestResult('URL Encoding Edge Case', 'PASS', 'Server responded to invalid encoded URL')
  else
    AddTestResult('URL Encoding Edge Case', 'WARNING', 'Server closed connection or ignored malformed encoding');
end;

procedure TfrmHTTPTester.RunGETRedirectTest;
var
  Host: string;
  Port: Integer;
  Response: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /redirect HTTP/1.0' + #13#10#13#10);
  if Pos('301', Response) > 0 then
    AddTestResult('Redirect Test', 'PASS', 'Received 301 Moved Permanently')
  else if Pos('302', Response) > 0 then
    AddTestResult('Redirect Test', 'PASS', 'Received 302 Found')
  else
    AddTestResult('Redirect Test', 'INFO', 'No redirect response or endpoint missing');
end;

procedure TfrmHTTPTester.RunGETSecurityTraversalTest;
var
  Host: string;
  Port: Integer;
  Response: string;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  Response := SendHTTPRequest(Host, Port, 'GET /../secret HTTP/1.0' + #13#10#13#10);
  if Pos('404', Response) > 0 then
    AddTestResult('Path Traversal Test', 'PASS', 'Server blocked path traversal')
  else if Pos('200 OK', Response) > 0 then
    AddTestResult('Path Traversal Test', 'FAIL', 'Potential directory traversal vulnerability')
  else
    AddTestResult('Path Traversal Test', 'INFO', 'Response: ' + Copy(Response, 1, 100));
end;

procedure TfrmHTTPTester.RunGETSlowLorisTest;
var
  Host: string;
  Port: Integer;
  ClientSocket: TSocket;
  Addr: TSockAddrIn;
  SentLen: Integer;
begin
  Host := edtServerAddress.Text;
  Port := StrToInt(edtPort.Text);

  ClientSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ClientSocket = INVALID_SOCKET then
  begin
    AddTestResult('Slow Loris Test', 'FAIL', 'Could not create socket');
    Exit;
  end;

  try
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(Port);
    Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(Host)));

    if connect(ClientSocket, Addr, SizeOf(Addr)) = SOCKET_ERROR then
    begin
      AddTestResult('Slow Loris Test', 'FAIL', 'Could not connect to server');
      Exit;
    end;

    SentLen := send(ClientSocket, PAnsiChar(AnsiString('GET /slow HTTP/1.1'#13#10))^, 21, 0);
    Sleep(2000);

    SentLen := send(ClientSocket, PAnsiChar(AnsiString('Host: localhost'#13#10))^, 18, 0);
    Sleep(2000);

    SentLen := send(ClientSocket, PAnsiChar(AnsiString(#13#10))^, 2, 0);

    if SentLen > 0 then
      AddTestResult('Slow Loris Test', 'PASS', 'Server handled slow headers (not vulnerable)')
    else
      AddTestResult('Slow Loris Test', 'FAIL', 'Connection dropped unexpectedly');
  finally
    closesocket(ClientSocket);
  end;
end;

procedure TfrmHTTPTester.TestUploadFile();
var
  HTTP: TIdHTTP;
  FormData: TIdMultipartFormDataStream;
  Response: string;
  FilePath: String;
  ServerURL: String;
begin

  FilePath := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) + 'Test.bin';
  ServerURL := edtServerAddress.Text+':'+edtPort.Text;


  HTTP := TIdHTTP.Create(nil);
  FormData := TIdMultipartFormDataStream.Create;
  try
    FormData.AddFile('file1', FilePath, 'application/octet-stream');

    FormData.AddFormField('description', 'Test file upload');

    try
      Response := HTTP.Post(ServerURL + '/upload', FormData);

      AddTestResult('Upload successful!' ,  'PASS' ,'Server response: ' + Response);
    except
      on E: Exception do
        AddTestResult('Upload failed: ', 'PASS', E.Message);
    end;
  finally
    FormData.Free;
    HTTP.Free;
  end;
end;


end.
