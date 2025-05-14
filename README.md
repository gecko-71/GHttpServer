# GHttpServer - Lightweight HTTP/HTTPS Server and Rest API

A simple, efficient HTTP/HTTPS server implemented in Delphi with JWT authentication support.

## Features

- **Protocol Support**: HTTP and HTTPS
- **Request Methods**: GET, POST
- **Custom Endpoints**: Easy definition of custom API endpoints with handler procedures
- **File Operations**: Upload and download functionality
- **Form Data**: Processing of URL-encoded and multipart form data
- **Authentication: JWT token authorization for securing API endpoints
- **Security Features**: 
  - IP monitoring
  - Request rate limiting
  - Protection against common attack vectors
- **Logging System**: Comprehensive logging with customizable output
- **Cross-Platform**: Compatible with both Windows and Linux
- **To support HTTPS, the OpenSSL-3.5.0_win32 library is required, including**
  - openssl.exe
  - libssl-3.dll
  - libcrypto-3.dll
  - legacy.dll

## Getting Started

### Prerequisites

- Delphi IDE (tested with Delphi 10.4 and above)
- Basic understanding of HTTP/HTTPS protocols

### Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/ghttp-server.git
```

2. Open the project in Delphi IDE
3. Build the project

### Basic Usage

```pascal
var
  Server: TGHTTPServer;
  HttpLogger: THttpLogger;
begin
  HttpLogger := THttpLogger.Create();
  try
    // Set up logging
    HttpLogger.OnNewLogLineProc := procedure(Sender: TObject; const LogLine: string)
    begin
      WriteLn(LogLine);
    end;

    // Create server instance on port 3042 with max 200 connections
    Server := TGHTTPServer.Create(nil, 3042, 200, HttpLogger);
    try
      // Add a simple endpoint
      Server.AddEndpointProc('/', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                        AResponseBuilder: THTTPResponseBuilder;
                        ASerwer: TGHTTPServer)
        begin
          AResponseBuilder.SetStatus(200);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8',
            '<html><body><h1>Welcome to GHTTP Server</h1></body></html>');
        end,atNone, []);

      // Start the server
      Server.Start;
    finally
      Server.Free;
    end;
  finally
    HttpLogger.Free;
  end;
end;
```

## JWT Authorization
The server supports JWT token authentication for securing API endpoints.
## Token Generation
```pascal
Server.AddEndpointProc('/api/token', 'POST',
  procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
    AResponseBuilder: THTTPResponseBuilder; AServer: TGHTTPServer)
  var
    RequestJson: TJSONObject;
    Username, Password: string;
    Token: string;
  begin
    try
      RequestJson := TJSONObject.ParseJSONValue(ARequestParser.BodyValue) as TJSONObject;
      if not Assigned(RequestJson) then
      begin
        AResponseBuilder.SetStatus(400);
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid JSON"}');
        Exit;
      end;
      
      Username := RequestJson.GetValue<string>('username', '');
      Password := RequestJson.GetValue<string>('password', '');
      
      if (Username = 'admin') and (Password = 'admin') then
      begin
        // Create token with roles
        var Claims := TJSONObject.Create;
        var Roles := TJSONArray.Create;
        Roles.Add('admin');
        Claims.AddPair('roles', Roles);
        
        Token := AServer.JWTManager.CreateToken(Username, Claims);
        AResponseBuilder.SetStatus(200);
        AResponseBuilder.AddTextContent('response', 'application/json', 
          Format('{"token":"%s","token_type":"Bearer"}', [Token]));
        
        Claims.Free;
      end
      else
      begin
        AResponseBuilder.SetStatus(401);
        AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Invalid credentials"}');
      end;
      
      RequestJson.Free;
    except
      AResponseBuilder.SetStatus(500);
      AResponseBuilder.AddTextContent('error', 'application/json', '{"error":"Server error"}');
    end;
  end, atNone, []);
```
## Protected Endpoints
```pascal
Server.AddEndpointProc('/api/secure', 'GET',
  procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
    AResponseBuilder: THTTPResponseBuilder; AServer: TGHTTPServer)
  begin
    AResponseBuilder.SetStatus(200);
    AResponseBuilder.AddTextContent('content', 'application/json',
      '{"message": "This is a secure endpoint"}');
  end, atJWT, []);
```
 
## Structure

The project consists of the following main components:

- **GHTTP.pas**: Main server implementation
- **GHTTPServer.pas**: Core server functionality
- **HTTPRequest.pas**: Request parsing
- **HTTPResponseBuilder.pas**: Response generation
- **HttpServerUtils.pas**: Utility functions
- **Logger.pas**: Logging system

## License

This code is provided for non-commercial use only. See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Authors

- **Gecko71** - *Initial work*

## Acknowledgments

- Thanks to all contributors and testers
