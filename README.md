# GHttpServer - Lightweight HTTP/HTTPS Server

A simple, efficient, and modular HTTP/HTTPS server implemented in Delphi. This project provides an easy-to-use platform for handling web requests with minimal configuration.

## Features

- **Protocol Support**: HTTP and HTTPS
- **Request Methods**: GET, POST
- **Custom Endpoints**: Easy definition of custom API endpoints with handler procedures
- **File Operations**: Upload and download functionality
- **Form Data**: Processing of URL-encoded and multipart form data
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
