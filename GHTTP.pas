{
  GHTTP - Simple HTTP Server Component
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

unit GHTTP;

interface

uses
  {$IFDEF MSWINDOWS}
  WinSock, Windows,
  {$ENDIF}
  {$IFDEF LINUX}
  Posix.SysSocket, Posix.NetinetIn, Posix.ArpaInet, Posix.Unistd, Posix.NetDB,
  {$ENDIF}
  GHTTPServer, HttpServerUtils, Logger;


type
  TGHTTP = class
  private

  public
    constructor Create();
    destructor Destroy; override;
    procedure Start;
  end;


implementation

uses System.Classes, System.SysUtils,
     System.IOUtils, System.StrUtils,
     HTTPResponseBuilder, HTTPRequest,
     System.Generics.Collections;

const
  htmlstat: string =
    '<!DOCTYPE html>' + sLineBreak +
    '<html>' + sLineBreak +
    '<head>' + sLineBreak +
    '<meta charset="UTF-8">' + sLineBreak +
    '<title>File Upload</title>' + sLineBreak +
    '<style>' + sLineBreak +
    'body { font-family: Arial; padding: 20px; }' + sLineBreak +
    '.container { border: 2px dashed #ccc; padding: 20px; text-align: center; }' + sLineBreak +
    '</style>' + sLineBreak +
    '</head>' + sLineBreak +
    '<body>' + sLineBreak +
    '<h1>File Upload</h1>' + sLineBreak +
    '<div class="container">' + sLineBreak +
    '<form action="/upload" method="post" enctype="multipart/form-data">' + sLineBreak +
    '<input type="file" name="file" multiple><br><br>' + sLineBreak +
    '<button type="submit">Upload Files</button>' + sLineBreak +
    '</form>' + sLineBreak +
    '</div>' + sLineBreak +
    '</body>' + sLineBreak +
    '</html>';

constructor TGHTTP.Create();
begin

end;

destructor TGHTTP.Destroy;
begin
  inherited;
end;



procedure TGHTTP.Start;
var
  Server: TGHTTPServer;
  HttpLogger: THttpLogger;
begin
  HttpLogger := THttpLogger.Create();
  try
    HttpLogger.OnNewLogLineProc :=
           procedure(Sender: TObject; const LogLine: string)
           begin
             WriteLn(LogLine);
           end;
    //=====================================================================
    Server := TGHTTPServer.Create(nil, 3042, 200, HttpLogger);
    try
      HttpLogger.Log('Starting server... ');
      Server.AddEndpointProc('/', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        begin
            AResponseBuilder.SetStatus(200);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8',
              '<html><body><h1>Welcome to the server</h1></body></html>');
        end,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/redirect', 'GET',
          procedure(Sender: TObject;ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
          begin
            AResponseBuilder.SetStatus(302);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8','');
          end,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/echo', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        var
          Pair: TPair<string, string>;
        begin
          var ResponseStr: String := '<html><body><h1>Echo Parameters</h1><ul>';
          ResponseStr := ResponseStr + '<li>Method: GET</li>';

          for Pair in ARequestParser.Params do
          begin
             ResponseStr := ResponseStr + Format('<p><li>%s = %s</li></p>',
                           [Pair.Key, Pair.Value]);
          end;
          ResponseStr := ResponseStr + '</ul></body></html>';
          AResponseBuilder.SetStatus(200);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
        end,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/TestCase', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        begin
          var ResponseStr: String :=
            '<html><body><h1>Hello from TestCase!</h1>' +
            '<p>Active connections: ' + IntToStr(AServer.GetActiveConnections) + '</p>' +
            '<p>Method: GET</p>' +
            '</body></html>';
          AResponseBuilder.SetStatus(200);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
        end,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/post-test', 'POST',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        var
          Pair: TPair<string, string>;
        begin
          var ResponseStr: String := '<html><body><h1>POST Test</h1>';
          ResponseStr := ResponseStr + '<p>Received POST data:</p><ul>';

          for Pair in ARequestParser.Params do
          begin
            ResponseStr := ResponseStr + Format('<li>%s = %s</li>', [Pair.Key, Pair.Value]);
          end;
          ResponseStr := ResponseStr + '</ul>';

          if Length(ARequestParser.BodyValue) > 0 then
            ResponseStr := ResponseStr + '<p>Raw POST data: ' + ARequestParser.BodyValue + '</p>';
          ResponseStr := ResponseStr + '</body></html>';
          AResponseBuilder.SetStatus(200);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
        end,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/post-test', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        begin
          var ResponseStr: string  := '<html><body><h1>POST Test - Method Not Allowed</h1>';
          ResponseStr := ResponseStr + '<p>Please use POST method</p>';
          ResponseStr := ResponseStr + '<form method="post" action="/post-test">';
          ResponseStr := ResponseStr + '<input type="text" name="name" placeholder="Your name"><br>';
          ResponseStr := ResponseStr + '<input type="text" name="message" placeholder="Your message"><br>';
          ResponseStr := ResponseStr + '<input type="submit" value="Submit">';
          ResponseStr := ResponseStr + '</form></body></html>';
          AResponseBuilder.SetStatus(405);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
        end,atNone,[]);
      //=====================================================================
    Server.AddEndpointProc('/download', 'GET',
      procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                          AResponseBuilder: THTTPResponseBuilder;
                           AServer: TGHTTPServer)
      var
        FileName: string;
        FilePath: string;
        FileStream: TFileStream;
        FileData: TBytes;
        FileExt: string;
        ContentType: string;
        FileSize: Int64;
        Response: string;
      begin
        FileName := ARequestParser.GetParam('file');
        if FileName = '' then
        begin
          Response := '<html><body><h1>Error</h1><p>Missing file parameter</p></body></html>';
          AResponseBuilder.SetStatus(400);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', Response);
          Exit;
        end;

        if (Pos('..', FileName) > 0) or (Pos('/', FileName) > 0) or (Pos('\', FileName) > 0) then
        begin
          Response := '<html><body><h1>403 Forbidden</h1><p>Invalid file name</p></body></html>';
          AResponseBuilder.SetStatus(403);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', Response);
          Exit;
        end;

        FilePath := AServer.BaseDirectory + FileName;

        if not TFile.Exists(FilePath) then
        begin
          Response := '<html><body><h1>404 Not Found</h1><p>File not found</p></body></html>';
          AResponseBuilder.SetStatus(404);
          AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', Response);
          Exit;
        end;

        try
          FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
          try
            FileSize := FileStream.Size;
            SetLength(FileData, FileSize);
            if FileSize > 0 then
              FileStream.ReadBuffer(FileData[0], FileSize);

            FileExt := LowerCase(ExtractFileExt(FileName));
            ContentType := AServer.GetMimeType(FileExt);

            AResponseBuilder.SetStatus(200);
            AResponseBuilder.AddHeader('Content-Disposition', 'attachment; filename="' + FileName + '"');
            AResponseBuilder.AddBinaryContent('file', ContentType, FileData);
          finally
            FileStream.Free;
          end;
        except
          on E: Exception do
          begin
            Response := Format('<html><body><h1>500 Internal Server Error</h1><p>Error reading file: %s</p></body></html>', [E.Message]);
            AResponseBuilder.SetStatus(500);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', Response);
          end;
        end;
      end,atNone,[]);

      //=====================================================================
      Server.AddEndpointProc('/files', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer:TGHTTPServer)
        var
          SR: TSearchRec;
          Files: TStringList;
          i: Integer;
        begin
          Files := TStringList.Create;
          try
            if FindFirst(AServer.BaseDirectory + '*.*', faAnyFile, SR) = 0 then
            begin
              repeat
                if (SR.Name <> '.') and (SR.Name <> '..') and ((SR.Attr and faDirectory) = 0) then
                  Files.Add(SR.Name);
              until FindNext(SR) <> 0;
              FindClose(SR);
            end;

            var Response := '<html><body><h1>Available Files</h1><ul>';
            for i := 0 to Files.Count - 1 do
              Response := Response + Format('<li><a href="/download?file=%s">%s</a></li>',
                [Files[i], Files[i]]);
            Response := Response + '</ul></body></html>';
            AResponseBuilder.SetStatus(200);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', Response);
          finally
            Files.Free;
          end;
        end,atNone,[]);
      //=====================================================================
       Server.AddEndpointProc('/sendfile', 'GET',
            procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                            AResponseBuilder: THTTPResponseBuilder;
                            AServer: TGHTTPServer)
            begin
              AResponseBuilder.SetStatus(200);
              AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', htmlstat);
            end ,atNone,[]);
      //=====================================================================
      Server.AddEndpointProc('/upload', 'POST',
      procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                          AResponseBuilder: THTTPResponseBuilder;
                          AServer: TGHTTPServer)
      var
        UploadedFile: THTTPMultipartFile;
        TargetDir: string;
        TargetFilePath: string;
        FileStream: TFileStream;
        ResponseHtml: string;
        SuccessMessage: string;
        ErrorMessage: string;
        i: Integer;
      begin
        UploadedFile := ARequestParser.GetFile('file');

        if UploadedFile = nil then
        begin
          if SameText(ARequestParser.GetHeader('Content-Type'), 'multipart/form-data') then
          begin
            ErrorMessage := 'No file was selected. Please choose a file to upload.';
            ResponseHtml :=
              '<!DOCTYPE html>' + sLineBreak +
              '<html>' + sLineBreak +
              '<head>' + sLineBreak +
              '<meta charset="UTF-8">' + sLineBreak +
              '<title>Upload Error</title>' + sLineBreak +
              '<style>' + sLineBreak +
              'body { font-family: Arial; padding: 20px; }' + sLineBreak +
              '.error { color: red; }' + sLineBreak +
              '.container { border: 2px dashed #ccc; padding: 20px; text-align: center; }' + sLineBreak +
              '</style>' + sLineBreak +
              '</head>' + sLineBreak +
              '<body>' + sLineBreak +
              '<h1>File Upload Error</h1>' + sLineBreak +
              '<div class="container">' + sLineBreak +
              '<p class="error">' + ErrorMessage + '</p>' + sLineBreak +
              '<form action="/upload" method="post" enctype="multipart/form-data">' + sLineBreak +
              '<input type="file" name="file" multiple><br><br>' + sLineBreak +
              '<button type="submit">Upload Files</button>' + sLineBreak +
              '</form>' + sLineBreak +
              '</div>' + sLineBreak +
              '</body>' + sLineBreak +
              '</html>';

            AResponseBuilder.SetStatus(400);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseHtml);
          end
          else
          begin
            AResponseBuilder.SetStatus(200);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', htmlstat);
          end;
          Exit;
        end;

        try
          TargetDir :=  AServer.BaseDirectory + 'uploads\';

          if not DirectoryExists(TargetDir) then
            ForceDirectories(TargetDir);

          i := 1;
          while FileExists(TargetFilePath) do
          begin
            TargetFilePath := TargetDir + ChangeFileExt(UploadedFile.Filename, '') +
                              '_' + IntToStr(i) + ExtractFileExt(UploadedFile.Filename);
            Inc(i);
          end;

          FileStream := TFileStream.Create(ExtractFileName(UploadedFile.Filename), fmCreate);
          try
            if Length(UploadedFile.Data) > 0 then
              FileStream.WriteBuffer(UploadedFile.Data[0], Length(UploadedFile.Data));

            SuccessMessage := Format('File "%s" uploaded successfully (%d bytes).',
                                    [ExtractFileName(TargetFilePath), Length(UploadedFile.Data)]);

            ResponseHtml :=
              '<!DOCTYPE html>' + sLineBreak +
              '<html>' + sLineBreak +
              '<head>' + sLineBreak +
              '<meta charset="UTF-8">' + sLineBreak +
              '<title>Upload Success</title>' + sLineBreak +
              '<style>' + sLineBreak +
              'body { font-family: Arial; padding: 20px; }' + sLineBreak +
              '.success { color: green; font-weight: bold; }' + sLineBreak +
              '.container { border: 2px dashed #ccc; padding: 20px; text-align: center; }' + sLineBreak +
              '</style>' + sLineBreak +
              '</head>' + sLineBreak +
              '<body>' + sLineBreak +
              '<h1>File Upload Success</h1>' + sLineBreak +
              '<div class="container">' + sLineBreak +
              '<p class="success">' + SuccessMessage + '</p>' + sLineBreak +
              '<form action="/upload" method="post" enctype="multipart/form-data">' + sLineBreak +
              '<input type="file" name="file" multiple><br><br>' + sLineBreak +
              '<button type="submit">Upload Another File</button>' + sLineBreak +
              '</form>' + sLineBreak +
              '</div>' + sLineBreak +
              '</body>' + sLineBreak +
              '</html>';

            AResponseBuilder.SetStatus(200);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseHtml);
          finally
            FileStream.Free;
          end;
        except
          on E: Exception do
          begin
            ErrorMessage := Format('Error uploading file: %s', [E.Message]);
            ResponseHtml :=
              '<!DOCTYPE html>' + sLineBreak +
              '<html>' + sLineBreak +
              '<head>' + sLineBreak +
              '<meta charset="UTF-8">' + sLineBreak +
              '<title>Upload Error</title>' + sLineBreak +
              '<style>' + sLineBreak +
              'body { font-family: Arial; padding: 20px; }' + sLineBreak +
              '.error { color: red; }' + sLineBreak +
              '.container { border: 2px dashed #ccc; padding: 20px; text-align: center; }' + sLineBreak +
              '</style>' + sLineBreak +
              '</head>' + sLineBreak +
              '<body>' + sLineBreak +
              '<h1>File Upload Error</h1>' + sLineBreak +
              '<div class="container">' + sLineBreak +
              '<p class="error">' + ErrorMessage + '</p>' + sLineBreak +
              '<form action="/upload" method="post" enctype="multipart/form-data">' + sLineBreak +
              '<input type="file" name="file" multiple><br><br>' + sLineBreak +
              '<button type="submit">Try Again</button>' + sLineBreak +
              '</form>' + sLineBreak +
              '</div>' + sLineBreak +
              '</body>' + sLineBreak +
              '</html>';

            AResponseBuilder.SetStatus(500);
            AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseHtml);
          end;
        end;
      end,atNone,[]);

      //=====================================================================
  Server.AddEndpointProc('/form-test', 'POST',
    procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                      AResponseBuilder: THTTPResponseBuilder;
                      AServer:TGHTTPServer)
    var
      Pair: TPair<string, string>;
    begin
      var ResponseStr: String := '<html><body><h1>Form URL Encoded Test</h1>';

      if SameText(ARequestParser.ContentType, 'application/x-www-form-urlencoded') then
      begin
        ResponseStr := ResponseStr + '<p>Content-Type: application/x-www-form-urlencoded</p>';
        ResponseStr := ResponseStr + '<p>Parsed form parameters:</p><ul>';

        for Pair in ARequestParser.Params do
        begin
          ResponseStr := ResponseStr + Format('<li>%s = %s</li>', [Pair.Key, Pair.Value]);
        end;

        ResponseStr := ResponseStr + '</ul>';

        if Length(ARequestParser.BodyValue) > 0 then
          ResponseStr := ResponseStr + '<p>Raw body data: ' + ARequestParser.BodyValue + '</p>';

        AResponseBuilder.SetStatus(200);
      end
      else
      begin
        ResponseStr := ResponseStr + '<p>Error: Expected application/x-www-form-urlencoded content type but received: ' +
                                    ARequestParser.ContentType + '</p>';
        AResponseBuilder.SetStatus(400);
      end;

      ResponseStr := ResponseStr + '</body></html>';
      AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
    end,atNone,[]);

  //=====================================================================
  Server.AddEndpointProc('/multipart-test', 'POST',
    procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                    AResponseBuilder: THTTPResponseBuilder;
                    AServer:TGHTTPServer)
    var
      UploadedFile: THTTPMultipartFile;
      Pair: TPair<string, string>;
      i: Integer;
    begin
      var ResponseStr: String := '<html><body><h1>Multipart Form Data Test</h1>';

      if Pos('multipart/form-data', LowerCase(ARequestParser.ContentType)) > 0 then
      begin
        ResponseStr := ResponseStr + '<p>Content-Type: ' + ARequestParser.ContentType + '</p>';

        ResponseStr := ResponseStr + '<p>Form fields:</p><ul>';

        for Pair in ARequestParser.Params do
        begin
          ResponseStr := ResponseStr + Format('<li>%s = %s</li>', [Pair.Key, Pair.Value]);
        end;

        ResponseStr := ResponseStr + '</ul>';

        i := 0;
        UploadedFile := ARequestParser.GetFile('file1');
        while UploadedFile <> nil do
        begin
          if i = 0 then
            ResponseStr := ResponseStr + '<p>Uploaded files:</p><ul>';

          ResponseStr := ResponseStr + Format('<li>Field name: %s, Filename: %s, Content-Type: %s, Size: %d bytes</li>',
                                            [UploadedFile.Name, UploadedFile.Filename,
                                             UploadedFile.ContentType, Length(UploadedFile.Data)]);

          i := i + 1;
          UploadedFile := ARequestParser.GetFile('file' + IntToStr(i + 1));
        end;

        if i > 0 then
          ResponseStr := ResponseStr + '</ul>'
        else
          ResponseStr := ResponseStr + '<p>No files uploaded.</p>';

        AResponseBuilder.SetStatus(200);
      end
      else
      begin
        ResponseStr := ResponseStr + '<p>Error: Expected multipart/form-data content type but received: ' +
                                    ARequestParser.ContentType + '</p>';
        AResponseBuilder.SetStatus(400);
      end;

      ResponseStr := ResponseStr + '</body></html>';
      AResponseBuilder.AddTextContent('content', 'text/html; charset=utf-8', ResponseStr);
    end,atNone,[]);

      Server.Start;
    finally
      Server.Free;
    end;
  finally
    HttpLogger.Free;
  end;
end;


end.
