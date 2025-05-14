{
  GHttpsSvrPrj - Simple HTTP Server Component
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

program GHttpsSvrPrj;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,
  GHTTPSServer in 'GHTTPSServer.pas',
  GHTTPServer in 'GHTTPServer.pas',
  HTTPRequest in 'HTTPRequest.pas',
  HTTPResponseBuilder in 'HTTPResponseBuilder.pas',
  HttpServerUtils in 'HttpServerUtils.pas',
  Logger in 'Logger.pas',
  OpenSSLWrapper in 'OpenSSLWrapper.pas',
  GHTTPConstants in 'GHTTPConstants.pas';

var
  Server: TGHTTPSServer;
  HttpLogger: THttpLogger;
begin
  HttpLogger := THttpLogger.Create();
  try
    HttpLogger.OnNewLogLineProc :=
           procedure(Sender: TObject; const LogLine: string)
           begin
             WriteLn(LogLine);
           end;
    Server := TGHTTPSServer.Create(nil, 8443,200, HttpLogger);
    try

      Server.CertificatePath := 'cert.pem';
      Server.PrivateKeyPath := 'key.pem';

      Server.AddEndpointProc('/api/hello', 'GET',
        procedure(Sender: TObject; ARequestParser: THTTPRequestParser;
                  AResponseBuilder: THTTPResponseBuilder; ASerwer: TGHTTPServer)
        begin
          AResponseBuilder.SetStatus(200, 'OK');
          AResponseBuilder.AddTextContent('application/json', 'text/plain',
                                         '{"message":"Hello from HTTPS server!"}');
        end,atNone,[]);

      // Uruchom serwer
      Server.Start;
    finally
      Server.Free;
    end;
  finally
    HttpLogger.free;
  end;
end.
