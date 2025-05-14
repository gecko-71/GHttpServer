{
  GHttpSvrPrj - Simple HTTP Server Component
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

program GHttpSvrPrj;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  GHTTPServer in 'GHTTPServer.pas',
  HttpServerUtils in 'HttpServerUtils.pas',
  Logger in 'Logger.pas',
  GHTTP in 'GHTTP.pas',
  HTTPRequest in 'HTTPRequest.pas',
  HTTPResponseBuilder in 'HTTPResponseBuilder.pas',
  GHTTPConstants in 'GHTTPConstants.pas';

var
  GHTTP: TGHTTP;
begin
  GHTTP := TGHTTP.Create;
  try
     GHTTP.Start;
  finally
    GHTTP.free;
  end;
end.
