{
  SSLCertGenerator - Simple HTTP Server Component
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
program SSLCertGenerator;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.IOUtils,
  Winapi.Windows;

const
  DEFAULT_CERT_PATH = 'cert.pem';
  DEFAULT_KEY_PATH = 'key.pem';
  DEFAULT_DAYS = 365;
  DEFAULT_BITS = 2048;
  DEFAULT_CN = 'localhost';

type
  TCertificateInfo = record
    Country: string;
    State: string;
    City: string;
    Organization: string;
    OrganizationalUnit: string;
    CommonName: string;
    Email: string;
  end;

var
  CertInfo: TCertificateInfo;

function RunOpenSSLCommand(const Command: string): Boolean;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  CmdLine: string;
  ExitCode: Cardinal;
begin
  Result := False;
  FillChar(SI, SizeOf(SI), 0);
  SI.cb := SizeOf(SI);
  SI.dwFlags := STARTF_USESHOWWINDOW;
  SI.wShowWindow := SW_HIDE;

  CmdLine := Command;
  UniqueString(CmdLine);

  if CreateProcess(nil, PChar(CmdLine), nil, nil, False,
                  CREATE_NO_WINDOW, nil, nil, SI, PI) then
  begin
    WaitForSingleObject(PI.hProcess, INFINITE);
    GetExitCodeProcess(PI.hProcess, ExitCode);
    CloseHandle(PI.hProcess);
    CloseHandle(PI.hThread);
    Result := (ExitCode = 0);
  end;
end;

function GenerateSSLCertificate(const CertPath, KeyPath: string;
                              const Info: TCertificateInfo;
                              Days: Integer; Bits: Integer): Boolean;
var
  OpenSSLPath: string;
  CmdLine: string;
  SubjectStr: string;
begin
  Result := False;

  OpenSSLPath := 'openssl.exe';

  WriteLn('Generating RSA private key...');
  CmdLine := Format('"%s" genpkey -algorithm RSA -out "%s" -pkeyopt rsa_keygen_bits:%d',
                  [OpenSSLPath, KeyPath, Bits]);

  if not RunOpenSSLCommand(CmdLine) then
  begin
    WriteLn('Error generating private key');
    WriteLn('Command: ', CmdLine);
    Exit;
  end;

  SubjectStr := Format('/CN=%s', [Info.CommonName]);
  if Info.Country <> '' then
    SubjectStr := SubjectStr + Format('/C=%s', [Info.Country]);
  if Info.State <> '' then
    SubjectStr := SubjectStr + Format('/ST=%s', [Info.State]);
  if Info.City <> '' then
    SubjectStr := SubjectStr + Format('/L=%s', [Info.City]);
  if Info.Organization <> '' then
    SubjectStr := SubjectStr + Format('/O=%s', [Info.Organization]);
  if Info.OrganizationalUnit <> '' then
    SubjectStr := SubjectStr + Format('/OU=%s', [Info.OrganizationalUnit]);
  if Info.Email <> '' then
    SubjectStr := SubjectStr + Format('/emailAddress=%s', [Info.Email]);

  WriteLn('Generating SSL certificate...');
  CmdLine := Format('%s req -new -x509 -key "%s" -out "%s" -days %d -subj "%s"',
                  [OpenSSLPath, KeyPath, CertPath, Days, SubjectStr]);

  CmdLine := Format('%s req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -config minimal.cnf -subj "%s"',
                  [OpenSSLPath, SubjectStr]);

  if not RunOpenSSLCommand(CmdLine) then
  begin
    WriteLn('Error generating certificate');
    WriteLn('Command: ', CmdLine);
    Exit;
  end;

  WriteLn('SSL certificate generated successfully:');
  WriteLn('- Certificate: ', CertPath);
  WriteLn('- Private key: ', KeyPath);

  Result := True;
end;

procedure InitializeDefaultCertInfo;
begin
  CertInfo.Country := 'AA';
  CertInfo.State := 'BBBBBB CCCCCCCC';
  CertInfo.City := 'DDD';
  CertInfo.Organization := 'Organization';
  CertInfo.OrganizationalUnit := 'EEEEEE';
  CertInfo.CommonName := DEFAULT_CN;
  CertInfo.Email := 'admin@example.com';
end;

var
  CertPath, KeyPath: string;
  Days, Bits: Integer;
  Response: string;
begin
  try
    InitializeDefaultCertInfo;

    CertPath := DEFAULT_CERT_PATH;
    KeyPath := DEFAULT_KEY_PATH;
    Days := DEFAULT_DAYS;
    Bits := DEFAULT_BITS;

    WriteLn('SSL Certificate Generator');
    WriteLn('------------------------');
    WriteLn('Using default values:');
    WriteLn('- Certificate path: ', CertPath);
    WriteLn('- Key path: ', KeyPath);
    WriteLn('- Days valid: ', Days);
    WriteLn('- Key bits: ', Bits);
    WriteLn('- Common Name: ', CertInfo.CommonName);
    WriteLn;

    if FileExists(CertPath) or FileExists(KeyPath) then
    begin
      WriteLn('Certificate files already exist. Overwrite? (Y/N)');
      ReadLn(Response);
      if (Length(Response) = 0) or (UpCase(Response[1]) <> 'Y') then
      begin
        WriteLn('Certificate generation cancelled.');
        Exit;
      end;
    end;

    if GenerateSSLCertificate(CertPath, KeyPath, CertInfo, Days, Bits) then
      WriteLn('Certificate generation successful.')
    else
      WriteLn('Certificate generation failed.');

    WriteLn;
    WriteLn('Press Enter to exit...');
    ReadLn;
  except
    on E: Exception do
    begin
      WriteLn('Error: ', E.Message);
      WriteLn('Press Enter to exit...');
      ReadLn;
    end;
  end;
end.
