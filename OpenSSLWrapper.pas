{
  OpenSSLWrapper - Simple HTTP Server Component
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

unit OpenSSLWrapper;

interface

uses
  {$IFDEF MSWINDOWS}
  WinSock, Windows,
  {$ENDIF}
  {$IFDEF LINUX}
  Posix.SysSocket, Posix.NetinetIn, Posix.ArpaInet, Posix.Unistd, Posix.NetDB,
  {$ENDIF}
  SysUtils, Classes, System.IOUtils, Logger, System.Generics.Collections;

const
  // SSL library filenames for OpenSSL 3.x
  SSL_DLL = 'libssl-3.dll';
  CRYPTO_DLL = 'libcrypto-3.dll';

  // SSL Constants
  SSL_FILETYPE_PEM = 1;
  SSL_VERIFY_NONE = 0;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_ZERO_RETURN = 6;

  // OpenSSL 3.x version constants
  TLS1_2_VERSION = $0303;
  TLS1_3_VERSION = $0304;

  // OpenSSL version type
  OPENSSL_VERSION = 0;

  // Session cache modes
  SSL_SESS_CACHE_SERVER = $0002;

type
  // OpenSSL types
  PSSL_CTX = Pointer;
  PSSL = Pointer;
  PSSL_METHOD = Pointer;
  PX509 = Pointer;
  PEVP_PKEY = Pointer;

  // SSL Socket record to associate SSL object with socket
  TSSLSocketInfo = record
    Socket: TSocket;
    SSL: PSSL;
  end;

  TSSLSocketList = class(TList<TSSLSocketInfo>)
  public
    function FindBySocket(ASocket: TSocket): Integer;
    function GetSSL(ASocket: TSocket): PSSL;
    procedure RemoveBySocket(ASocket: TSocket);
  end;

  // SSL exception
  EOpenSSLException = class(Exception);

  // OpenSSL wrapper class
  TOpenSSLWrapper = class
  private
    FSSLContext: PSSL_CTX;
    FSSLSocketList: TSSLSocketList;
    FSSLLibraryHandle: THandle;
    FCryptoLibraryHandle: THandle;
    FCertificatePath: string;
    FPrivateKeyPath: string;
    FInitialized: Boolean;
    FLogger: THttpLogger;

    // OpenSSL 3.x function pointers
    FOPENSSL_init_ssl: function(opts: UInt64; settings: Pointer): Integer; cdecl;
    FOPENSSL_init_crypto: function(opts: UInt64; settings: Pointer): Integer; cdecl;
    FSSL_CTX_new: function(meth: PSSL_METHOD): PSSL_CTX; cdecl;
    FSSL_CTX_free: procedure(ctx: PSSL_CTX); cdecl;
    FSSL_CTX_use_certificate_file: function(ctx: PSSL_CTX; const filename: PAnsiChar; typ: Integer): Integer; cdecl;
    FSSL_CTX_use_PrivateKey_file: function(ctx: PSSL_CTX; const filename: PAnsiChar; typ: Integer): Integer; cdecl;
    FSSL_CTX_check_private_key: function(ctx: PSSL_CTX): Integer; cdecl;
    FSSL_CTX_set_verify: procedure(ctx: PSSL_CTX; mode: Integer; callback: Pointer); cdecl;
    FSSL_CTX_set_min_proto_version: function(ctx: PSSL_CTX; version: Integer): Integer; cdecl;
    FSSL_CTX_set_cipher_list: function(ctx: PSSL_CTX; const str: PAnsiChar): Integer; cdecl;
    FSSL_CTX_set_session_cache_mode: function(ctx: PSSL_CTX; mode: Integer): Integer; cdecl;
    FOPENSSL_version: function(t: Integer): PAnsiChar; cdecl;
    FSSL_new: function(ctx: PSSL_CTX): PSSL; cdecl;
    FSSL_free: procedure(ssl: PSSL); cdecl;
    FSSL_set_fd: function(ssl: PSSL; fd: Integer): Integer; cdecl;
    FSSL_accept: function(ssl: PSSL): Integer; cdecl;
    FSSL_connect: function(ssl: PSSL): Integer; cdecl;
    FSSL_read: function(ssl: PSSL; buf: Pointer; num: Integer): Integer; cdecl;
    FSSL_write: function(ssl: PSSL; const buf: Pointer; num: Integer): Integer; cdecl;
    FSSL_shutdown: function(ssl: PSSL): Integer; cdecl;
    FSSL_get_error: function(ssl: PSSL; ret: Integer): Integer; cdecl;
    FTLS_server_method: function: PSSL_METHOD; cdecl; // Changed name for OpenSSL 3.x
    FERR_get_error: function: Cardinal; cdecl;
    FERR_error_string: function(e: Cardinal; buf: PAnsiChar): PAnsiChar; cdecl;
    FERR_clear_error: procedure; cdecl;
    FSSL_get_version: function(ssl: PSSL): PAnsiChar; cdecl;
    FSSL_get_cipher_name: function(ssl: PSSL): PAnsiChar; cdecl;

    function LoadOpenSSLLibraries: Boolean;
    procedure UnloadOpenSSLLibraries;
    function GetProcAddress(Module: THandle; ProcName: AnsiString): Pointer;
    procedure VerifySSLFunctions;
    function SimpleSSLTest: Boolean;
    procedure LogSSLError(const Msg: string);
    procedure LogSSLErrorDetailed(const Msg: string);
    function CheckCertificateFiles: Boolean;
    procedure WriteLog(const AMessage: string);

  public
    constructor Create(ALogger: THttpLogger = nil);
    destructor Destroy; override;

    procedure Initialize;
    procedure Finalize;

    // SSL connection management
    function CreateSSLObject(Socket: TSocket): Boolean;
    function PerformSSLHandshake(Socket: TSocket): Boolean;
    procedure CleanupSSLConnection(Socket: TSocket);

    // Socket operations
    procedure SetSocketBlocking(Socket: TSocket);
    procedure SetSocketNonBlocking(Socket: TSocket);

    // SSL I/O operations
    function SSLRead(Socket: TSocket; var Buffer; Length: Integer): Integer;
    function SSLWrite(Socket: TSocket; const Buffer; Length: Integer): Integer;

    // Properties
    property CertificatePath: string read FCertificatePath write FCertificatePath;
    property PrivateKeyPath: string read FPrivateKeyPath write FPrivateKeyPath;
    property SSLContext: PSSL_CTX read FSSLContext;
    property Initialized: Boolean read FInitialized;
    property SSLSocketList: TSSLSocketList read FSSLSocketList;

    // Get connection information
    function GetSSLVersion(Socket: TSocket): string;
    function GetSSLCipherName(Socket: TSocket): string;
  end;

implementation

{ TSSLSocketList }

function TSSLSocketList.FindBySocket(ASocket: TSocket): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to Count - 1 do
  begin
    if Items[I].Socket = ASocket then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function TSSLSocketList.GetSSL(ASocket: TSocket): PSSL;
var
  Index: Integer;
begin
  Result := nil;
  Index := FindBySocket(ASocket);
  if Index >= 0 then
    Result := Items[Index].SSL;
end;

procedure TSSLSocketList.RemoveBySocket(ASocket: TSocket);
var
  Index: Integer;
begin
  Index := FindBySocket(ASocket);
  if Index >= 0 then
    Delete(Index);
end;

{ TOpenSSLWrapper }

constructor TOpenSSLWrapper.Create(ALogger: THttpLogger = nil);
begin
  inherited Create;
  FSSLContext := nil;
  FSSLSocketList := TSSLSocketList.Create;
  FSSLLibraryHandle := 0;
  FCryptoLibraryHandle := 0;
  FInitialized := False;
  FLogger := ALogger;

  // Default certificate paths (relative to application directory)
  FCertificatePath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'cert.pem');
  FPrivateKeyPath := TPath.Combine(ExtractFilePath(ParamStr(0)), 'key.pem');
end;

destructor TOpenSSLWrapper.Destroy;
begin
  Finalize;
  FSSLSocketList.Free;
  UnloadOpenSSLLibraries;
  inherited;
end;

procedure TOpenSSLWrapper.WriteLog(const AMessage: string);
begin
  if Assigned(FLogger) then
    FLogger.Log(AMessage);
end;

function TOpenSSLWrapper.GetProcAddress(Module: THandle; ProcName: AnsiString): Pointer;
begin
  Result := Windows.GetProcAddress(Module, PAnsiChar(ProcName));
  if Result = nil then
    WriteLog(Format('Failed to get address for procedure: %s', [string(ProcName)]));
end;

function TOpenSSLWrapper.LoadOpenSSLLibraries: Boolean;
var
  LibPath: string;
begin
  Result := False;

  // Check if libraries are already loaded
  if (FSSLLibraryHandle <> 0) and (FCryptoLibraryHandle <> 0) then
  begin
    Result := True;
    Exit;
  end;

  // Get path to the application directory
  LibPath := ExtractFilePath(ParamStr(0));
  WriteLog(Format('Looking for OpenSSL libraries in: %s', [LibPath]));

  // Load SSL library from application directory
  FSSLLibraryHandle := LoadLibrary(PChar(TPath.Combine(LibPath, SSL_DLL)));
  if FSSLLibraryHandle = 0 then
  begin
    WriteLog(Format('Failed to load %s', [SSL_DLL]));
    Exit;
  end;

  // Load Crypto library
  FCryptoLibraryHandle := LoadLibrary(PChar(TPath.Combine(LibPath, CRYPTO_DLL)));
  if FCryptoLibraryHandle = 0 then
  begin
    WriteLog(Format('Failed to load %s', [CRYPTO_DLL]));
    FreeLibrary(FSSLLibraryHandle);
    FSSLLibraryHandle := 0;
    Exit;
  end;

  // Get OpenSSL 3.x function addresses
  @FOPENSSL_init_ssl := GetProcAddress(FSSLLibraryHandle, 'OPENSSL_init_ssl');
  @FOPENSSL_init_crypto := GetProcAddress(FCryptoLibraryHandle, 'OPENSSL_init_crypto');
  @FSSL_CTX_new := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_new');
  @FSSL_CTX_free := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_free');
  @FSSL_CTX_use_certificate_file := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_use_certificate_file');
  @FSSL_CTX_use_PrivateKey_file := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_use_PrivateKey_file');
  @FSSL_CTX_check_private_key := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_check_private_key');
  @FSSL_CTX_set_verify := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_set_verify');
  @FSSL_CTX_set_min_proto_version := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_set_min_proto_version');
  @FSSL_CTX_set_cipher_list := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_set_cipher_list');
  @FSSL_CTX_set_session_cache_mode := GetProcAddress(FSSLLibraryHandle, 'SSL_CTX_set_session_cache_mode');
  @FOPENSSL_version := GetProcAddress(FCryptoLibraryHandle, 'OpenSSL_version');
  @FSSL_new := GetProcAddress(FSSLLibraryHandle, 'SSL_new');
  @FSSL_free := GetProcAddress(FSSLLibraryHandle, 'SSL_free');
  @FSSL_set_fd := GetProcAddress(FSSLLibraryHandle, 'SSL_set_fd');
  @FSSL_accept := GetProcAddress(FSSLLibraryHandle, 'SSL_accept');
  @FSSL_connect := GetProcAddress(FSSLLibraryHandle, 'SSL_connect');
  @FSSL_read := GetProcAddress(FSSLLibraryHandle, 'SSL_read');
  @FSSL_write := GetProcAddress(FSSLLibraryHandle, 'SSL_write');
  @FSSL_shutdown := GetProcAddress(FSSLLibraryHandle, 'SSL_shutdown');
  @FSSL_get_error := GetProcAddress(FSSLLibraryHandle, 'SSL_get_error');
  @FTLS_server_method := GetProcAddress(FSSLLibraryHandle, 'TLS_server_method'); // Changed name in OpenSSL 3.x
  @FERR_get_error := GetProcAddress(FCryptoLibraryHandle, 'ERR_get_error');
  @FERR_error_string := GetProcAddress(FCryptoLibraryHandle, 'ERR_error_string');
  @FERR_clear_error := GetProcAddress(FCryptoLibraryHandle, 'ERR_clear_error');
  @FSSL_get_version := GetProcAddress(FSSLLibraryHandle, 'SSL_get_version');
  @FSSL_get_cipher_name := GetProcAddress(FSSLLibraryHandle, 'SSL_get_cipher_name');

  // Verify all functions were loaded
  Result := Assigned(FOPENSSL_init_ssl) and
            Assigned(FOPENSSL_init_crypto) and
            Assigned(FSSL_CTX_new) and
            Assigned(FSSL_CTX_free) and
            Assigned(FSSL_CTX_use_certificate_file) and
            Assigned(FSSL_CTX_use_PrivateKey_file) and
            Assigned(FSSL_CTX_check_private_key) and
            Assigned(FSSL_CTX_set_verify) and
            Assigned(FSSL_new) and
            Assigned(FSSL_free) and
            Assigned(FSSL_set_fd) and
            Assigned(FSSL_accept) and
            Assigned(FSSL_connect) and
            Assigned(FSSL_read) and
            Assigned(FSSL_write) and
            Assigned(FSSL_shutdown) and
            Assigned(FSSL_get_error) and
            Assigned(FTLS_server_method) and
            Assigned(FERR_get_error) and
            Assigned(FERR_error_string) and
            Assigned(FERR_clear_error);

  // Optional functions - don't fail if these aren't available
  if Result then
  begin
    // Log which optional functions are available
    if not Assigned(FSSL_CTX_set_min_proto_version) then
      WriteLog('Warning: SSL_CTX_set_min_proto_version not available in this OpenSSL version');
    if not Assigned(FSSL_CTX_set_cipher_list) then
      WriteLog('Warning: SSL_CTX_set_cipher_list not available in this OpenSSL version');
    if not Assigned(FSSL_CTX_set_session_cache_mode) then
      WriteLog('Warning: SSL_CTX_set_session_cache_mode not available in this OpenSSL version');
    if not Assigned(FOPENSSL_version) then
      WriteLog('Warning: OpenSSL_version not available in this OpenSSL version');
    if not Assigned(FSSL_get_version) then
      WriteLog('Warning: SSL_get_version not available in this OpenSSL version');
    if not Assigned(FSSL_get_cipher_name) then
      WriteLog('Warning: SSL_get_cipher_name not available in this OpenSSL version');
  end;

  if not Result then
  begin
    WriteLog('Failed to load all required OpenSSL functions');
    UnloadOpenSSLLibraries;
  end;

  // Success
  WriteLog('OpenSSL libraries loaded successfully');
end;

procedure TOpenSSLWrapper.UnloadOpenSSLLibraries;
begin
  if FSSLLibraryHandle <> 0 then
  begin
    FreeLibrary(FSSLLibraryHandle);
    FSSLLibraryHandle := 0;
  end;

  if FCryptoLibraryHandle <> 0 then
  begin
    FreeLibrary(FCryptoLibraryHandle);
    FCryptoLibraryHandle := 0;
  end;

  // Clear function pointers
  @FOPENSSL_init_ssl := nil;
  @FOPENSSL_init_crypto := nil;
  @FSSL_CTX_new := nil;
  @FSSL_CTX_free := nil;
  @FSSL_CTX_use_certificate_file := nil;
  @FSSL_CTX_use_PrivateKey_file := nil;
  @FSSL_CTX_check_private_key := nil;
  @FSSL_CTX_set_verify := nil;
  @FSSL_CTX_set_min_proto_version := nil;
  @FSSL_CTX_set_cipher_list := nil;
  @FSSL_CTX_set_session_cache_mode := nil;
  @FOPENSSL_version := nil;
  @FSSL_new := nil;
  @FSSL_free := nil;
  @FSSL_set_fd := nil;
  @FSSL_accept := nil;
  @FSSL_connect := nil;
  @FSSL_read := nil;
  @FSSL_write := nil;
  @FSSL_shutdown := nil;
  @FSSL_get_error := nil;
  @FTLS_server_method := nil;
  @FERR_get_error := nil;
  @FERR_error_string := nil;
  @FERR_clear_error := nil;
  @FSSL_get_version := nil;
  @FSSL_get_cipher_name := nil;
end;

function TOpenSSLWrapper.CheckCertificateFiles: Boolean;
begin
  Result := False;

  WriteLog(Format('Checking certificate file: %s', [FCertificatePath]));
  if not FileExists(FCertificatePath) then
  begin
    WriteLog('Certificate file not found!');
    Exit;
  end;

  WriteLog(Format('Checking private key file: %s', [FPrivateKeyPath]));
  if not FileExists(FPrivateKeyPath) then
  begin
    WriteLog('Private key file not found!');
    Exit;
  end;

  try
    // Try to read files to verify access permissions
    var CertContent := TFile.ReadAllText(FCertificatePath);
    var KeyContent := TFile.ReadAllText(FPrivateKeyPath);

    if not CertContent.Contains('BEGIN CERTIFICATE') then
    begin
      WriteLog('Certificate file format appears invalid');
      Exit;
    end;

    if not KeyContent.Contains('BEGIN PRIVATE KEY') and
       not KeyContent.Contains('BEGIN RSA PRIVATE KEY') then
    begin
      WriteLog('Private key file format appears invalid');
      Exit;
    end;

    Result := True;
    WriteLog('Certificate files are valid and accessible');
  except
    on E: Exception do
    begin
      WriteLog(Format('Error accessing certificate files: %s', [E.Message]));
      Result := False;
    end;
  end;
end;

procedure TOpenSSLWrapper.VerifySSLFunctions;
begin
  WriteLog('Verifying SSL function pointers...');
  if not Assigned(FOPENSSL_init_ssl) then WriteLog('OPENSSL_init_ssl is NULL');
  if not Assigned(FOPENSSL_init_crypto) then WriteLog('OPENSSL_init_crypto is NULL');
  if not Assigned(FSSL_CTX_new) then WriteLog('SSL_CTX_new is NULL');
  if not Assigned(FSSL_CTX_free) then WriteLog('SSL_CTX_free is NULL');
  if not Assigned(FSSL_CTX_use_certificate_file) then WriteLog('SSL_CTX_use_certificate_file is NULL');
  if not Assigned(FSSL_CTX_use_PrivateKey_file) then WriteLog('SSL_CTX_use_PrivateKey_file is NULL');
  if not Assigned(FSSL_CTX_check_private_key) then WriteLog('SSL_CTX_check_private_key is NULL');
  if not Assigned(FSSL_CTX_set_verify) then WriteLog('SSL_CTX_set_verify is NULL');
  if not Assigned(FSSL_new) then WriteLog('SSL_new is NULL');
  if not Assigned(FSSL_free) then WriteLog('SSL_free is NULL');
  if not Assigned(FSSL_set_fd) then WriteLog('SSL_set_fd is NULL');
  if not Assigned(FSSL_accept) then WriteLog('SSL_accept is NULL');
  if not Assigned(FSSL_read) then WriteLog('SSL_read is NULL');
  if not Assigned(FSSL_write) then WriteLog('SSL_write is NULL');
  if not Assigned(FSSL_shutdown) then WriteLog('SSL_shutdown is NULL');
  if not Assigned(FSSL_get_error) then WriteLog('SSL_get_error is NULL');
  if not Assigned(FTLS_server_method) then WriteLog('TLS_server_method is NULL');
  if not Assigned(FERR_get_error) then WriteLog('ERR_get_error is NULL');
  if not Assigned(FERR_error_string) then WriteLog('ERR_error_string is NULL');
  if not Assigned(FERR_clear_error) then WriteLog('ERR_clear_error is NULL');
end;

function TOpenSSLWrapper.SimpleSSLTest: Boolean;
var
  TestSSL: PSSL;
begin
  Result := False;
  WriteLog('Running simple SSL test...');

  // Create an SSL object
  TestSSL := FSSL_new(FSSLContext);
  if TestSSL = nil then
  begin
    LogSSLErrorDetailed('Failed to create test SSL object');
    Exit;
  end;

  try
    // Just a basic verification that SSL functions work
    WriteLog('SSL object created successfully');
    Result := True;
  finally
    FSSL_free(TestSSL);
  end;
end;

procedure TOpenSSLWrapper.SetSocketBlocking(Socket: TSocket);
var
  NonBlocking: u_long;
begin
  NonBlocking := 0; // 0 = blocking mode
  ioctlsocket(Socket, FIONBIO, NonBlocking);
end;

procedure TOpenSSLWrapper.SetSocketNonBlocking(Socket: TSocket);
var
  NonBlocking: u_long;
begin
  NonBlocking := 1; // 1 = non-blocking mode
  ioctlsocket(Socket, FIONBIO, NonBlocking);
end;

procedure TOpenSSLWrapper.Initialize;
var
  VersionStr: AnsiString;
begin
  // Check if already initialized
  if FInitialized then
    Exit;

  WriteLog('Initializing SSL...');

  // Clear any existing SSL errors
  if Assigned(FERR_clear_error) then
    FERR_clear_error();

  // Load OpenSSL libraries
  if not LoadOpenSSLLibraries then
    raise EOpenSSLException.Create('Failed to load OpenSSL libraries');

  // Verify function pointers
  VerifySSLFunctions;

  // Log OpenSSL version if available
  if Assigned(FOPENSSL_version) then
  begin
    VersionStr := FOPENSSL_version(OPENSSL_VERSION);
    WriteLog(Format('Using OpenSSL version: %s', [string(VersionStr)]));
  end;

  // Check certificate and key files
  if not CheckCertificateFiles then
    raise EOpenSSLException.Create('Failed to verify certificate files');

  // Initialize OpenSSL for OpenSSL 3.x
  FOPENSSL_init_crypto(0, nil);
  FOPENSSL_init_ssl(0, nil);

  // Create SSL context
  FSSLContext := FSSL_CTX_new(FTLS_server_method());
  if FSSLContext = nil then
  begin
    LogSSLErrorDetailed('Failed to create SSL context');
    raise EOpenSSLException.Create('Failed to create SSL context');
  end;

  // Set certificate file
  if FSSL_CTX_use_certificate_file(FSSLContext, PAnsiChar(AnsiString(FCertificatePath)),
                                 SSL_FILETYPE_PEM) <= 0 then
  begin
    LogSSLErrorDetailed('Failed to load certificate');
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create('Failed to load certificate');
  end;

  // Set private key file
  if FSSL_CTX_use_PrivateKey_file(FSSLContext, PAnsiChar(AnsiString(FPrivateKeyPath)),
                               SSL_FILETYPE_PEM) <= 0 then
  begin
    LogSSLErrorDetailed('Failed to load private key');
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create('Failed to load private key');
  end;

  // Verify private key
  if FSSL_CTX_check_private_key(FSSLContext) <= 0 then
  begin
    LogSSLErrorDetailed('Private key does not match the certificate');
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create('Private key does not match the certificate');
  end;

  // Set verification method to none (no client certificate verification)
  FSSL_CTX_set_verify(FSSLContext, SSL_VERIFY_NONE, nil);

  // Optional: Force TLS 1.2 or later if available
  if Assigned(FSSL_CTX_set_min_proto_version) then
  begin
    if FSSL_CTX_set_min_proto_version(FSSLContext, TLS1_2_VERSION) <= 0 then
      LogSSLErrorDetailed('Warning: Failed to set minimum protocol version to TLS 1.2');
  end;

  // Optional: Set cipher list to a more compatible set if available
  if Assigned(FSSL_CTX_set_cipher_list) then
  begin
    if FSSL_CTX_set_cipher_list(FSSLContext,
       PAnsiChar('HIGH:MEDIUM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5')) <= 0 then
      LogSSLErrorDetailed('Warning: Failed to set cipher list');
  end;

  // Optional: Enable session caching if available
  if Assigned(FSSL_CTX_set_session_cache_mode) then
  begin
    FSSL_CTX_set_session_cache_mode(FSSLContext, SSL_SESS_CACHE_SERVER);
  end;

  // Test SSL functionality
  if not SimpleSSLTest then
  begin
    WriteLog('SSL initialization test failed');
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create('SSL initialization test failed');
  end;

  FInitialized := True;
  WriteLog('SSL initialized successfully');
end;

procedure TOpenSSLWrapper.Finalize;
var
  I: Integer;
  SocketInfo: TSSLSocketInfo;
begin
  if not FInitialized then
    Exit;

  WriteLog('Finalizing SSL...');

  // Free all SSL objects
  for I := FSSLSocketList.Count - 1 downto 0 do
  begin
    SocketInfo := FSSLSocketList[I];
    if SocketInfo.SSL <> nil then
    begin
      FSSL_shutdown(SocketInfo.SSL);
      FSSL_free(SocketInfo.SSL);
    end;
  end;

  // Clear the socket list
  FSSLSocketList.Clear;

  // Free SSL context
  if FSSLContext <> nil then
  begin
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
  end;

  FInitialized := False;
  WriteLog('SSL finalized');
end;

procedure TOpenSSLWrapper.LogSSLError(const Msg: string);
var
  ErrorCode: Cardinal;
  ErrorStr: string;
begin
  // Log all errors in the queue, not just the first one
  ErrorCode := FERR_get_error();

  if ErrorCode = 0 then
  begin
    WriteLog(Format('%s: No specific SSL error code available', [Msg]));
    Exit;
  end;

  while ErrorCode <> 0 do
  begin
    ErrorStr := string(FERR_error_string(ErrorCode, nil));
    WriteLog(Format('%s: %s (0x%x)', [Msg, ErrorStr, ErrorCode]));
    ErrorCode := FERR_get_error();
  end;
end;

procedure TOpenSSLWrapper.LogSSLErrorDetailed(const Msg: string);
var
  ErrorCode: Cardinal;
  ErrorStr: AnsiString;
  ErrorBuffer: array[0..255] of AnsiChar;
begin
  WriteLog(Msg);

  // Log all errors in the queue
  ErrorCode := FERR_get_error();
  if ErrorCode = 0 then
  begin
    WriteLog('  No SSL errors in queue');
    Exit;
  end;

  while ErrorCode <> 0 do
  begin
    FillChar(ErrorBuffer, SizeOf(ErrorBuffer), 0);
    FERR_error_string(ErrorCode, @ErrorBuffer);
    ErrorStr := ErrorBuffer;
    WriteLog(Format('  SSL Error: %s (0x%x)', [string(ErrorStr), ErrorCode]));
    ErrorCode := FERR_get_error();
  end;

  if Assigned(FERR_clear_error) then
    FERR_clear_error();
end;

function TOpenSSLWrapper.CreateSSLObject(Socket: TSocket): Boolean;
var
  SSL: PSSL;
  SocketInfo: TSSLSocketInfo;
begin
  Result := False;

  if not FInitialized then
  begin
    WriteLog('Cannot create SSL object: SSL not initialized');
    Exit;
  end;

  // Create SSL structure for this connection
  SSL := FSSL_new(FSSLContext);
  if SSL = nil then
  begin
    LogSSLErrorDetailed('Failed to create SSL structure');
    Exit;
  end;

  // Associate socket with SSL structure
  if FSSL_set_fd(SSL, Socket) <= 0 then
  begin
    LogSSLErrorDetailed('Failed to associate socket with SSL');
    FSSL_free(SSL);
    Exit;
  end;

  // Store SSL object with socket
  SocketInfo.Socket := Socket;
  SocketInfo.SSL := SSL;
  FSSLSocketList.Add(SocketInfo);

  Result := True;
end;

function TOpenSSLWrapper.PerformSSLHandshake(Socket: TSocket): Boolean;
var
  SSL: PSSL;
  RetVal: Integer;
  SSLError: Integer;
  RetryCount: Integer;
  const MaxRetries = 5;
begin
  Result := False;
  SSL := FSSLSocketList.GetSSL(Socket);

  if SSL = nil then
  begin
    WriteLog(Format('Cannot perform handshake: No SSL object for socket %d', [Socket]));
    Exit;
  end;

  // Temporarily set socket to blocking mode for SSL handshake
  SetSocketBlocking(Socket);

  // Perform SSL handshake with retry logic
  RetryCount := 0;
  repeat
    RetVal := FSSL_accept(SSL);
    if RetVal <= 0 then
    begin
      SSLError := FSSL_get_error(SSL, RetVal);

      // If we need to read or write more data, wait a bit and retry
      if (SSLError = SSL_ERROR_WANT_READ) or (SSLError = SSL_ERROR_WANT_WRITE) then
      begin
        Inc(RetryCount);
        if RetryCount <= MaxRetries then
        begin
          WriteLog(Format('SSL handshake pending, retrying (%d/%d)...', [RetryCount, MaxRetries]));
          Sleep(100); // Wait a bit before retrying
          Continue;
        end;
      end;

      WriteLog(Format('SSL handshake failed with SSL error code: %d', [SSLError]));
      LogSSLErrorDetailed('SSL handshake failed');
      SetSocketNonBlocking(Socket);
      Exit;
    end;

    // Success, break the loop
    Break;
  until RetryCount > MaxRetries;

  // Set socket back to non-blocking mode
  SetSocketNonBlocking(Socket);

  // Log successful handshake with protocol and cipher if available
  if Assigned(FSSL_get_version) and Assigned(FSSL_get_cipher_name) then
  begin
    var Protocol: PAnsiChar := FSSL_get_version(SSL);
    var Cipher: PAnsiChar := FSSL_get_cipher_name(SSL);
    WriteLog(Format('SSL handshake successful. Protocol: %s, Cipher: %s',
                   [string(Protocol), string(Cipher)]));
  end
  else
  begin
    WriteLog('SSL handshake successful');
  end;

  Result := True;
end;

procedure TOpenSSLWrapper.CleanupSSLConnection(Socket: TSocket);
var
  SSL: PSSL;
begin
  SSL := FSSLSocketList.GetSSL(Socket);
  if SSL <> nil then
  begin
    FSSL_shutdown(SSL);
    FSSL_free(SSL);
    FSSLSocketList.RemoveBySocket(Socket);
    WriteLog(Format('SSL connection for socket %d cleaned up', [Socket]));
  end;
end;

function TOpenSSLWrapper.SSLRead(Socket: TSocket; var Buffer; Length: Integer): Integer;
var
  SSL: PSSL;
  Error: Integer;
begin
  Result := 0;
  SSL := FSSLSocketList.GetSSL(Socket);
  if SSL = nil then
    Exit;

  Result := FSSL_read(SSL, @Buffer, Length);
  if Result <= 0 then
  begin
    Error := FSSL_get_error(SSL, Result);
    if (Error = SSL_ERROR_WANT_READ) or (Error = SSL_ERROR_WANT_WRITE) then
      Result := 0
    else if Error = SSL_ERROR_ZERO_RETURN then
      Result := 0  // Connection closed
    else
      Result := -1; // Error
  end;
end;

function TOpenSSLWrapper.SSLWrite(Socket: TSocket; const Buffer; Length: Integer): Integer;
var
  SSL: PSSL;
  Error: Integer;
begin
  Result := 0;
  SSL := FSSLSocketList.GetSSL(Socket);
  if SSL = nil then
    Exit;

  Result := FSSL_write(SSL, @Buffer, Length);
  if Result <= 0 then
  begin
    Error := FSSL_get_error(SSL, Result);
    if (Error = SSL_ERROR_WANT_READ) or (Error = SSL_ERROR_WANT_WRITE) then
      Result := 0
    else
      Result := -1; // Error
  end;
end;

function TOpenSSLWrapper.GetSSLVersion(Socket: TSocket): string;
var
  SSL: PSSL;
begin
  Result := '';
  SSL := FSSLSocketList.GetSSL(Socket);

  if (SSL <> nil) and Assigned(FSSL_get_version) then
    Result := string(FSSL_get_version(SSL));
end;

function TOpenSSLWrapper.GetSSLCipherName(Socket: TSocket): string;
var
  SSL: PSSL;
begin
  Result := '';
  SSL := FSSLSocketList.GetSSL(Socket);

  if (SSL <> nil) and Assigned(FSSL_get_cipher_name) then
    Result := string(FSSL_get_cipher_name(SSL));
end;

end.
