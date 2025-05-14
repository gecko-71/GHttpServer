unit OpenSSLWrapper;

interface

uses
  {$IFDEF MSWINDOWS}
  WinSock, Windows,
  {$ENDIF}
  {$IFDEF LINUX}
  Posix.SysSocket, Posix.NetinetIn, Posix.ArpaInet, Posix.Unistd, Posix.NetDB,
  {$ENDIF}
  SysUtils, Classes, System.IOUtils, Logger,
  System.Generics.Collections, GHTTPConstants;


type
  TSecureProtocol = (spSSL2, spSSL3, spTLS1, spTLS11, spTLS12, spTLS13);
  TSecureProtocols = set of TSecureProtocol;

  PSSL_CTX = Pointer;
  PSSL = Pointer;
  PSSL_METHOD = Pointer;
  PX509 = Pointer;
  PEVP_PKEY = Pointer;

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

  EOpenSSLException = class(Exception);

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
    FSecureProtocols: TSecureProtocols;

    FOPENSSL_init_ssl: function(opts: UInt64; settings: Pointer): Integer; cdecl;
    FOPENSSL_init_crypto: function(opts: UInt64; settings: Pointer): Integer; cdecl;
    FSSL_CTX_new: function(meth: PSSL_METHOD): PSSL_CTX; cdecl;
    FSSL_CTX_free: procedure(ctx: PSSL_CTX); cdecl;
    FSSL_CTX_use_certificate_file: function(ctx: PSSL_CTX; const filename: PAnsiChar; typ: Integer): Integer; cdecl;
    FSSL_CTX_use_PrivateKey_file: function(ctx: PSSL_CTX; const filename: PAnsiChar; typ: Integer): Integer; cdecl;
    FSSL_CTX_check_private_key: function(ctx: PSSL_CTX): Integer; cdecl;
    FSSL_CTX_set_verify: procedure(ctx: PSSL_CTX; mode: Integer; callback: Pointer); cdecl;
    FSSL_CTX_set_min_proto_version: function(ctx: PSSL_CTX; version: Integer): Integer; cdecl;
    FSSL_CTX_set_max_proto_version: function(ctx: PSSL_CTX; version: Integer): Integer; cdecl;
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
    FTLS_server_method: function: PSSL_METHOD; cdecl;
    FERR_get_error: function: Cardinal; cdecl;
    FERR_error_string: function(e: Cardinal; buf: PAnsiChar): PAnsiChar; cdecl;
    FERR_clear_error: procedure; cdecl;
    FSSL_get_version: function(ssl: PSSL): PAnsiChar; cdecl;
    FSSL_get_cipher_name: function(ssl: PSSL): PAnsiChar; cdecl;
    FSSL_CIPHER_get_name: function(cipher: Pointer): PAnsiChar; cdecl;
    FSSL_get_current_cipher: function(ssl: PSSL): Pointer; cdecl;

    function LoadOpenSSLLibraries: Boolean;
    procedure UnloadOpenSSLLibraries;
    function GetProcAddress(Module: THandle; ProcName: AnsiString): Pointer;
    procedure VerifySSLFunctions;
    function SimpleSSLTest: Boolean;
    procedure LogSSLErrorDetailed(const Msg: string);
    function CheckCertificateFiles: Boolean;
    procedure WriteLog(const AMessage: string);

  public
    constructor Create(ALogger: THttpLogger = nil);
    destructor Destroy; override;

    procedure Initialize;
    procedure Finalize;

    function CreateSSLObject(Socket: TSocket): Boolean;
    function PerformSSLHandshake(Socket: TSocket): Boolean;
    procedure CleanupSSLConnection(Socket: TSocket);

    procedure SetSocketBlocking(Socket: TSocket);
    procedure SetSocketNonBlocking(Socket: TSocket);

    function SSLRead(Socket: TSocket; var Buffer; Length: Integer): Integer;
    function SSLWrite(Socket: TSocket; const Buffer; Length: Integer): Integer;

    property CertificatePath: string read FCertificatePath write FCertificatePath;
    property PrivateKeyPath: string read FPrivateKeyPath write FPrivateKeyPath;
    property SSLContext: PSSL_CTX read FSSLContext;
    property Initialized: Boolean read FInitialized;
    property SSLSocketList: TSSLSocketList read FSSLSocketList;
    property SecureProtocols: TSecureProtocols read FSecureProtocols write FSecureProtocols;

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
  FSecureProtocols := [spTLS12, spTLS13];

  FCertificatePath := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_CERT_FILE);
  FPrivateKeyPath := TPath.Combine(ExtractFilePath(ParamStr(0)), DEFAULT_KEY_FILE);
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
  if (Result = nil) and
     (ProcName <> PROC_SSL_CTX_SET_MIN_PROTO_VERSION) and
     (ProcName <> PROC_SSL_CTX_SET_MAX_PROTO_VERSION) and
     (ProcName <> PROC_SSL_CTX_SET_SESSION_CACHE_MODE) and
     (ProcName <> PROC_SSL_GET_CIPHER_NAME) then
    WriteLog(Format(LOG_FAILED_GET_PROC_ADDRESS, [string(ProcName)]));
end;

function TOpenSSLWrapper.LoadOpenSSLLibraries: Boolean;
var
  LibPath: string;
begin
  Result := False;

  if (FSSLLibraryHandle <> 0) and (FCryptoLibraryHandle <> 0) then
  begin
    Result := True;
    Exit;
  end;

  LibPath := ExtractFilePath(ParamStr(0));
  WriteLog(Format(LOG_LOOKING_FOR_LIBRARIES, [LibPath]));

  FSSLLibraryHandle := LoadLibrary(PChar(TPath.Combine(LibPath, SSL_DLL)));
  if FSSLLibraryHandle = 0 then
  begin
    WriteLog(Format(LOG_FAILED_TO_LOAD, [SSL_DLL]));
    Exit;
  end;

  FCryptoLibraryHandle := LoadLibrary(PChar(TPath.Combine(LibPath, CRYPTO_DLL)));
  if FCryptoLibraryHandle = 0 then
  begin
    WriteLog(Format(LOG_FAILED_TO_LOAD, [CRYPTO_DLL]));
    FreeLibrary(FSSLLibraryHandle);
    FSSLLibraryHandle := 0;
    Exit;
  end;

  @FOPENSSL_init_ssl := GetProcAddress(FSSLLibraryHandle, PROC_OPENSSL_INIT_SSL);
  @FOPENSSL_init_crypto := GetProcAddress(FCryptoLibraryHandle, PROC_OPENSSL_INIT_CRYPTO);
  @FSSL_CTX_new := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_NEW);
  @FSSL_CTX_free := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_FREE);
  @FSSL_CTX_use_certificate_file := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_USE_CERT_FILE);
  @FSSL_CTX_use_PrivateKey_file := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_USE_PRIVKEY_FILE);
  @FSSL_CTX_check_private_key := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_CHECK_PRIVKEY);
  @FSSL_CTX_set_verify := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_SET_VERIFY);
  @FSSL_CTX_set_min_proto_version := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_SET_MIN_PROTO_VERSION);
  @FSSL_CTX_set_max_proto_version := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_SET_MAX_PROTO_VERSION);
  @FSSL_CTX_set_cipher_list := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_SET_CIPHER_LIST);
  @FSSL_CTX_set_session_cache_mode := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_CTX_SET_SESSION_CACHE_MODE);
  @FOPENSSL_version := Windows.GetProcAddress(FCryptoLibraryHandle, PROC_OPENSSL_VERSION);
  @FSSL_new := GetProcAddress(FSSLLibraryHandle, PROC_SSL_NEW);
  @FSSL_free := GetProcAddress(FSSLLibraryHandle, PROC_SSL_FREE);
  @FSSL_set_fd := GetProcAddress(FSSLLibraryHandle, PROC_SSL_SET_FD);
  @FSSL_accept := GetProcAddress(FSSLLibraryHandle, PROC_SSL_ACCEPT);
  @FSSL_connect := GetProcAddress(FSSLLibraryHandle, PROC_SSL_CONNECT);
  @FSSL_read := GetProcAddress(FSSLLibraryHandle, PROC_SSL_READ);
  @FSSL_write := GetProcAddress(FSSLLibraryHandle, PROC_SSL_WRITE);
  @FSSL_shutdown := GetProcAddress(FSSLLibraryHandle, PROC_SSL_SHUTDOWN);
  @FSSL_get_error := GetProcAddress(FSSLLibraryHandle, PROC_SSL_GET_ERROR);
  @FTLS_server_method := GetProcAddress(FSSLLibraryHandle, PROC_TLS_SERVER_METHOD);
  @FERR_get_error := GetProcAddress(FCryptoLibraryHandle, PROC_ERR_GET_ERROR);
  @FERR_error_string := GetProcAddress(FCryptoLibraryHandle, PROC_ERR_ERROR_STRING);
  @FERR_clear_error := GetProcAddress(FCryptoLibraryHandle, PROC_ERR_CLEAR_ERROR);
  @FSSL_get_version := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_GET_VERSION);
  @FSSL_get_cipher_name := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_GET_CIPHER_NAME);
  @FSSL_get_current_cipher := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_GET_CURRENT_CIPHER);
  @FSSL_CIPHER_get_name := Windows.GetProcAddress(FSSLLibraryHandle, PROC_SSL_CIPHER_GET_NAME);

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

  if not Result then
  begin
    WriteLog(LOG_FAILED_LOAD_FUNCTIONS);
    UnloadOpenSSLLibraries;
  end else
    WriteLog(LOG_LIBRARIES_LOADED);
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

  @FOPENSSL_init_ssl := nil;
  @FOPENSSL_init_crypto := nil;
  @FSSL_CTX_new := nil;
  @FSSL_CTX_free := nil;
  @FSSL_CTX_use_certificate_file := nil;
  @FSSL_CTX_use_PrivateKey_file := nil;
  @FSSL_CTX_check_private_key := nil;
  @FSSL_CTX_set_verify := nil;
  @FSSL_CTX_set_min_proto_version := nil;
  @FSSL_CTX_set_max_proto_version := nil;
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
  @FSSL_get_current_cipher := nil;
  @FSSL_CIPHER_get_name := nil;
end;

function TOpenSSLWrapper.CheckCertificateFiles: Boolean;
begin
  Result := False;

  WriteLog(Format(LOG_CHECKING_CERTIFICATE, [FCertificatePath]));
  if not FileExists(FCertificatePath) then
  begin
    WriteLog(LOG_CERT_NOT_FOUND);
    Exit;
  end;

  WriteLog(Format(LOG_CHECKING_KEY, [FPrivateKeyPath]));
  if not FileExists(FPrivateKeyPath) then
  begin
    WriteLog(LOG_KEY_NOT_FOUND);
    Exit;
  end;

  try
    var CertContent := TFile.ReadAllText(FCertificatePath);
    var KeyContent := TFile.ReadAllText(FPrivateKeyPath);

    if not CertContent.Contains(LOG_BEGIN_CERTIFICATE) then
    begin
      WriteLog(LOG_INVALID_CERT_FORMAT);
      Exit;
    end;

    if not KeyContent.Contains(LOG_BEGIN_PRIVATE_KEY) and
       not KeyContent.Contains(LOG_BEGIN_RSA_PRIVATE_KEY) then
    begin
      WriteLog(LOG_INVALID_KEY_FORMAT);
      Exit;
    end;

    Result := True;
    WriteLog(LOG_CERT_FILES_VALID);
  except
    on E: Exception do
    begin
      WriteLog(Format(LOG_ERROR_ACCESSING_FILES, [E.Message]));
      Result := False;
    end;
  end;
end;

procedure TOpenSSLWrapper.VerifySSLFunctions;
begin
  WriteLog(LOG_VERIFYING_POINTERS);
  if not Assigned(FOPENSSL_init_ssl) then WriteLog(Format(LOG_NULL_POINTER, [PROC_OPENSSL_INIT_SSL]));
  if not Assigned(FOPENSSL_init_crypto) then WriteLog(Format(LOG_NULL_POINTER, [PROC_OPENSSL_INIT_CRYPTO]));
  if not Assigned(FSSL_CTX_new) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_NEW]));
  if not Assigned(FSSL_CTX_free) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_FREE]));
  if not Assigned(FSSL_CTX_use_certificate_file) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_USE_CERT_FILE]));
  if not Assigned(FSSL_CTX_use_PrivateKey_file) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_USE_PRIVKEY_FILE]));
  if not Assigned(FSSL_CTX_check_private_key) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_CHECK_PRIVKEY]));
  if not Assigned(FSSL_CTX_set_verify) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_CTX_SET_VERIFY]));
  if not Assigned(FSSL_new) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_NEW]));
  if not Assigned(FSSL_free) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_FREE]));
  if not Assigned(FSSL_set_fd) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_SET_FD]));
  if not Assigned(FSSL_accept) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_ACCEPT]));
  if not Assigned(FSSL_read) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_READ]));
if not Assigned(FSSL_write) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_WRITE]));
  if not Assigned(FSSL_shutdown) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_SHUTDOWN]));
  if not Assigned(FSSL_get_error) then WriteLog(Format(LOG_NULL_POINTER, [PROC_SSL_GET_ERROR]));
  if not Assigned(FTLS_server_method) then WriteLog(Format(LOG_NULL_POINTER, [PROC_TLS_SERVER_METHOD]));
  if not Assigned(FERR_get_error) then WriteLog(Format(LOG_NULL_POINTER, [PROC_ERR_GET_ERROR]));
  if not Assigned(FERR_error_string) then WriteLog(Format(LOG_NULL_POINTER, [PROC_ERR_ERROR_STRING]));
  if not Assigned(FERR_clear_error) then WriteLog(Format(LOG_NULL_POINTER, [PROC_ERR_CLEAR_ERROR]));
end;

function TOpenSSLWrapper.SimpleSSLTest: Boolean;
var
  TestSSL: PSSL;
begin
  Result := False;
  WriteLog(LOG_RUNNING_SSL_TEST);

  TestSSL := FSSL_new(FSSLContext);
  if TestSSL = nil then
  begin
    LogSSLErrorDetailed(LOG_TEST_SSL_OBJECT_FAILED);
    Exit;
  end;

  try
    WriteLog(LOG_SSL_OBJECT_SUCCESS);
    Result := True;
  finally
    FSSL_free(TestSSL);
  end;
end;

procedure TOpenSSLWrapper.SetSocketBlocking(Socket: TSocket);
var
  NonBlocking: u_long;
begin
  NonBlocking := 0;
  ioctlsocket(Socket, FIONBIO, NonBlocking);
end;

procedure TOpenSSLWrapper.SetSocketNonBlocking(Socket: TSocket);
var
  NonBlocking: u_long;
begin
  NonBlocking := 1;
  ioctlsocket(Socket, FIONBIO, NonBlocking);
end;

procedure TOpenSSLWrapper.Initialize;
var
  VersionStr: AnsiString;
  MinVersion, MaxVersion: Integer;
begin
  if FInitialized then
    Exit;

  WriteLog(LOG_INITIALIZING_SSL);

  if Assigned(FERR_clear_error) then
    FERR_clear_error();

  if not LoadOpenSSLLibraries then
    raise EOpenSSLException.Create(ERR_LOAD_OPENSSL_LIBRARIES);

  VerifySSLFunctions;

  if Assigned(FOPENSSL_version) then
  begin
    VersionStr := FOPENSSL_version(OPENSSL_VERSION);
    WriteLog(Format(LOG_OPENSSL_VERSION, [string(VersionStr)]));
  end;

  if not CheckCertificateFiles then
    raise EOpenSSLException.Create(ERR_VERIFY_CERTIFICATE_FILES);

  FOPENSSL_init_crypto(0, nil);
  FOPENSSL_init_ssl(0, nil);

  FSSLContext := FSSL_CTX_new(FTLS_server_method());
  if FSSLContext = nil then
  begin
    LogSSLErrorDetailed(LOG_CREATE_SSL_CONTEXT_FAILED);
    raise EOpenSSLException.Create(ERR_CREATE_SSL_CONTEXT);
  end;

  if FSSL_CTX_use_certificate_file(FSSLContext, PAnsiChar(AnsiString(FCertificatePath)),
                                 SSL_FILETYPE_PEM) <= 0 then
  begin
    LogSSLErrorDetailed(LOG_LOAD_CERTIFICATE_FAILED);
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create(ERR_LOAD_CERTIFICATE);
  end;

  if FSSL_CTX_use_PrivateKey_file(FSSLContext, PAnsiChar(AnsiString(FPrivateKeyPath)),
                               SSL_FILETYPE_PEM) <= 0 then
  begin
    LogSSLErrorDetailed(LOG_LOAD_PRIVATE_KEY_FAILED);
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create(ERR_LOAD_PRIVATE_KEY);
  end;

  if FSSL_CTX_check_private_key(FSSLContext) <= 0 then
  begin
    LogSSLErrorDetailed(LOG_PRIVATE_KEY_MISMATCH);
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create(ERR_PRIVATE_KEY_MISMATCH);
  end;

  FSSL_CTX_set_verify(FSSLContext, SSL_VERIFY_NONE, nil);

  MinVersion := TLS1_2_VERSION;
  if spSSL2 in FSecureProtocols then
    MinVersion := SSL2_VERSION
  else if spSSL3 in FSecureProtocols then
    MinVersion := SSL3_VERSION
  else if spTLS1 in FSecureProtocols then
    MinVersion := TLS1_VERSION
  else if spTLS11 in FSecureProtocols then
    MinVersion := TLS1_1_VERSION
  else if spTLS12 in FSecureProtocols then
    MinVersion := TLS1_2_VERSION
  else if spTLS13 in FSecureProtocols then
    MinVersion := TLS1_3_VERSION;

  MaxVersion := TLS1_3_VERSION;
  if spTLS13 in FSecureProtocols then
    MaxVersion := TLS1_3_VERSION
  else if spTLS12 in FSecureProtocols then
    MaxVersion := TLS1_2_VERSION
  else if spTLS11 in FSecureProtocols then
    MaxVersion := TLS1_1_VERSION
  else if spTLS1 in FSecureProtocols then
    MaxVersion := TLS1_VERSION
  else if spSSL3 in FSecureProtocols then
    MaxVersion := SSL3_VERSION
  else if spSSL2 in FSecureProtocols then
    MaxVersion := SSL2_VERSION;

  if Assigned(FSSL_CTX_set_min_proto_version) then
  begin
    if FSSL_CTX_set_min_proto_version(FSSLContext, MinVersion) <= 0 then
      WriteLog(LOG_SET_MIN_VERSION_FAILED)
    else
      WriteLog(Format(LOG_SET_MIN_VERSION_SUCCESS, [MinVersion]));
  end
  else
    WriteLog(LOG_MIN_VERSION_NOT_SUPPORTED);

  if Assigned(FSSL_CTX_set_max_proto_version) then
  begin
    if FSSL_CTX_set_max_proto_version(FSSLContext, MaxVersion) <= 0 then
      WriteLog(LOG_SET_MAX_VERSION_FAILED)
    else
      WriteLog(Format(LOG_SET_MAX_VERSION_SUCCESS, [MaxVersion]));
  end
  else
    WriteLog(LOG_MAX_VERSION_NOT_SUPPORTED);

  if Assigned(FSSL_CTX_set_cipher_list) then
  begin
    if FSSL_CTX_set_cipher_list(FSSLContext, PAnsiChar(CIPHER_LIST)) <= 0 then
      WriteLog(LOG_SET_CIPHER_LIST_FAILED);
  end;

  if Assigned(FSSL_CTX_set_session_cache_mode) then
  begin
    if FSSL_CTX_set_session_cache_mode(FSSLContext, SSL_SESS_CACHE_SERVER) <= 0 then
      WriteLog(LOG_SET_SESSION_CACHE_FAILED);
  end;

  if not SimpleSSLTest then
  begin
    WriteLog(LOG_SSL_INIT_TEST_FAILED);
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
    raise EOpenSSLException.Create(ERR_SSL_INIT_TEST_FAILED);
  end;

  FInitialized := True;
  WriteLog(LOG_SSL_INITIALIZED);
end;

procedure TOpenSSLWrapper.Finalize;
var
  I: Integer;
  SocketInfo: TSSLSocketInfo;
begin
  if not FInitialized then
    Exit;

  WriteLog(LOG_FINALIZING_SSL);

  for I := FSSLSocketList.Count - 1 downto 0 do
  begin
    SocketInfo := FSSLSocketList[I];
    if SocketInfo.SSL <> nil then
    begin
      FSSL_shutdown(SocketInfo.SSL);
      FSSL_free(SocketInfo.SSL);
    end;
  end;

  FSSLSocketList.Clear;

  if FSSLContext <> nil then
  begin
    FSSL_CTX_free(FSSLContext);
    FSSLContext := nil;
  end;

  FInitialized := False;
  WriteLog(LOG_SSL_FINALIZED);
end;


procedure TOpenSSLWrapper.LogSSLErrorDetailed(const Msg: string);
var
  ErrorCode: Cardinal;
  ErrorStr: AnsiString;
  ErrorBuffer: array[0..255] of AnsiChar;
begin
  WriteLog(Msg);

  ErrorCode := FERR_get_error();
  if ErrorCode = 0 then
  begin
    WriteLog(LOG_SSL_ERROR_HEADER);
    Exit;
  end;

  while ErrorCode <> 0 do
  begin
    FillChar(ErrorBuffer, SizeOf(ErrorBuffer), 0);
    FERR_error_string(ErrorCode, @ErrorBuffer);
    ErrorStr := ErrorBuffer;
    WriteLog(Format(LOG_SSL_ERROR_DETAIL, [string(ErrorStr), ErrorCode]));
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
    WriteLog(LOG_SSL_OBJECT_NOT_INITIALIZED);
    Exit;
  end;

  SSL := FSSL_new(FSSLContext);
  if SSL = nil then
  begin
    LogSSLErrorDetailed(LOG_SSL_STRUCTURE_FAILED);
    Exit;
  end;

  if FSSL_set_fd(SSL, Socket) <= 0 then
  begin
    LogSSLErrorDetailed(LOG_SSL_SET_FD_FAILED);
    FSSL_free(SSL);
    Exit;
  end;

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
    WriteLog(Format(LOG_SSL_HANDSHAKE_NO_OBJECT, [Socket]));
    Exit;
  end;

  SetSocketBlocking(Socket);

  RetryCount := 0;
  repeat
    RetVal := FSSL_accept(SSL);
    if RetVal <= 0 then
    begin
      SSLError := FSSL_get_error(SSL, RetVal);

      if (SSLError = SSL_ERROR_WANT_READ) or (SSLError = SSL_ERROR_WANT_WRITE) then
      begin
        Inc(RetryCount);
        if RetryCount <= MaxRetries then
        begin
          WriteLog(Format(LOG_SSL_HANDSHAKE_RETRY, [RetryCount, MaxRetries]));
          Sleep(100);
          Continue;
        end;
      end;

      WriteLog(Format(LOG_SSL_HANDSHAKE_FAILED, [SSLError]));
      LogSSLErrorDetailed(LOG_SSL_HANDSHAKE_DETAILED);
      SetSocketNonBlocking(Socket);
      Exit;
    end;

    Break;
  until RetryCount > MaxRetries;

  SetSocketNonBlocking(Socket);

  WriteLog(LOG_SSL_HANDSHAKE_SUCCESS);

  if Assigned(FSSL_get_version) then
  begin
    var Protocol: PAnsiChar := FSSL_get_version(SSL);
    WriteLog(Format(LOG_PROTOCOL, [string(Protocol)]));
  end;

  if Assigned(FSSL_get_current_cipher) and Assigned(FSSL_CIPHER_get_name) then
  begin
    var CurrentCipher := FSSL_get_current_cipher(SSL);
    if CurrentCipher <> nil then
    begin
      var CipherName := FSSL_CIPHER_get_name(CurrentCipher);
      WriteLog(Format(LOG_CIPHER, [string(CipherName)]));
    end;
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
    WriteLog(Format(LOG_SSL_CONNECTION_CLEANUP, [Socket]));
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
      Result := 0
    else
      Result := -1;
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
      Result := -1;
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
  Cipher: Pointer;
begin
  Result := '';
  SSL := FSSLSocketList.GetSSL(Socket);

  if SSL = nil then
    Exit;

  if Assigned(FSSL_get_current_cipher) and Assigned(FSSL_CIPHER_get_name) then
  begin
    Cipher := FSSL_get_current_cipher(SSL);
    if Cipher <> nil then
      Result := string(FSSL_CIPHER_get_name(Cipher));
  end;
end;

end.
