{
  GHTTPConstants - HTTP Server Component Constants
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

unit GHTTPConstants;

interface

const
  //----------------------------------------------------------------------
  // HTTP Methods
  //----------------------------------------------------------------------
  HTTP_METHOD_GET = 'GET';
  HTTP_METHOD_POST = 'POST';
  HTTP_METHOD_HEAD = 'HEAD';
  HTTP_METHOD_PUT = 'PUT';
  HTTP_METHOD_DELETE = 'DELETE';
  HTTP_METHOD_OPTIONS = 'OPTIONS';
  HTTP_METHOD_PATCH = 'PATCH';

  //----------------------------------------------------------------------
  // HTTP Versions
  //----------------------------------------------------------------------
  HTTP_VERSION_1_0 = 'HTTP/1.0';
  HTTP_VERSION_1_1 = 'HTTP/1.1';
  HTTP_VERSION_2_0 = 'HTTP/2';
  HTTP_VERSION_3_0 = 'HTTP/3';

  //----------------------------------------------------------------------
  // HTTP Status Codes
  //----------------------------------------------------------------------
  HTTP_STATUS_OK = 200;
  HTTP_STATUS_CREATED = 201;
  HTTP_STATUS_ACCEPTED = 202;
  HTTP_STATUS_NO_CONTENT = 204;
  HTTP_STATUS_BAD_REQUEST = 400;
  HTTP_STATUS_UNAUTHORIZED = 401;
  HTTP_STATUS_FORBIDDEN = 403;
  HTTP_STATUS_NOT_FOUND = 404;
  HTTP_STATUS_METHOD_NOT_ALLOWED = 405;
  HTTP_STATUS_REQUEST_TIMEOUT = 408;
  HTTP_STATUS_PAYLOAD_TOO_LARGE = 413;
  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415;
  HTTP_STATUS_TOO_MANY_REQUESTS = 429;
  HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
  HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
  HTTP_STATUS_NOT_IMPLEMENTED = 501;
  HTTP_STATUS_SERVICE_UNAVAILABLE = 503;

  //----------------------------------------------------------------------
  // HTTP Status Messages
  //----------------------------------------------------------------------
  HTTP_MSG_OK = 'OK';
  HTTP_MSG_CREATED = 'Created';
  HTTP_MSG_ACCEPTED = 'Accepted';
  HTTP_MSG_NO_CONTENT = 'No Content';
  HTTP_MSG_BAD_REQUEST = 'Bad Request';
  HTTP_MSG_UNAUTHORIZED = 'Unauthorized';
  HTTP_MSG_FORBIDDEN = 'Forbidden';
  HTTP_MSG_NOT_FOUND = 'Not Found';
  HTTP_MSG_METHOD_NOT_ALLOWED = 'Method Not Allowed';
  HTTP_MSG_REQUEST_TIMEOUT = 'Request Timeout';
  HTTP_MSG_PAYLOAD_TOO_LARGE = 'Payload Too Large';
  HTTP_MSG_UNSUPPORTED_MEDIA_TYPE = 'Unsupported Media Type';
  HTTP_MSG_TOO_MANY_REQUESTS = 'Too Many Requests';
  HTTP_MSG_REQUEST_HEADER_FIELDS_TOO_LARGE = 'Request Header Fields Too Large';
  HTTP_MSG_INTERNAL_SERVER_ERROR = 'Internal Server Error';
  HTTP_MSG_NOT_IMPLEMENTED = 'Not Implemented';
  HTTP_MSG_SERVICE_UNAVAILABLE = 'Service Unavailable';

  // Pozostawione dodatkowe komunikaty o bікdach, ktуre maj№ specyficzn№ treњж
  STATUS_400_INCOMPLETE = 'Incomplete request body';
  STATUS_400_INVALID_LENGTH = 'Invalid Content-Length value';

  //----------------------------------------------------------------------
  // HTTP Headers
  //----------------------------------------------------------------------
  HTTP_HEADER_CONTENT_TYPE = 'Content-Type';
  HTTP_HEADER_CONTENT_LENGTH = 'Content-Length';
  HTTP_HEADER_CONNECTION = 'Connection';
  HTTP_HEADER_USER_AGENT = 'User-Agent';
  HTTP_HEADER_SERVER = 'Server';
  HTTP_HEADER_ACCEPT = 'Accept';
  HTTP_HEADER_LOCATION = 'Location';
  HTTP_HEADER_RETRY_AFTER = 'Retry-After';
  HTTP_HEADER_ALLOW = 'Allow';
  HTTP_HEADER_CACHE_CONTROL = 'Cache-Control';

  //----------------------------------------------------------------------
  // Security Headers
  //----------------------------------------------------------------------
  HTTP_HEADER_CONTENT_SECURITY_POLICY = 'Content-Security-Policy';
  HTTP_HEADER_X_CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options';
  HTTP_HEADER_X_FRAME_OPTIONS = 'X-Frame-Options';
  HTTP_HEADER_X_XSS_PROTECTION = 'X-XSS-Protection';
  HTTP_HEADER_STRICT_TRANSPORT_SECURITY = 'Strict-Transport-Security';
  HTTP_HEADER_REFERRER_POLICY = 'Referrer-Policy';
  HTTP_HEADER_PERMISSIONS_POLICY = 'Permissions-Policy';

  //----------------------------------------------------------------------
  // Security Header Values
  //----------------------------------------------------------------------
  HTTP_VALUE_NOSNIFF = 'nosniff';
  HTTP_VALUE_DENY = 'DENY';
  HTTP_VALUE_SAMEORIGIN = 'SAMEORIGIN';
  HTTP_VALUE_XSS_MODE_BLOCK = '1; mode=block';
  HTTP_VALUE_HSTS = 'max-age=31536000; includeSubDomains';
  HTTP_VALUE_REFERRER_POLICY = 'strict-origin-when-cross-origin';
  HTTP_VALUE_PERMISSIONS_POLICY = 'geolocation=(), microphone=(), camera=()';
  HTTP_VALUE_CSP = 'default-src ''self''; script-src ''self''; style-src ''self''; ' +
    'img-src ''self'' data:; connect-src ''self''; frame-ancestors ''none''; base-uri ''self''; form-action ''self'';';
  HTTP_VALUE_XSS  = 'default-src ''self''; script-src ''self''; object-src ''none''; frame-ancestors ''self''; form-action ''self''; base-uri ''self''; img-src ''self'' data:';
  HTTP_VALUE_POLICY = 'strict-origin-when-cross-origin';
  //----------------------------------------------------------------------
  // Connection Values
  //----------------------------------------------------------------------
  HTTP_VALUE_KEEP_ALIVE = 'keep-alive';
  HTTP_VALUE_CLOSE = 'close';

  //----------------------------------------------------------------------
  // Cache Control Values
  //----------------------------------------------------------------------
  HTTP_VALUE_NO_CACHE = 'no-cache';
  HTTP_VALUE_NO_STORE = 'no-store';
  HTTP_VALUE_MUST_REVALIDATE = 'must-revalidate';
  HTTP_VALUE_NO_CACHE_FULL = 'no-store, no-cache, must-revalidate, max-age=0';

  //----------------------------------------------------------------------
  // MIME Types for Common File Extensions
  //----------------------------------------------------------------------
  MIME_TYPE_HTML = 'text/html';
  MIME_TYPE_TEXT = 'text/plain';
  MIME_TYPE_CSS = 'text/css';
  MIME_TYPE_JAVASCRIPT = 'application/javascript';
  MIME_TYPE_JSON = 'application/json';
  MIME_TYPE_XML = 'application/xml';
  MIME_TYPE_PDF = 'application/pdf';
  MIME_TYPE_BIN = 'application/octet-stream';
  MIME_TYPE_JPEG = 'image/jpeg';
  MIME_TYPE_PNG = 'image/png';
  MIME_TYPE_GIF = 'image/gif';
  MIME_TYPE_SVG = 'image/svg+xml';
  MIME_TYPE_ICO = 'image/x-icon';
  MIME_TYPE_ZIP = 'application/zip';
  MIME_TYPE_DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  MIME_TYPE_XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  MIME_TYPE_MP4 = 'video/mp4';
  MIME_TYPE_MP3 = 'audio/mpeg';

  //----------------------------------------------------------------------
  // Server Configuration
  //----------------------------------------------------------------------
  DEFAULT_PORT = 80;
  DEFAULT_SECURE_PORT = 443;
  DEFAULT_MAX_CONNECTIONS = 100;
  DEFAULT_MAX_HEADER_SIZE = 8192;
  DEFAULT_BUFFER_SIZE = 65536 + 65536 + 65536;
  DEFAULT_MAX_POST_SIZE = 104857600;
  DEFAULT_MAX_REQUEST_TIME_SECONDS = 30;
  DEFAULT_FILE_TRANSFER_TIMEOUT_SECONDS = 300;
  DEFAULT_SEND_TIMEOUT_MS = 10000;
  DEFAULT_MAX_WORKER_THREADS = 100;
  DEFAULT_MIN_WORKER_THREADS = 10;

  //----------------------------------------------------------------------
  // Directory Names
  //----------------------------------------------------------------------
  DEFAULT_FILES_DIR = 'Files';
  DEFAULT_TMP_DIR = 'Tmp';

  //----------------------------------------------------------------------
  // SSL Certificate Files
  //----------------------------------------------------------------------
  DEFAULT_CERT_FILE = 'cert.pem';
  DEFAULT_KEY_FILE = 'key.pem';

  //----------------------------------------------------------------------
  // Rate Limiting
  //----------------------------------------------------------------------
  DEFAULT_RATE_LIMIT_REQUESTS = 60;
  DEFAULT_RATE_LIMIT_PERIOD_SECONDS = 60;
  DEFAULT_BLOCK_TIME_SECONDS = 600;
  DEFAULT_FAILED_ATTEMPTS_THRESHOLD = 5;

  //----------------------------------------------------------------------
  // HTTP Line Endings
  //----------------------------------------------------------------------
  CRLF = #13#10;
  HEADER_END = #13#10#13#10;

  //----------------------------------------------------------------------
  // Error Messages
  //----------------------------------------------------------------------
  ERROR_SOCKET_CREATION = 'Socket creation failed';
  ERROR_BIND_FAILED = 'Bind failed';
  ERROR_LISTEN_FAILED = 'Listen failed';
  ERROR_SSL_INITIALIZATION = 'Failed to initialize SSL: %s';
  ERROR_WSA_STARTUP = 'WSAStartup failed';
  ERROR_DIRECTORY_CREATE_FAILED = 'Failed to create directory: ';
  ERR_FILE_TYPE_NOT_ALLOWED = 'File type not allowed';
  ERR_SAVING_UPLOADED_FILE = 'Error saving uploaded file: %s';
  ERR_ENDPOINT_HANDLER = 'Error in endpoint handler %s: %s';
  ERR_ERROR = 'error';
  ERR_INTERNAL_SERVER = '500 Internal Server Error';
  ERR_NOT_FOUND = '404 Not Found';
  ERR_NOT_FOUND_ENDPOINT = '404 Not Found Endpoint';
  ERR_CONNECTION_ERROR = 'Task: Connection error while receiving POST data from IP %s. Expected: %d, Got: %d';

  //----------------------------------------------------------------------
  // Log Messages
  //----------------------------------------------------------------------
  LOG_SERVER_STARTED = 'Server started on port %d';
  LOG_SERVER_STARTED_SECURE = 'Server started on port %d with %s';
  LOG_SERVER_STOPPED = 'Server stopped';
  LOG_TOO_MANY_CONNECTIONS = 'Too many connections, rejecting';
  LOG_CONNECTION_FROM_IP = 'Task: Connection from IP %s';
  LOG_BLOCKED_CONNECTION = 'Task: Blocked connection from IP %s';
  LOG_RATE_LIMIT_EXCEEDED = 'Task: Rate limit exceeded for IP %s';
  LOG_TIMEOUT = 'Task: Timeout for IP %s (%.1f seconds)';
  LOG_RECEIVE_FAILED = 'Task: Receive failed for IP %s, error %d - %s';
  LOG_CLIENT_CLOSED = 'Task: Client closed connection from IP %s';
  LOG_HEADER_SIZE_EXCEEDED = 'Task: Header size limit exceeded for IP %s';
  LOG_INVALID_CONTENT_LENGTH = 'Task: Invalid Content-Length from IP %s: "%s"';
  LOG_NEGATIVE_CONTENT_LENGTH = 'Task: Negative Content-Length from IP %s: %d';
  LOG_CONTENT_LENGTH_LARGE = 'Task: Content-Length too large from IP %s: %d';
  LOG_EMPTY_CONTENT_LENGTH = 'Task: Empty Content-Length from IP %s';
  LOG_INCOMPLETE_POST = 'Task: Incomplete POST data from IP %s. Expected: %d, Got: %d';
  LOG_POST_REQUEST_RECEIVED = 'Task: Complete POST request received for IP %s (%d bytes)';
  LOG_SUSPICIOUS_USER_AGENT = 'Task: Suspicious User-Agent detected from IP %s: %s';
  LOG_HTTPS_USER_AGENT = 'HTTPS client user agent: %s';
  LOG_SUSPICIOUS_HTTPS_USER_AGENT = 'Suspicious user agent detected in HTTPS connection: %s';
  LOG_ERROR_CREATING_RESPONSE = 'Task: Error creating response for IP %s: %s';
  LOG_SEND_FAILED = 'Task: Send failed for IP %s, error %d - %s';
  LOG_RESPONSE_SENT = 'Task: Response sent for IP %s (%d bytes)';
  LOG_EXCEPTION = 'Task: Exception for IP %s: %s';
  LOG_ERROR_SENDING_ERROR = 'Error while sending error response';
  LOG_ERROR_SENDING_RESPONSE = 'Error sending %d response';
  LOG_CHUNKED_ENCODING_REJECTED = 'Rejected chunked encoding request from %s';
  MSG_BASE_DIRECTORY_SET = 'Base directory set to: %s';
  MSG_FILE_UPLOADED = 'File uploaded: %s (%d bytes)';

  //----------------------------------------------------------------------
  // Path and Security
  //----------------------------------------------------------------------
  ENDPOINT_DEFAULT = '/';
  PATH_TRAVERSAL_ATTEMPT = 'Path traversal attempt detected';

  //----------------------------------------------------------------------
  // File Extensions
  //----------------------------------------------------------------------
  EXT_TXT = '.txt';
  EXT_HTML = '.html';
  EXT_HTM = '.htm';
  EXT_JS = '.js';
  EXT_JPG = '.jpg';
  EXT_JPEG = '.jpeg';
  EXT_PNG = '.png';
  EXT_GIF = '.gif';
  EXT_PDF = '.pdf';
  EXT_XML = '.xml';
  EXT_JSON = '.json';
  EXT_DCU = '.dcu';

  //----------------------------------------------------------------------
  // Complete Headers
  //----------------------------------------------------------------------
  HEADER_X_CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options: nosniff';
  HEADER_X_FRAME_OPTIONS = 'X-Frame-Options: DENY';
  HEADER_X_XSS_PROTECTION = 'X-XSS-Protection: 1; mode=block';
  HEADER_REFERRER_POLICY = 'Referrer-Policy: strict-origin-when-cross-origin';
  HEADER_PERMISSIONS_POLICY = 'Permissions-Policy: geolocation=(), microphone=(), camera=()';
  HEADER_CONTENT_SECURITY_POLICY = 'Content-Security-Policy: default-src ''self''; script-src ''self''; style-src ''self''; ' +
    'img-src ''self'' data:; connect-src ''self''; frame-ancestors ''none''; base-uri ''self''; form-action ''self'';';
  HEADER_STRICT_TRANSPORT_SECURITY = 'Strict-Transport-Security: max-age=31536000; includeSubDomains';

  //----------------------------------------------------------------------
  // IP-related constants
  //----------------------------------------------------------------------
  IP_ANY_ADDRESS = '0.0.0.0';
  IP_VALUE_UNKNOWN = 'Unknown';

  //----------------------------------------------------------------------
  // Form parsing
  //----------------------------------------------------------------------
  HEADER_BOUNDARY_PREFIX = 'boundary=';

  //----------------------------------------------------------------------
  // Socket Error Messages
  //----------------------------------------------------------------------
  MSG_WSAEWOULDBLOCK = 'Operation would block (WSAEWOULDBLOCK)';
  MSG_WSAENETDOWN = 'Network is down (WSAENETDOWN)';
  MSG_WSAENOTSOCK = 'Not a socket (WSAENOTSOCK)';
  MSG_WSAEOPNOTSUPP = 'Operation not supported (WSAEOPNOTSUPP)';
  MSG_WSAESHUTDOWN = 'Socket shutdown (WSAESHUTDOWN)';
  MSG_WSAECONNABORTED = 'Connection aborted (WSAECONNABORTED)';
  MSG_WSAECONNRESET = 'Connection reset (WSAECONNRESET)';
  MSG_WSAETIMEDOUT = 'Connection timed out (WSAETIMEDOUT)';
  MSG_WSAEHOSTUNREACH = 'Host unreachable (WSAEHOSTUNREACH)';
  MSG_SOCKET_UNKNOWN = 'Socket Error (%d)';

  //----------------------------------------------------------------------
  // HTTP Response Formatting
  //----------------------------------------------------------------------
  HTTP_RESPONSE_FORMAT = 'HTTP/1.1 %d %s'#13#10 +
                      'Content-Type: text/plain'#13#10 +
                      'Content-Length: %d'#13#10 +
                      'Connection: close'#13#10;

  CONTENT_TYPE = 'Content-Type: text/plain';
  CONTENT_LENGTH = 'Content-Length: %d';
  CONTENT_LENGTH_HEADER = 'Content-Length:';
  CONNECTION = 'Connection: close';
  RETRY_AFTER_60 = 'Retry-After: 60';
  RETRY_AFTER_600 = 'Retry-After: 600';

  //----------------------------------------------------------------------
  // HTTP Constants
  //----------------------------------------------------------------------
  HTTP_POST = 'POST ';

  //----------------------------------------------------------------------
  // Other HTTP Headers
  //----------------------------------------------------------------------
  HDR_SERVER = 'Server';
  HDR_SERVER_VALUE = 'WebServer';
  HDR_PRAGMA = 'Pragma';
  HDR_EXPIRES = 'Expires';
  HDR_USER_AGENT = 'User-Agent:';
  SET_COOKIE_HEADER = 'Set-Cookie';
  CACHE_CONTROL_HEADER = 'Cache-Control';
  ACCEPT_HEADER = 'Accept';
  ACCEPT_ENCODING_HEADER = 'Accept-Encoding';
  ACCEPT_LANGUAGE_HEADER = 'Accept-Language';

  VAL_EXPIRES_ZERO = '0';

  //----------------------------------------------------------------------
  // Browser and Threat Detection
  //----------------------------------------------------------------------
  BROWSER_MSIE_60 = 'MSIE 6.0';
  THREAT_SQLMAP = 'sqlmap';
  THREAT_FUZZ = 'fuzz';
  THREAT_SCRIPT_TAG = '<script>';
  THREAT_SQL_SELECT = 'SELECT';

  //----------------------------------------------------------------------
  // Separators
  //----------------------------------------------------------------------
  SEMICOLON_SEPARATOR = '; ';
  COMMA_SEPARATOR = ', ';
  SPACE_SEPARATOR = ' ';

  //----------------------------------------------------------------------
  // Header validation messages
  //----------------------------------------------------------------------
  WARNING_HEADER = 'No explicit end of header section detected';
  EMPTY_HEADER_SECTION = 'Empty header section';
  INVALID_HEADER_FORMAT_NO_LINES = 'Invalid header format: no lines found';
  INVALID_FOLDED_HEADER_LINE = 'Invalid folded header line: %s';
  INVALID_HEADER_FORMAT_MISSING_COLON = 'Invalid header format (missing colon): %s';
  INVALID_HEADER_FORMAT_EMPTY_NAME = 'Invalid header format (empty name): %s';
  EMPTY_HEADER_NAME_AFTER_TRIMMING = 'Empty header name after trimming';
  INVALID_CHARACTER_IN_HEADER_NAME = 'Invalid character in header name: %s (char at position %d: %s)';

  //----------------------------------------------------------------------
  // OpenSSL Constants
  //----------------------------------------------------------------------
  SSL_DLL = 'libssl-3.dll';
  CRYPTO_DLL = 'libcrypto-3.dll';

  SSL_FILETYPE_PEM = 1;
  SSL_VERIFY_NONE = 0;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_ZERO_RETURN = 6;

  SSL2_VERSION = $0002;
  SSL3_VERSION = $0300;
  TLS1_VERSION = $0301;
  TLS1_1_VERSION = $0302;
  TLS1_2_VERSION = $0303;
  TLS1_3_VERSION = $0304;

  OPENSSL_VERSION = 0;
  SSL_SESS_CACHE_SERVER = $0002;

  CIPHER_LIST = 'HIGH:MEDIUM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5';

  //----------------------------------------------------------------------
  // OpenSSL Error Messages
  //----------------------------------------------------------------------
  ERR_LOAD_OPENSSL_LIBRARIES = 'Failed to load OpenSSL libraries';
  ERR_VERIFY_CERTIFICATE_FILES = 'Failed to verify certificate files';
  ERR_CREATE_SSL_CONTEXT = 'Failed to create SSL context';
  ERR_LOAD_CERTIFICATE = 'Failed to load certificate';
  ERR_LOAD_PRIVATE_KEY = 'Failed to load private key';
  ERR_PRIVATE_KEY_MISMATCH = 'Private key does not match the certificate';
  ERR_SSL_INIT_TEST_FAILED = 'SSL initialization test failed';

  //----------------------------------------------------------------------
  // OpenSSL Log Messages
  //----------------------------------------------------------------------
  LOG_LOOKING_FOR_LIBRARIES = 'Looking for OpenSSL libraries in: %s';
  LOG_FAILED_TO_LOAD = 'Failed to load %s';
  LOG_FAILED_GET_PROC_ADDRESS = 'Failed to get address for procedure: %s';
  LOG_FAILED_LOAD_FUNCTIONS = 'Failed to load all required OpenSSL functions';
  LOG_LIBRARIES_LOADED = 'OpenSSL libraries loaded successfully';
  LOG_CHECKING_CERTIFICATE = 'Checking certificate file: %s';
  LOG_CERT_NOT_FOUND = 'Certificate file not found!';
  LOG_CHECKING_KEY = 'Checking private key file: %s';
  LOG_KEY_NOT_FOUND = 'Private key file not found!';
  LOG_INVALID_CERT_FORMAT = 'Certificate file format appears invalid';
  LOG_INVALID_KEY_FORMAT = 'Private key file format appears invalid';
  LOG_CERT_FILES_VALID = 'Certificate files are valid and accessible';
  LOG_ERROR_ACCESSING_FILES = 'Error accessing certificate files: %s';
  LOG_VERIFYING_POINTERS = 'Verifying SSL function pointers...';
  LOG_NULL_POINTER = '%s is NULL';
  LOG_RUNNING_SSL_TEST = 'Running simple SSL test...';
  LOG_TEST_SSL_OBJECT_FAILED = 'Failed to create test SSL object';
  LOG_SSL_OBJECT_SUCCESS = 'SSL object created successfully';
  LOG_INITIALIZING_SSL = 'Initializing SSL...';
  LOG_OPENSSL_VERSION = 'Using OpenSSL version: %s';
  LOG_CREATE_SSL_CONTEXT_FAILED = 'Failed to create SSL context';
  LOG_LOAD_CERTIFICATE_FAILED = 'Failed to load certificate';
  LOG_LOAD_PRIVATE_KEY_FAILED = 'Failed to load private key';
  LOG_PRIVATE_KEY_MISMATCH = 'Private key does not match the certificate';
  LOG_SET_MIN_VERSION_FAILED = 'Notice: Failed to set minimum protocol version, continuing anyway';
  LOG_MIN_VERSION_NOT_SUPPORTED = 'Setting minimum protocol version not supported, using default';
  LOG_SET_MIN_VERSION_SUCCESS = 'Set minimum protocol version: 0x%x';
  LOG_SET_MAX_VERSION_FAILED = 'Notice: Failed to set maximum protocol version, continuing anyway';
  LOG_MAX_VERSION_NOT_SUPPORTED = 'Setting maximum protocol version not supported, using default';
  LOG_SET_MAX_VERSION_SUCCESS = 'Set maximum protocol version: 0x%x';
  LOG_SET_CIPHER_LIST_FAILED = 'Notice: Failed to set cipher list, continuing anyway';
  LOG_SET_SESSION_CACHE_FAILED = 'Notice: Failed to set session cache mode, continuing anyway';
  LOG_SSL_INIT_TEST_FAILED = 'SSL initialization test failed';
  LOG_SSL_INITIALIZED = 'SSL initialized successfully';
  LOG_FINALIZING_SSL = 'Finalizing SSL...';
  LOG_SSL_FINALIZED = 'SSL finalized';
  LOG_NO_SSL_ERROR = '%s: No specific SSL error code available';
  LOG_SSL_ERROR = '%s: %s (0x%x)';
  LOG_SSL_ERROR_HEADER = 'No SSL errors in queue';
  LOG_SSL_ERROR_DETAIL = '  SSL Error: %s (0x%x)';
  LOG_SSL_OBJECT_NOT_INITIALIZED = 'Cannot create SSL object: SSL not initialized';
  LOG_SSL_STRUCTURE_FAILED = 'Failed to create SSL structure';
  LOG_SSL_SET_FD_FAILED = 'Failed to associate socket with SSL';
  LOG_SSL_HANDSHAKE_NO_OBJECT = 'Cannot perform handshake: No SSL object for socket %d';
  LOG_SSL_HANDSHAKE_RETRY = 'SSL handshake pending, retrying (%d/%d)...';
  LOG_SSL_HANDSHAKE_FAILED = 'SSL handshake failed with SSL error code: %d';
  LOG_SSL_HANDSHAKE_DETAILED = 'SSL handshake failed';
  LOG_SSL_HANDSHAKE_SUCCESS = 'SSL handshake successful';
  LOG_PROTOCOL = 'Protocol: %s';
  LOG_CIPHER = 'Cipher: %s';
  LOG_SSL_CONNECTION_CLEANUP = 'SSL connection for socket %d cleaned up';
  LOG_BEGIN_CERTIFICATE = 'BEGIN CERTIFICATE';
  LOG_BEGIN_PRIVATE_KEY = 'BEGIN PRIVATE KEY';
  LOG_BEGIN_RSA_PRIVATE_KEY = 'BEGIN RSA PRIVATE KEY';

  //----------------------------------------------------------------------
  // OpenSSL Procedure Names
  //----------------------------------------------------------------------
  PROC_OPENSSL_INIT_SSL = 'OPENSSL_init_ssl';
  PROC_OPENSSL_INIT_CRYPTO = 'OPENSSL_init_crypto';
  PROC_SSL_CTX_NEW = 'SSL_CTX_new';
  PROC_SSL_CTX_FREE = 'SSL_CTX_free';
  PROC_SSL_CTX_USE_CERT_FILE = 'SSL_CTX_use_certificate_file';
  PROC_SSL_CTX_USE_PRIVKEY_FILE = 'SSL_CTX_use_PrivateKey_file';
  PROC_SSL_CTX_CHECK_PRIVKEY = 'SSL_CTX_check_private_key';
  PROC_SSL_CTX_SET_VERIFY = 'SSL_CTX_set_verify';
  PROC_SSL_CTX_SET_MIN_PROTO_VERSION = 'SSL_CTX_set_min_proto_version';
  PROC_SSL_CTX_SET_MAX_PROTO_VERSION = 'SSL_CTX_set_max_proto_version';
  PROC_SSL_CTX_SET_CIPHER_LIST = 'SSL_CTX_set_cipher_list';
  PROC_SSL_CTX_SET_SESSION_CACHE_MODE = 'SSL_CTX_set_session_cache_mode';
  PROC_OPENSSL_VERSION = 'OpenSSL_version';
  PROC_SSL_NEW = 'SSL_new';
  PROC_SSL_FREE = 'SSL_free';
  PROC_SSL_SET_FD = 'SSL_set_fd';
  PROC_SSL_ACCEPT = 'SSL_accept';
  PROC_SSL_CONNECT = 'SSL_connect';
  PROC_SSL_READ = 'SSL_read';
  PROC_SSL_WRITE = 'SSL_write';
  PROC_SSL_SHUTDOWN = 'SSL_shutdown';
  PROC_SSL_GET_ERROR = 'SSL_get_error';
  PROC_TLS_SERVER_METHOD = 'TLS_server_method';
  PROC_ERR_GET_ERROR = 'ERR_get_error';
  PROC_ERR_ERROR_STRING = 'ERR_error_string';
  PROC_ERR_CLEAR_ERROR = 'ERR_clear_error';
  PROC_SSL_GET_VERSION = 'SSL_get_version';
  PROC_SSL_GET_CIPHER_NAME = 'SSL_get_cipher_name';
  PROC_SSL_GET_CURRENT_CIPHER = 'SSL_get_current_cipher';
  PROC_SSL_CIPHER_GET_NAME = 'SSL_CIPHER_get_name';

  // Log message constants
  C_EMPTY_IP_ADDR = 'Empty IP address';
  C_LOG_PREFIX = '[%s] [TIPMonitor] %s';
  C_REGISTER_REQUEST_PREFIX = 'RegisterRequest: ';
  C_REGISTER_REQUEST_EMPTY_IP = 'RegisterRequest: Empty IP address';
  C_REGISTER_REQUEST_MAX_RECORDS = 'RegisterRequest: Cannot add IP %s, max records (%d) reached';
  C_REGISTER_REQUEST_NEW_IP = 'RegisterRequest: New IP %s added';
  C_REGISTER_REQUEST_BLOCKED = 'RegisterRequest: IP %s blocked until %s';
  C_REGISTER_REQUEST_RESET_COUNT = 'RegisterRequest: Reset request count for IP %s';
  C_REGISTER_REQUEST_BLOCKED_EXCEEDING = 'RegisterRequest: IP %s blocked for exceeding %d requests/min';
  C_REGISTER_REQUEST_COUNT = 'RegisterRequest: IP %s request count = %d';

  C_REGISTER_FAILED_PREFIX = 'RegisterFailedAttempt: ';
  C_REGISTER_FAILED_EMPTY_IP = 'RegisterFailedAttempt: Empty IP address';
  C_REGISTER_FAILED_MAX_RECORDS = 'RegisterFailedAttempt: Cannot add IP %s, max records (%d) reached';
  C_REGISTER_FAILED_COUNT = 'RegisterFailedAttempt: IP %s failed attempts = %d';
  C_REGISTER_FAILED_BLOCKED = 'RegisterFailedAttempt: IP %s blocked for %d failed attempts';

  C_IS_IP_BLOCKED_PREFIX = 'IsIPBlocked: ';
  C_IS_IP_BLOCKED_EMPTY = 'IsIPBlocked: Empty IP address';
  C_IS_IP_BLOCKED_UNTIL = 'IsIPBlocked: IP %s is blocked until %s';
  C_IS_IP_BLOCKED_NOT = 'IsIPBlocked: IP %s is not blocked';

  C_CLEANUP_REMOVED_IP = 'Cleanup: Removed IP %s';
  C_CLEANUP_SUMMARY = 'Cleanup: Removed %d records, current count = %d';

  // Default values
  C_DEFAULT_MAX_REQUESTS = 340;
  C_DEFAULT_MAX_FAILED = 5;
  C_DEFAULT_BLOCK_TIME = 0;
  C_DEFAULT_CLEANUP_INTERVAL = 3;
  C_DEFAULT_MAX_IP_RECORDS = 10000;
  C_DEFAULT_INACTIVE_MINUTES = 30;

  CONTENT_TYPE_TEXT_PREFIX = 'text/';
  CONTENT_TYPE_CHARSET = 'charset=';
  BINARY_DATA_FORMAT = '[Binary data, %d bytes]';
  EMPTY_STRING = '';

  //----------------------------------------------------------------------
  // Multipart Content Formatting
  //----------------------------------------------------------------------
  BOUNDARY_START_FORMAT = '--%s' + CRLF;
  BOUNDARY_END_FORMAT = '--%s--' + CRLF;
  HEADER_CONTENT_TYPE_FORMAT = 'Content-Type: %s' + CRLF;
  HEADER_CONTENT_DISPOSITION_ATTACHMENT = 'Content-Disposition: attachment; filename="%s"' + CRLF;
  HEADER_CONTENT_DISPOSITION_FORM_DATA = 'Content-Disposition: form-data; name="%s"' + CRLF;
  HEADER_CUSTOM_FORMAT = '%s: %s' + CRLF;

  MIME_TYPE_JSON_UTF8 = 'application/json; charset=utf-8';

  //----------------------------------------------------------------------
  // Content Type Partial Matches
  //----------------------------------------------------------------------
  CONTENT_TYPE_MULTIPART_FORM_DATA = 'multipart/form-data';
  CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded';

  //----------------------------------------------------------------------
  // HTTP Header Values
  //----------------------------------------------------------------------
  HTTP_TRANSFER_ENCODING_CHUNKED = 'chunked';

  //----------------------------------------------------------------------
  // Error Messages
  //----------------------------------------------------------------------
  ERROR_PARSE_REQUEST_FORMAT = 'Error in ParseRequest: %s';

  //----------------------------------------------------------------------
  // Line Endings and Separators
  //----------------------------------------------------------------------
  LF = #10;
  DOUBLE_LF = #10#10;
  CRLF_PATTERN = #13#10;
  DOUBLE_CRLF = #13#10#13#10;
  QUERY_SEPARATOR = '?';

  //----------------------------------------------------------------------
  // JSON Structure Characters
  //----------------------------------------------------------------------
  JSON_OPEN_BRACE = '{';
  JSON_CLOSE_BRACE = '}';
  JSON_OPEN_BRACKET = '[';
  JSON_CLOSE_BRACKET = ']';
  JSON_QUOTE = '"';
  JSON_ESCAPE = '\';

  //----------------------------------------------------------------------
  // JSON Error Messages
  //----------------------------------------------------------------------
  JSON_ERROR_MISSING_BRACES = '{"error":"Malformed JSON: Missing closing braces"}';
  JSON_ERROR_MISSING_BRACKETS = '{"error":"Malformed JSON: Missing closing brackets"}';
  JSON_ERROR_PARSE_FORMAT = '{"error":"Failed to parse JSON body: %s"}';

  //----------------------------------------------------------------------
  // File Extensions (bez kropki)
  //----------------------------------------------------------------------
  FEXT_TXT = 'txt';
  FEXT_HTML = 'html';
  FEXT_HTM = 'htm';
  FEXT_CSS = 'css';
  FEXT_JS = 'js';
  FEXT_JSON = 'json';
  FEXT_JPG = 'jpg';
  FEXT_JPEG = 'jpeg';
  FEXT_PNG = 'png';
  FEXT_GIF = 'gif';
  FEXT_SVG = 'svg';
  FEXT_PDF = 'pdf';
  FEXT_ZIP = 'zip';
  FEXT_EXE = 'exe';
  FEXT_BIN = 'bin';
  FEXT_MP4 = 'mp4';
  FEXT_MP3 = 'mp3';
  FEXT_XML = 'xml';
  FEXT_DOCX = 'docx';
  FEXT_XLSX = 'xlsx';
  FEXT_ICO = 'ico';

implementation

end.
