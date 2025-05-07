{
  HTTPRequest - Simple HTTP Server Component
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

unit HTTPRequest;

interface

uses
  System.Classes, System.SysUtils, System.Generics.Collections, System.NetEncoding;

type
  THTTPHeader = record
    Name: string;
    Value: string;
  end;

  THTTPMultipartFile = class
  private
    FName: string;
    FFilename: string;
    FContentType: string;
    FData: TBytes;
    FStream: TStream;
    FOwnsStream: Boolean;
    FIsStreaming: Boolean;
  public
    constructor Create(const AName, AFilename, AContentType: string; const AData: TBytes); overload;
    constructor CreateFromStream(const AName, AFilename, AContentType: string; AStream: TStream; AOwnsStream: Boolean = True); overload;
    destructor Destroy; override;
    property Name: string read FName;
    property Filename: string read FFilename;
    property ContentType: string read FContentType;
    property Data: TBytes read FData;
    property Stream: TStream read FStream;
    property IsStreaming: Boolean read FIsStreaming;
  end;

  THTTPRequestParser = class
  private
    FRawData: TBytes;
    FMethod: string;
    FPath: string;
    FProtocol: string;
    FHeaders: TList<THTTPHeader>;
    FParams: TDictionary<string, string>;
    FFiles: TObjectList<THTTPMultipartFile>;
    FBody: TBytes;
    FContentType: string;
    FBoundary: string;
    FIsMultipart: Boolean;
    FIsFormUrlEncoded: Boolean;
    FIsValid: Boolean;
    FPathParams: TDictionary<string, string>;
    FBasePath: string;   // Base path without parameters
    FStreamingThreshold: Integer; // File size threshold, above which we use streaming
    procedure ParsePathParams;
    procedure ParseRequest;
    procedure ParseHeaders(const HeaderSection: string);
    procedure ParseUrlEncodedParams(const ParamsStr: string);
    procedure ParseMultipartData;
    function FindBoundaryPositions(const Data: TBytes; const Boundary: TBytes): TArray<Integer>;
    function ExtractContentDisposition(const Headers: string; out Name, Filename: string): Boolean;
    function ExtractContentType(const Headers: string): string;
    function IsLargeFile(const ContentLength: Integer): Boolean;
    function GetBodyValue: string;
    function FindBytesPos(const Data: TBytes; const Pattern: TArray<Byte>): Integer;
    function UTF8ToString(const Bytes: TBytes): string;
  public
    constructor Create(const RequestData: TBytes; AStreamingThreshold: Integer = 1024 * 1024); // 1MB domy lny pr g
    destructor Destroy; override;
    function MatchPathPattern(const Pattern, Path: string; out Params: TDictionary<string, string>): Boolean;
    function GetPathParam(const Name: string): string;
    function GetHeader(const Name: string): string;
    function GetParam(const Name: string): string;
    function GetFile(const Name: string): THTTPMultipartFile;
    property BasePath: string read FBasePath;
    property Method: string read FMethod;
    property Path: string read FPath;
    property Protocol: string read FProtocol;
    property Body: TBytes read FBody;
    property BodyValue: String read GetBodyValue;
    property ContentType: string read FContentType;
    property IsMultipart: Boolean read FIsMultipart;
    property IsFormUrlEncoded: Boolean read FIsFormUrlEncoded;
    property IsValid: Boolean read FIsValid;
    property StreamingThreshold: Integer read FStreamingThreshold write FStreamingThreshold;
    property Params: TDictionary<string, string> read FParams;
  end;

implementation



{ THTTPMultipartFile }

constructor THTTPMultipartFile.Create(const AName, AFilename, AContentType: string; const AData: TBytes);
begin
  inherited Create;
  FName := AName;
  FFilename := AFilename;
  FContentType := AContentType;
  FData := AData;
  FIsStreaming := False;
  FStream := nil;
end;

constructor THTTPMultipartFile.CreateFromStream(const AName, AFilename, AContentType: string; AStream: TStream; AOwnsStream: Boolean = True);
begin
  inherited Create;
  FName := AName;
  FFilename := AFilename;
  FContentType := AContentType;
  FStream := AStream;
  FOwnsStream := AOwnsStream;
  FIsStreaming := True;
end;

destructor THTTPMultipartFile.Destroy;
begin
  SetLength(FData, 0);
  if FIsStreaming and FOwnsStream and Assigned(FStream) then
    FStream.Free;
  inherited;
end;

{ THTTPRequestParser }

constructor THTTPRequestParser.Create(const RequestData: TBytes; AStreamingThreshold: Integer = 1024 * 1024);
begin
  inherited Create;
  FRawData := RequestData;
  FHeaders := TList<THTTPHeader>.Create;
  FParams := TDictionary<string, string>.Create;
  FFiles := TObjectList<THTTPMultipartFile>.Create(True);
  FPathParams := TDictionary<string, string>.Create;
  FIsValid := False;
  FIsMultipart := False;
  FIsFormUrlEncoded := False;
  FStreamingThreshold := AStreamingThreshold;
  ParseRequest;
end;

destructor THTTPRequestParser.Destroy;
begin
  FHeaders.Free;
  FParams.Free;
  FFiles.Free;
  if Assigned(FPathParams) then
    FPathParams.Free;
  SetLength(FRawData, 0);
  SetLength(FBody, 0);
  inherited;
end;

function THTTPRequestParser.IsLargeFile(const ContentLength: Integer): Boolean;
begin
  Result := ContentLength > FStreamingThreshold;
end;

procedure THTTPRequestParser.ParsePathParams;
begin
  // Default implementation - base path will be the same as the original
  FBasePath := FPath;
  // W tym miejscu mo na rozszerzy  o automatyczne wykrywanie parametr w w  cie ce
  // Na przyk ad dla  cie ek typu /users/{id}/profile
end;

function THTTPRequestParser.MatchPathPattern(const Pattern, Path: string; out Params: TDictionary<string, string>): Boolean;
var
  PatternParts, PathParts: TArray<string>;
  i: Integer;
  ParamName: string;
begin
  Result := False;
  Params := TDictionary<string, string>.Create;

  // We split the pattern and path into parts according to the '/' character
  PatternParts := Pattern.Split(['/']);
  PathParts := Path.Split(['/']);

  // Je li liczba cz ci jest r na, zwracamy False
  if Length(PatternParts) <> Length(PathParts) then
  begin
    Params.Free;
    Exit;
  end;

   // Go through all parts and check if they match
  for i := 0 to Length(PatternParts) - 1 do
  begin
    // If pattern part starts with '{' and ends with '}', then it's a parameter
    if (Length(PatternParts[i]) > 2) and (PatternParts[i][1] = '{') and
       (PatternParts[i][Length(PatternParts[i])] = '}') then
    begin
       ParamName := Copy(PatternParts[i], 2, Length(PatternParts[i]) - 2);
       Params.Add(ParamName, PathParts[i]);
    end
     else if PatternParts[i] <> PathParts[i] then
    begin
      Params.Free;
      Exit;
    end;
  end;


  Result := True;

  if Assigned(FPathParams) then
  begin
    for ParamName in Params.Keys do
    begin
      FPathParams.Add(ParamName, Params[ParamName]);
    end;
  end;

  FBasePath := Pattern;
end;

function THTTPRequestParser.GetBodyValue: string;
begin
  Result := TEncoding.UTF8.GetString(FBody);
end;


function THTTPRequestParser.GetPathParam(const Name: string): string;
begin
  Result := '';
  if Assigned(FPathParams) and FPathParams.TryGetValue(Name, Result) then
  else
    Result := '';
end;

procedure THTTPRequestParser.ParseRequest;
var
  RequestStr: string;
  HeadersEnd: Integer;
  FirstLineEnd: Integer;
  RequestLine: string;
  HeadersSection: string;
  Parts: TArray<string>;
  QueryPos: Integer;
  QueryStr: string;
begin
  try
    RequestStr := '';
    try
      RequestStr := TEncoding.ASCII.GetString(FRawData);
    except
      RequestStr := TEncoding.Default.GetString(FRawData);
    end;

    // Find the end of headers
    HeadersEnd := Pos(#13#10#13#10, RequestStr);
    if HeadersEnd <= 0 then
    begin
      FIsValid := False;
      Exit;
    end;

    // Extract headers section
    HeadersSection := Copy(RequestStr, 1, HeadersEnd - 1);

    // Extract body
    if HeadersEnd + 4 <= Length(FRawData) then
    begin
      SetLength(FBody, Length(FRawData) - (HeadersEnd + 3));
      if Length(FBody) > 0 then
        Move(FRawData[HeadersEnd + 4], FBody[0], Length(FBody));
    end;

    // Parse first line (method, path, protocol)
    FirstLineEnd := Pos(#13#10, HeadersSection);
    if FirstLineEnd <= 0 then
    begin
      FIsValid := False;
      Exit;
    end;

    RequestLine := Copy(HeadersSection, 1, FirstLineEnd - 1);
    Parts := RequestLine.Split([' ']);
    if Length(Parts) < 3 then
    begin
      FIsValid := False;
      Exit;
    end;

    FMethod := Parts[0];
    var RawPath := Parts[1]; // Keep raw path with URL encoding intact
    FProtocol := Parts[2];

    // Parse headers
    ParseHeaders(HeadersSection);

    // Check content type
    FContentType := GetHeader('Content-Type');

    if Pos('multipart/form-data', LowerCase(FContentType)) > 0 then
    begin
      // Extract boundary
      var BoundaryPos := Pos('boundary=', LowerCase(FContentType));
      if BoundaryPos > 0 then
      begin
        FBoundary := Copy(FContentType, BoundaryPos + 9, Length(FContentType));
        FIsMultipart := True;
        // Call ParseMultipartData to process the multipart data
        ParseMultipartData;
      end;
    end
    // Handle application/x-www-form-urlencoded
    else if SameText(FContentType, 'application/x-www-form-urlencoded') then
    begin
      FIsFormUrlEncoded := True;
      if Length(FBody) > 0 then
      begin
        var BodyStr := TEncoding.UTF8.GetString(FBody);
        ParseUrlEncodedParams(BodyStr);
      end;
    end;

    // Handle URL parameters for all methods
    QueryPos := Pos('?', RawPath);
    if QueryPos > 0 then
    begin
      QueryStr := Copy(RawPath, QueryPos + 1, Length(RawPath));
      FPath := TNetEncoding.URL.Decode(Copy(RawPath, 1, QueryPos - 1));
      ParseUrlEncodedParams(QueryStr);
    end
    else
    begin
      FPath := TNetEncoding.URL.Decode(RawPath);
    end;

    // Initialize path parameters dictionary if not yet created
    if not Assigned(FPathParams) then
      FPathParams := TDictionary<string, string>.Create;

    ParsePathParams;
    FIsValid := True;
  except
    on E: Exception do
    begin
      FIsValid := False;
      // You can add error logging here
    end;
  end;
end;

procedure THTTPRequestParser.ParseHeaders(const HeaderSection: string);
var
  HeaderLines: TArray<string>;
  i: Integer;
  Line: string;
  SeparatorPos: Integer;
  Header: THTTPHeader;
begin
  HeaderLines := HeaderSection.Split([#13#10]);

  for i := 1 to Length(HeaderLines) - 1 do
  begin
    Line := HeaderLines[i];
    SeparatorPos := Pos(':', Line);
    if SeparatorPos > 0 then
    begin
      Header.Name := Trim(Copy(Line, 1, SeparatorPos - 1));
      Header.Value := Trim(Copy(Line, SeparatorPos + 1, Length(Line)));
      FHeaders.Add(Header);
    end;
  end;
end;

procedure THTTPRequestParser.ParseUrlEncodedParams(const ParamsStr: string);
var
  ParamPairs: TArray<string>;
  i: Integer;
  Pair: string;
  SeparatorPos: Integer;
  ParamName, ParamValue: string;
begin
  ParamPairs := ParamsStr.Split(['&']);
  for i := 0 to Length(ParamPairs) - 1 do
  begin
    Pair := ParamPairs[i];
    SeparatorPos := Pos('=', Pair);
    if SeparatorPos > 0 then
    begin
      ParamName := Copy(Pair, 1, SeparatorPos - 1);
      ParamValue := Copy(Pair, SeparatorPos + 1, Length(Pair));

      // URL decode
      try
        ParamName := TNetEncoding.URL.Decode(ParamName);
      except
      end;

      try
        ParamValue := TNetEncoding.URL.Decode(ParamValue);
      except
      end;

      FParams.AddOrSetValue(ParamName, ParamValue);
    end
    else if Pair <> '' then
    begin
      try
        ParamName := TNetEncoding.URL.Decode(Pair);
      except
        ParamName := Pair;
      end;
      FParams.AddOrSetValue(ParamName, '');
    end;
  end;
end;

// Helper function to properly convert URL-decoded UTF-8 bytes to string
function THTTPRequestParser.UTF8ToString(const Bytes: TBytes): string;
begin
  Result := TEncoding.UTF8.GetString(Bytes);
end;

procedure THTTPRequestParser.ParseMultipartData;
var
  BoundaryBytes, EndBoundaryBytes: TBytes;
  BoundaryPositions: TArray<Integer>;
  i: Integer;
  PartStart, PartEnd: Integer;
  PartBytes: TBytes;
  PartStr: string;
  HeadersEnd: Integer;
  Headers: string;
  Content: TBytes;
  Name, Filename: string;
  ContentType: string;
  FileObject: THTTPMultipartFile;
  ContentLength: Integer;
  TempStream: TMemoryStream;
begin
  BoundaryBytes := TEncoding.ASCII.GetBytes('--' + FBoundary);
  EndBoundaryBytes := TEncoding.ASCII.GetBytes('--' + FBoundary + '--');

  BoundaryPositions := FindBoundaryPositions(FBody, BoundaryBytes);

  for i := 0 to Length(BoundaryPositions) - 2 do
  begin
    if (BoundaryPositions[i] + Length(EndBoundaryBytes) <= Length(FBody)) then
    begin
      var IsEndBoundary := True;
      for var j := 0 to Length(EndBoundaryBytes) - 1 do
      begin
        if (BoundaryPositions[i] + j >= Length(FBody)) or
           (FBody[BoundaryPositions[i] + j] <> EndBoundaryBytes[j]) then
        begin
          IsEndBoundary := False;
          Break;
        end;
      end;

      if IsEndBoundary then
        Continue;
    end;

    PartStart := BoundaryPositions[i] + Length(BoundaryBytes) + 2;
    PartEnd := BoundaryPositions[i + 1] - 2;

    if PartEnd > PartStart then
    begin
      var HeadersEndPos := PartStart;
      while (HeadersEndPos + 3 < PartEnd) and
            not ((FBody[HeadersEndPos] = 13) and (FBody[HeadersEndPos + 1] = 10) and
                 (FBody[HeadersEndPos + 2] = 13) and (FBody[HeadersEndPos + 3] = 10)) do
        Inc(HeadersEndPos);

      if HeadersEndPos + 3 >= PartEnd then
        Continue; // Invalid data

      SetLength(PartBytes, HeadersEndPos - PartStart);
      if Length(PartBytes) > 0 then
        Move(FBody[PartStart], PartBytes[0], Length(PartBytes));
      Headers := TEncoding.UTF8.GetString(PartBytes);

      // Extract Content-Disposition
      if ExtractContentDisposition(Headers, Name, Filename) then
      begin
        ContentType := ExtractContentType(Headers);

        ContentLength := PartEnd - (HeadersEndPos + 4);

        if Filename <> '' then
        begin
          if IsLargeFile(ContentLength) then
          begin
            TempStream := TMemoryStream.Create;
            TempStream.Size := ContentLength;
            if ContentLength > 0 then
              Move(FBody[HeadersEndPos + 4], TempStream.Memory^, ContentLength);
            TempStream.Position := 0;

            FileObject := THTTPMultipartFile.CreateFromStream(Name, Filename, ContentType, TempStream, True);
            FFiles.Add(FileObject);
          end
          else
          begin
            SetLength(Content, ContentLength);
            if ContentLength > 0 then
              Move(FBody[HeadersEndPos + 4], Content[0], ContentLength);

            FileObject := THTTPMultipartFile.Create(Name, Filename, ContentType, Content);
            FFiles.Add(FileObject);
          end;
        end
        else
        begin
          SetLength(Content, ContentLength);
          if ContentLength > 0 then
            Move(FBody[HeadersEndPos + 4], Content[0], ContentLength);

          FParams.AddOrSetValue(Name, TEncoding.UTF8.GetString(Content));
        end;
      end;
    end;
  end;
end;

function THTTPRequestParser.FindBoundaryPositions(const Data: TBytes; const Boundary: TBytes): TArray<Integer>;
var
  Positions: TList<Integer>;
  i, j: Integer;
  Found: Boolean;
begin
  Positions := TList<Integer>.Create;
  try
    for i := 0 to Length(Data) - Length(Boundary) do
    begin
      Found := True;
      for j := 0 to Length(Boundary) - 1 do
      begin
        if Data[i + j] <> Boundary[j] then
        begin
          Found := False;
          Break;
        end;
      end;
      if Found then
        Positions.Add(i);
    end;
    Result := Positions.ToArray;
  finally
    Positions.Free;
  end;
end;

function THTTPRequestParser.ExtractContentDisposition(const Headers: string; out Name, Filename: string): Boolean;
var
  ContentDisposition: string;
  DispositionPos, NamePos, FilenamePos: Integer;
  NameStart, NameEnd, FilenameStart, FilenameEnd: Integer;
begin
  Result := False;
  Name := '';
  Filename := '';

  DispositionPos := Pos('Content-Disposition:', Headers);
  if DispositionPos <= 0 then
    Exit;

  // Find the end of Content-Disposition line
  ContentDisposition := Copy(Headers, DispositionPos, Length(Headers));
  var EndLinePos := Pos(#13#10, ContentDisposition);
  if EndLinePos > 0 then
    ContentDisposition := Copy(ContentDisposition, 1, EndLinePos - 1);

  NamePos := Pos('name="', ContentDisposition);
  if NamePos > 0 then
  begin
    NameStart := NamePos + 6;
    NameEnd := Pos('"', ContentDisposition, NameStart);
    if NameEnd > NameStart then
    begin
      Name := Copy(ContentDisposition, NameStart, NameEnd - NameStart);
      Result := True;
    end;
  end;

  FilenamePos := Pos('filename="', ContentDisposition);
  if FilenamePos > 0 then
  begin
    FilenameStart := FilenamePos + 10;
    FilenameEnd := Pos('"', ContentDisposition, FilenameStart);
    if FilenameEnd > FilenameStart then
      Filename := Copy(ContentDisposition, FilenameStart, FilenameEnd - FilenameStart);
  end;
end;

function THTTPRequestParser.ExtractContentType(const Headers: string): string;
var
  ContentTypePos: Integer;
  EndLinePos: Integer;
  ContentTypeLine: string;
begin
  Result := 'application/octet-stream';

  ContentTypePos := Pos('Content-Type:', Headers);
  if ContentTypePos <= 0 then
    Exit;

  // Find the end of Content-Type line
  ContentTypeLine := Copy(Headers, ContentTypePos, Length(Headers));
  EndLinePos := Pos(#13#10, ContentTypeLine);
  if EndLinePos > 0 then
    ContentTypeLine := Copy(ContentTypeLine, 1, EndLinePos - 1);

  // Extract Content-Type value
  ContentTypeLine := Copy(ContentTypeLine, Pos(':', ContentTypeLine) + 1, Length(ContentTypeLine));
  Result := Trim(ContentTypeLine);
end;

function THTTPRequestParser.GetHeader(const Name: string): string;
var
  i: Integer;
begin
  Result := '';

  for i := 0 to FHeaders.Count - 1 do
  begin
    if SameText(FHeaders[i].Name, Name) then
    begin
      Result := FHeaders[i].Value;
      Break;
    end;
  end;
end;

function THTTPRequestParser.GetParam(const Name: string): string;
begin
  if not FParams.TryGetValue(Name, Result) then
    Result := '';
end;

function THTTPRequestParser.GetFile(const Name: string): THTTPMultipartFile;
var
  i: Integer;
begin
  Result := nil;

  for i := 0 to FFiles.Count - 1 do
  begin
    if SameText(FFiles[i].Name, Name) then
    begin
      Result := FFiles[i];
      Break;
    end;
  end;
end;

function THTTPRequestParser.FindBytesPos(const Data: TBytes; const Pattern: TArray<Byte>): Integer;
var
  i, j: Integer;
  Found: Boolean;
begin
  Result := -1;
  for i := 0 to Length(Data) - Length(Pattern) do
  begin
    Found := True;
    for j := 0 to Length(Pattern) - 1 do
    begin
      if Data[i + j] <> Pattern[j] then
      begin
        Found := False;
        Break;
      end;
    end;
    if Found then
    begin
      Result := i;
      Break;
    end;
  end;
end;

end.
