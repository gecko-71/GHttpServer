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
  System.Classes, System.SysUtils, System.Generics.Collections,
  System.NetEncoding, Logger;

type

  EHTTPParseError = class(Exception);
  EHTTPHeaderError = class(EHTTPParseError);

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
    FBasePath: string;
    FStreamingThreshold: Integer;
    FHttpLogger: THttpLogger;
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
    procedure DecodeChunkedEncoding(const ChunkedData: TBytes);
    procedure WriteLog(log: string);
    function FindRequestLineEnd(const Data: TBytes): Integer;
    function ParseRequestLine(const Data: TBytes; RequestLineEnd: Integer;
                             out MethodBytes, PathBytes, ProtocolBytes: TBytes): Boolean;
    procedure FindHeadersEnd(const Data: TBytes; RequestLineEnd: Integer;
                            out HeaderEndPos, BodyStartPos: Integer);
    procedure ParseHeadersSection(const Data: TBytes; HeaderEndPos: Integer);
    function ParseContentLength(const ContentLengthStr: string): Integer;
    procedure ProcessRequestBody(const Data: TBytes; BodyStartPos, ContentLength: Integer;
                                ChunkedEncoding: Boolean);
    procedure ProcessRequestContent(const ContentType: string);
    function CompareBoundary(const Data: TBytes; Offset: Integer; const Boundary: TBytes): Boolean;
    function FastIndexOf(const Data, Pattern: TBytes; StartPos, DataLength: Integer): Integer;
  public
    constructor Create(const RequestData: TBytes; AHttpLogger:THttpLogger;
                      AStreamingThreshold: Integer = 1024 * 1024);
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
    property HttpLogger: THttpLogger read FHttpLogger write FHttpLogger;
  end;

implementation

uses System.Math, GHTTPConstants, HttpServerUtils;

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

constructor THTTPRequestParser.Create(const RequestData: TBytes; AHttpLogger:THttpLogger;
                      AStreamingThreshold: Integer = 1024 * 1024);
begin
  inherited Create;
  FHttpLogger := AHttpLogger;
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
  FBasePath := FPath;
end;

function THTTPRequestParser.MatchPathPattern(const Pattern, Path: string; out Params: TDictionary<string, string>): Boolean;
var
  PatternParts, PathParts: TArray<string>;
  i: Integer;
  ParamName: string;
begin
  Result := False;
  Params := TDictionary<string, string>.Create;
  PatternParts := Pattern.Split(['/']);
  PathParts := Path.Split(['/']);
  if Length(PatternParts) <> Length(PathParts) then
  begin
    Params.Free;
    Exit;
  end;
  for i := 0 to Length(PatternParts) - 1 do
  begin
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
var
  ContentTypeLC: string;
  EncodingToUse: TEncoding;
begin
  Result := EMPTY_STRING;
  if Length(FBody) = 0 then
    Exit;
  ContentTypeLC := LowerCase(FContentType);
  EncodingToUse := TEncoding.UTF8;
  if Pos(MIME_TYPE_JSON, ContentTypeLC) > 0 then
  begin
    try
      Result := EncodingToUse.GetString(FBody);
      Result := Trim(Result);
      if (Result <> EMPTY_STRING) then
      begin
        if (Result[1] = JSON_OPEN_BRACE) and (Result[Length(Result)] <> JSON_CLOSE_BRACE) then
        begin
          var OpenBraces := 0;
          var CloseBraces := 0;
          var InString := False;
          var EscapeNext := False;
          for var I := 1 to Length(Result) do
          begin
            var C := Result[I];
            if C = JSON_QUOTE then
            begin
              if not EscapeNext then
                InString := not InString;
            end;
            if C = JSON_ESCAPE then
              EscapeNext := not EscapeNext
            else
              EscapeNext := False;
            if not InString then
            begin
              if C = JSON_OPEN_BRACE then Inc(OpenBraces);
              if C = JSON_CLOSE_BRACE then Inc(CloseBraces);
            end;
          end;
          if OpenBraces > CloseBraces then
          begin
            Result := JSON_ERROR_MISSING_BRACES;
          end;
        end
        else if (Result[1] = JSON_OPEN_BRACKET) and (Result[Length(Result)] <> JSON_CLOSE_BRACKET) then
        begin
          var OpenBrackets := 0;
          var CloseBrackets := 0;
          var InString := False;
          var EscapeNext := False;
          for var I := 1 to Length(Result) do
          begin
            var C := Result[I];
            if C = JSON_QUOTE then
            begin
              if not EscapeNext then
                InString := not InString;
            end;
            if C = JSON_ESCAPE then
              EscapeNext := not EscapeNext
            else
              EscapeNext := False;
            if not InString then
            begin
              if C = JSON_OPEN_BRACKET then Inc(OpenBrackets);
              if C = JSON_CLOSE_BRACKET then Inc(CloseBrackets);
            end;
          end;
          if OpenBrackets > CloseBrackets then
          begin
            Result := JSON_ERROR_MISSING_BRACKETS;
          end;
        end;
      end;
    except
      on E: Exception do
      begin
        Result := Format(JSON_ERROR_PARSE_FORMAT, [E.Message]);
      end;
    end;
  end
  else if Pos(CONTENT_TYPE_TEXT_PREFIX, ContentTypeLC) > 0 then
  begin
    try
      Result := EncodingToUse.GetString(FBody);
    except
      on E: Exception do
      begin
        try
          Result := TEncoding.Default.GetString(FBody);
        except
          Result := EMPTY_STRING;
        end;
      end;
    end;
  end
  else
  begin
    try
      Result := EncodingToUse.GetString(FBody);
    except
      Result := EMPTY_STRING;
    end;
  end;
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
  requestLineEnd, headerEndPos, bodyStartPos: Integer;
  contentLengthStr: string;
  contentLength, actualBodyLength: Integer;
  transferEncoding: string;
  chunkedEncoding: Boolean;
  queryPos: Integer;
  queryStr, rawPath: string;
  methodBytes, pathBytes, protocolBytes: TBytes;
  errorMessage: string;
begin
  try
    requestLineEnd := FindRequestLineEnd(FRawData);
    if requestLineEnd < 0 then
    begin
      FIsValid := False;
      Exit;
    end;

    if not ParseRequestLine(FRawData, requestLineEnd, methodBytes, pathBytes, protocolBytes) then
    begin
      FIsValid := False;
      Exit;
    end;
    FMethod := TEncoding.UTF8.GetString(methodBytes);
    rawPath := TEncoding.UTF8.GetString(pathBytes);
    FProtocol := TEncoding.UTF8.GetString(protocolBytes);

    if not (FProtocol.StartsWith(HTTP_VERSION_1_0) or
            FProtocol.StartsWith(HTTP_VERSION_1_1) or
            FProtocol.StartsWith(HTTP_VERSION_2_0) or
            FProtocol.StartsWith(HTTP_VERSION_3_0)) then
      FProtocol := HTTP_VERSION_1_1;

    FindHeadersEnd(FRawData, requestLineEnd, headerEndPos, bodyStartPos);

    if headerEndPos < 0 then
    begin
      FIsValid := False;
      Exit;
    end;

    ParseHeadersSection(FRawData, headerEndPos);
    FContentType := GetHeader(HTTP_HEADER_CONTENT_TYPE);
    contentLengthStr := GetHeader(HTTP_HEADER_CONTENT_LENGTH);
    transferEncoding := GetHeader(HTTP_HEADER_CONNECTION);
    chunkedEncoding := SameText(Trim(transferEncoding), HTTP_TRANSFER_ENCODING_CHUNKED);

    contentLength := ParseContentLength(contentLengthStr);
    ProcessRequestBody(FRawData, bodyStartPos, contentLength, chunkedEncoding);
    ProcessRequestContent(FContentType);

    queryPos := Pos(QUERY_SEPARATOR, rawPath);
    if queryPos > 0 then
    begin
      queryStr := Copy(rawPath, queryPos + 1, Length(rawPath));
      FPath := TNetEncoding.URL.Decode(Copy(rawPath, 1, queryPos - 1));
      ParseUrlEncodedParams(queryStr);
    end
    else
    begin
      FPath := TNetEncoding.URL.Decode(rawPath);
    end;

    if not Assigned(FPathParams) then
      FPathParams := TDictionary<string, string>.Create;

    ParsePathParams;
    FIsValid := True;
  except
    on E: Exception do
    begin
      errorMessage := Format(ERROR_PARSE_REQUEST_FORMAT, [E.Message]);
      FIsValid := False;
    end;
  end;
end;

function THTTPRequestParser.FindRequestLineEnd(const Data: TBytes): Integer;
var
  i, scanLimit: Integer;
  CR, LF: Byte;
begin
  CR := 13;
  LF := 10;

  Result := -1;
  scanLimit := Min(1024, Length(Data) - 2);

  for i := 0 to scanLimit do
  begin
    if (Data[i] = CR) and (i + 1 < Length(Data)) and (Data[i + 1] = LF) then
    begin
      Result := i;
      Exit;
    end
    else if (Data[i] = LF) then
    begin
      Result := i;
      Exit;
    end;
  end;

  for i := scanLimit + 1 to Length(Data) - 2 do
  begin
    if (Data[i] = CR) and (Data[i + 1] = LF) then
    begin
      Result := i;
      Exit;
    end
    else if (Data[i] = LF) then
    begin
      Result := i;
      Exit;
    end;
  end;
end;

function THTTPRequestParser.ParseRequestLine(const Data: TBytes; RequestLineEnd: Integer;
                                         out MethodBytes, PathBytes, ProtocolBytes: TBytes): Boolean;
var
  i, partCount, partStart: Integer;
  SPACE: Byte;
  parts: TArray<TBytes>;
begin
  SPACE := 32;

  SetLength(parts, 3);
  partCount := 0;
  partStart := 0;

  for i := 0 to RequestLineEnd - 1 do
  begin
    if Data[i] = SPACE then
    begin
      if partCount < 3 then
      begin
        SetLength(parts[partCount], i - partStart);
        if (i - partStart) > 0 then
          Move(Data[partStart], parts[partCount][0], i - partStart);
        Inc(partCount);
        partStart := i + 1;
      end;
    end;
  end;

  if (partCount < 3) and (partStart < RequestLineEnd) then
  begin
    SetLength(parts[partCount], RequestLineEnd - partStart);
    if (RequestLineEnd - partStart) > 0 then
      Move(Data[partStart], parts[partCount][0], RequestLineEnd - partStart);
    Inc(partCount);
  end;

  Result := (partCount = 3);

  if Result then
  begin
    MethodBytes := parts[0];
    PathBytes := parts[1];
    ProtocolBytes := parts[2];
  end;
end;

procedure THTTPRequestParser.FindHeadersEnd(const Data: TBytes; RequestLineEnd: Integer;
                                         out HeaderEndPos, BodyStartPos: Integer);
var
  i, j, skipSize: Integer;
  CR, LF: Byte;
begin
  CR := 13;
  LF := 10;

  HeaderEndPos := -1;
  BodyStartPos := -1;

  i := RequestLineEnd;
  if (Data[RequestLineEnd] = CR) and (RequestLineEnd + 1 < Length(Data)) and (Data[RequestLineEnd + 1] = LF) then
    i := RequestLineEnd + 2
  else if (Data[RequestLineEnd] = LF) then
    i := RequestLineEnd + 1;
  while i < Length(Data) - 1 do
  begin
    if (Data[i] = CR) then
    begin
      if (i + 1 < Length(Data)) and (Data[i + 1] = LF) then
      begin
        if (i + 3 < Length(Data)) and (Data[i + 2] = CR) and (Data[i + 3] = LF) then
        begin
          HeaderEndPos := i;
          BodyStartPos := i + 4;
          Exit;
        end;
        i := i + 2;
      end
      else
      begin
        Inc(i);
      end;
    end
    else if (Data[i] = LF) then
    begin
      if (i + 1 < Length(Data)) and (Data[i + 1] = LF) then
      begin
        HeaderEndPos := i;
        BodyStartPos := i + 2;
        Exit;
      end;
      Inc(i);
    end
    else
    begin
      skipSize := 1;

      for j := 1 to Min(16, Length(Data) - i - 1) do
      begin
        if (Data[i + j] = CR) or (Data[i + j] = LF) then
        begin
          skipSize := j;
          Break;
        end;
      end;

      i := i + skipSize;
    end;
  end;
end;

procedure THTTPRequestParser.ParseHeadersSection(const Data: TBytes; HeaderEndPos: Integer);
var
  headersBytes: TBytes;
  headersStr: string;
begin
  headersBytes := Copy(Data, 0, HeaderEndPos);
  headersStr := TEncoding.UTF8.GetString(headersBytes);
  ParseHeaders(headersStr);
end;

function THTTPRequestParser.ParseContentLength(const ContentLengthStr: string): Integer;
begin
  Result := 0;

  if ContentLengthStr <> EMPTY_STRING then
  begin
    try
      Result := StrToInt(Trim(ContentLengthStr));
      if Result < 0 then
        Result := 0;
    except
      Result := 0;
    end;
  end;
end;

procedure THTTPRequestParser.ProcessRequestBody(const Data: TBytes; BodyStartPos, ContentLength: Integer;
                                            ChunkedEncoding: Boolean);
var
  actualBodyLength: Integer;
begin
  if BodyStartPos < Length(Data) then
  begin
    actualBodyLength := Length(Data) - BodyStartPos;
    if ChunkedEncoding then
    begin
      try
        DecodeChunkedEncoding(Copy(Data, BodyStartPos, actualBodyLength));
      except
        on E: Exception do
        begin
          SetLength(FBody, actualBodyLength);
          if actualBodyLength > 0 then
            Move(Data[BodyStartPos], FBody[0], actualBodyLength);
        end;
      end;
    end
    else
    begin
      if (ContentLength > 0) and (ContentLength <= actualBodyLength) then
      begin
        SetLength(FBody, ContentLength);
        if ContentLength > 0 then
          Move(Data[BodyStartPos], FBody[0], ContentLength);
      end
      else
      begin
        SetLength(FBody, actualBodyLength);
        if actualBodyLength > 0 then
          Move(Data[BodyStartPos], FBody[0], actualBodyLength);
      end;
    end;
  end
  else
  begin
    SetLength(FBody, 0);
  end;
end;

procedure THTTPRequestParser.ProcessRequestContent(const ContentType: string);
var
  boundaryPos: Integer;
  bodyStr: string;
begin
  if Pos(MIME_TYPE_JSON, LowerCase(ContentType)) > 0 then
  begin

  end
  else if Pos(CONTENT_TYPE_MULTIPART_FORM_DATA, LowerCase(ContentType)) > 0 then
  begin
    boundaryPos := Pos(HEADER_BOUNDARY_PREFIX, LowerCase(ContentType));
    if boundaryPos > 0 then
    begin
      FBoundary := Copy(ContentType, boundaryPos + Length(HEADER_BOUNDARY_PREFIX), Length(ContentType));
      if (Length(FBoundary) >= 2) and (FBoundary[1] = '"') and (FBoundary[Length(FBoundary)] = '"') then
        FBoundary := Copy(FBoundary, 2, Length(FBoundary) - 2);
      FIsMultipart := True;
      ParseMultipartData;
    end;
  end
  else if Pos(CONTENT_TYPE_FORM_URLENCODED, LowerCase(ContentType)) > 0 then
  begin
    FIsFormUrlEncoded := True;
    if Length(FBody) > 0 then
    begin
      bodyStr := TEncoding.UTF8.GetString(FBody);
      ParseUrlEncodedParams(bodyStr);
    end;
  end;
end;

procedure THTTPRequestParser.DecodeChunkedEncoding(const ChunkedData: TBytes);
var
  i, ChunkSize, TotalSize: Integer;
  HexSize: string;
  ResultStream: TMemoryStream;
  IsInChunkSize: Boolean;
  IsInChunkData: Boolean;
  CR, LF: Byte;
begin
  ChunkSize := 0;
  CR := Byte(13);
  LF := Byte(10);

  ResultStream := TMemoryStream.Create;
  try
    i := 0;
    IsInChunkSize := True;
    IsInChunkData := False;
    HexSize := '';

    while i < Length(ChunkedData) do
    begin
      if IsInChunkSize then
      begin
        if ((ChunkedData[i] = CR) and (i + 1 < Length(ChunkedData)) and (ChunkedData[i+1] = LF)) then
        begin
          Inc(i, 2);

          if HexSize = '' then
            Break;

          try
            ChunkSize := StrToInt('$' + HexSize);
          except
            ChunkSize := 0;
          end;

          if ChunkSize = 0 then
            Break;

          IsInChunkSize := False;
          IsInChunkData := True;
          HexSize := '';
        end
        else
        begin
          var C: Char := Char(ChunkedData[i]);
          if CharInSet(C, ['0'..'9', 'a'..'f', 'A'..'F']) then
            HexSize := HexSize + C;
          Inc(i);
        end;
      end
      else if IsInChunkData then
      begin
        if ChunkSize > 0 then
        begin
          if i + ChunkSize <= Length(ChunkedData) then
          begin
            ResultStream.Write(ChunkedData[i], ChunkSize);
            Inc(i, ChunkSize);

            if (i + 1 < Length(ChunkedData)) and (ChunkedData[i] = CR) and (ChunkedData[i+1] = LF) then
              Inc(i, 2);

            IsInChunkData := False;
            IsInChunkSize := True;
          end
          else
          begin
            var AvailableSize := Length(ChunkedData) - i;
            ResultStream.Write(ChunkedData[i], AvailableSize);
            Inc(i, AvailableSize);
          end;
        end
        else
        begin
          IsInChunkData := False;
          IsInChunkSize := True;
        end;
      end;
    end;

    TotalSize := ResultStream.Size;
    if TotalSize > 0 then
    begin
      SetLength(FBody, TotalSize);
      ResultStream.Position := 0;
      ResultStream.Read(FBody[0], TotalSize);
    end
    else
    begin
      SetLength(FBody, 0);
    end;
  finally
    ResultStream.Free;
  end;
end;

procedure THTTPRequestParser.ParseHeaders(const HeaderSection: string);
var
 HeaderLines: TArray<string>;
 i, j: Integer;
 Line, CurrentHeaderName, CurrentHeaderValue: string;
 SeparatorPos: Integer;
 Header: THTTPHeader;
 TempHeader: THTTPHeader;
 ExistingHeader: Boolean;
 MultilineHeaderAllowed: Boolean;
 HeaderEnded: Boolean;
begin
 if Length(HeaderSection) = 0 then
   raise EHTTPHeaderError.Create(EMPTY_HEADER_SECTION);

 HeaderLines := HeaderSection.Split([#13#10]);

 if Length(HeaderLines) < 1 then
   raise EHTTPHeaderError.Create(INVALID_HEADER_FORMAT_NO_LINES);

 CurrentHeaderName := '';
 CurrentHeaderValue := '';
 MultilineHeaderAllowed := False;
 HeaderEnded := False;

 for i := 1 to High(HeaderLines) do
 begin
   Line := HeaderLines[i];

   if Line = '' then
   begin
     HeaderEnded := True;
     Break;
   end;

   if (Length(Line) > 0) and ((Line[1] = ' ') or (Line[1] = #9)) then
   begin
     if MultilineHeaderAllowed and (CurrentHeaderName <> '') then
       CurrentHeaderValue := CurrentHeaderValue + SPACE_SEPARATOR + TrimLeft(Line)
     else
       raise EHTTPHeaderError.CreateFmt(INVALID_FOLDED_HEADER_LINE, [Line]);

     Continue;
   end;

   if CurrentHeaderName <> '' then
   begin
     ExistingHeader := False;
     for j := 0 to FHeaders.Count - 1 do
     begin
       if SameText(FHeaders[j].Name, CurrentHeaderName) then
       begin
         TempHeader := FHeaders[j];

         if SameText(CurrentHeaderName, SET_COOKIE_HEADER) then
         begin
           TempHeader.Value := TempHeader.Value + SEMICOLON_SEPARATOR + CurrentHeaderValue;
           FHeaders[j] := TempHeader;
           ExistingHeader := True;
           Break;
         end
         else if SameText(CurrentHeaderName, CACHE_CONTROL_HEADER) or
                 SameText(CurrentHeaderName, ACCEPT_HEADER) or
                 SameText(CurrentHeaderName, ACCEPT_ENCODING_HEADER) or
                 SameText(CurrentHeaderName, ACCEPT_LANGUAGE_HEADER) then
         begin
           TempHeader.Value := TempHeader.Value + COMMA_SEPARATOR + CurrentHeaderValue;
           FHeaders[j] := TempHeader;
           ExistingHeader := True;
           Break;
         end;
       end;
     end;

     if not ExistingHeader then
     begin
       Header.Name := CurrentHeaderName;
       Header.Value := CurrentHeaderValue;
       FHeaders.Add(Header);
     end;

     CurrentHeaderName := '';
     CurrentHeaderValue := '';
     MultilineHeaderAllowed := False;
   end;

   SeparatorPos := Pos(':', Line);

   if SeparatorPos <= 0 then
     raise EHTTPHeaderError.CreateFmt(INVALID_HEADER_FORMAT_MISSING_COLON, [Line]);

   if SeparatorPos = 1 then
     raise EHTTPHeaderError.CreateFmt(INVALID_HEADER_FORMAT_EMPTY_NAME, [Line]);

   CurrentHeaderName := Trim(Copy(Line, 1, SeparatorPos - 1));
   CurrentHeaderValue := Trim(Copy(Line, SeparatorPos + 1, Length(Line)));

   if CurrentHeaderName = '' then
     raise EHTTPHeaderError.Create(EMPTY_HEADER_NAME_AFTER_TRIMMING);

   for j := 1 to Length(CurrentHeaderName) do
   begin
     if not (
       ((CurrentHeaderName[j] >= 'a') and (CurrentHeaderName[j] <= 'z')) or
       ((CurrentHeaderName[j] >= 'A') and (CurrentHeaderName[j] <= 'Z')) or
       ((CurrentHeaderName[j] >= '0') and (CurrentHeaderName[j] <= '9')) or
       (CurrentHeaderName[j] = '-') or (CurrentHeaderName[j] = '_')
     ) then
     begin
       raise EHTTPHeaderError.CreateFmt(
         INVALID_CHARACTER_IN_HEADER_NAME,
         [CurrentHeaderName, j, CurrentHeaderName[j]]);
     end;
   end;

   MultilineHeaderAllowed := True;
 end;

 if CurrentHeaderName <> '' then
 begin
   ExistingHeader := False;
   for j := 0 to FHeaders.Count - 1 do
   begin
     if SameText(FHeaders[j].Name, CurrentHeaderName) then
     begin
       TempHeader := FHeaders[j];

       if SameText(CurrentHeaderName, SET_COOKIE_HEADER) then
       begin
         TempHeader.Value := TempHeader.Value + SEMICOLON_SEPARATOR + CurrentHeaderValue;
         FHeaders[j] := TempHeader;
         ExistingHeader := True;
         Break;
       end
       else if SameText(CurrentHeaderName, CACHE_CONTROL_HEADER) or
               SameText(CurrentHeaderName, ACCEPT_HEADER) or
               SameText(CurrentHeaderName, ACCEPT_ENCODING_HEADER) or
               SameText(CurrentHeaderName, ACCEPT_LANGUAGE_HEADER) then
       begin
         TempHeader.Value := TempHeader.Value + COMMA_SEPARATOR + CurrentHeaderValue;
         FHeaders[j] := TempHeader;
         ExistingHeader := True;
         Break;
       end;
     end;
   end;

   if not ExistingHeader then
   begin
     Header.Name := CurrentHeaderName;
     Header.Value := CurrentHeaderValue;
     FHeaders.Add(Header);
   end;
 end;

 if not HeaderEnded and (Length(HeaderLines) > 1) then
   WriteLog(WARNING_HEADER);
end;

procedure THTTPRequestParser.WriteLog(log: string);
begin
  try
    if Assigned(FHttpLogger) then
      HttpLogger.Log(log);
  except
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


procedure THTTPRequestParser.ParseMultipartData;
var
  BoundaryBytes, EndBoundaryBytes, DoubleCRLF, DoubleLF: TBytes;
  i, BoundaryLen, EndBoundaryLen: Integer;
  HeaderStart, ContentStart, NextBoundary: Integer;
  CR, LF: Byte;
  Name, Filename, ContentType: string;
  FileObject: THTTPMultipartFile;
  ContentLength: Integer;
  TempStream: TMemoryStream;
  BodyLength: Integer;
begin
  BodyLength := Length(FBody);
  if BodyLength = 0 then
    Exit;

  CR := 13;
  LF := 10;

  BoundaryBytes := TEncoding.ASCII.GetBytes('--' + FBoundary);
  EndBoundaryBytes := TEncoding.ASCII.GetBytes('--' + FBoundary + '--');
  DoubleCRLF := TEncoding.ASCII.GetBytes(#13#10#13#10);
  DoubleLF := TEncoding.ASCII.GetBytes(#10#10);

  BoundaryLen := Length(BoundaryBytes);
  EndBoundaryLen := Length(EndBoundaryBytes);
  i := FastIndexOf(FBody, BoundaryBytes, 0, BodyLength);
  if i < 0 then
    Exit;

  i := i + BoundaryLen;

  if (i < BodyLength - 1) and (FBody[i] = CR) and (FBody[i + 1] = LF) then
    i := i + 2
  else if (i < BodyLength) and (FBody[i] = LF) then
    i := i + 1;

  while i < BodyLength do
  begin
    HeaderStart := i;
    var HeadersEndPos := FastIndexOf(FBody, DoubleCRLF, HeaderStart, BodyLength);
    if HeadersEndPos < 0 then
    begin
      HeadersEndPos := FastIndexOf(FBody, DoubleLF, HeaderStart, BodyLength);
      if HeadersEndPos < 0 then
        Break;

      ContentStart := HeadersEndPos + 2;
    end
    else
    begin
      ContentStart := HeadersEndPos + 4;
    end;

    var Headers := TEncoding.UTF8.GetString(FBody, HeaderStart, HeadersEndPos - HeaderStart);
    var NextBoundaryPos := FastIndexOf(FBody, BoundaryBytes, ContentStart, BodyLength);
    var EndBoundaryPos := FastIndexOf(FBody, EndBoundaryBytes, ContentStart, BodyLength);

    if (EndBoundaryPos >= 0) and ((NextBoundaryPos < 0) or (EndBoundaryPos < NextBoundaryPos)) then
    begin
      NextBoundary := EndBoundaryPos;
    end
    else
    begin
      NextBoundary := NextBoundaryPos;
    end;

    if NextBoundary < 0 then
      NextBoundary := BodyLength;

    var ContentEnd := NextBoundary;
    if (ContentEnd > 1) and (FBody[ContentEnd - 1] = LF) then
    begin
      if (ContentEnd > 2) and (FBody[ContentEnd - 2] = CR) then
        ContentEnd := ContentEnd - 2
      else
        ContentEnd := ContentEnd - 1;
    end;

    if ExtractContentDisposition(Headers, Name, Filename) then
    begin
      ContentType := ExtractContentType(Headers);
      ContentLength := ContentEnd - ContentStart;

      if ContentLength > 0 then
      begin
        if Filename <> '' then
        begin
          if IsLargeFile(ContentLength) then
          begin
            TempStream := TMemoryStream.Create;
            if FStreamingThreshold > 0 then
            begin
              TempStream.SetSize(ContentLength);
              Move(FBody[ContentStart], TempStream.Memory^, ContentLength);
              TempStream.Position := 0;
              FileObject := THTTPMultipartFile.CreateFromStream(Name, Filename, ContentType, TempStream, True);
            end
            else
            begin
              var MemoryStream := TCustomMemoryStream.Create;
              FileObject := THTTPMultipartFile.CreateFromStream(Name, Filename, ContentType, MemoryStream, True);
            end;

            FFiles.Add(FileObject);
          end
          else
          begin
            var Content: TBytes;
            SetLength(Content, ContentLength);
            Move(FBody[ContentStart], Content[0], ContentLength);
            FileObject := THTTPMultipartFile.Create(Name, Filename, ContentType, Content);
            FFiles.Add(FileObject);
          end;
        end
        else
        begin
          if ContentLength < 1024 then
          begin
            var Content: TBytes;
            SetLength(Content, ContentLength);
            Move(FBody[ContentStart], Content[0], ContentLength);
            FParams.AddOrSetValue(Name, TEncoding.UTF8.GetString(Content));
          end
          else
          begin
            FParams.AddOrSetValue(Name, TEncoding.UTF8.GetString(FBody, ContentStart, ContentLength));
          end;
        end;
      end;
    end;

    if NextBoundary < 0 then
      Break;
    i := NextBoundary + BoundaryLen;
    if (EndBoundaryPos >= 0) and (NextBoundary = EndBoundaryPos) then
      Break;
    if (i < BodyLength - 1) and (FBody[i] = CR) and (FBody[i + 1] = LF) then
      i := i + 2
    else if (i < BodyLength) and (FBody[i] = LF) then
      i := i + 1;
  end;
end;

function THTTPRequestParser.FastIndexOf(const Data, Pattern: TBytes; StartPos, DataLength: Integer): Integer;
var
  i, j, PatternLength, Skip: Integer;
  SkipTable: array[Byte] of Integer;
begin
  Result := -1;
  PatternLength := Length(Pattern);

  if (PatternLength = 0) or (StartPos + PatternLength > DataLength) then
    Exit;
  for i := 0 to 255 do
    SkipTable[i] := PatternLength;

  for i := 0 to PatternLength - 2 do
    SkipTable[Pattern[i]] := PatternLength - i - 1;

  i := StartPos + PatternLength - 1;
  while i < DataLength do
  begin
    j := PatternLength - 1;
    while (j >= 0) and (Data[i - (PatternLength - 1 - j)] = Pattern[j]) do
      Dec(j);

    if j < 0 then
    begin
      Result := i - (PatternLength - 1);
      Exit;
    end;

    Skip := SkipTable[Data[i]];
    Inc(i, Skip);
  end;
end;

function THTTPRequestParser.CompareBoundary(const Data: TBytes; Offset: Integer; const Boundary: TBytes): Boolean;
var
  i: Integer;
begin
  Result := False;
  if Offset + Length(Boundary) > Length(Data) then
    Exit;
  for i := 0 to Length(Boundary) - 1 do
  begin
    if Data[Offset + i] <> Boundary[i] then
      Exit;
  end;
  Result := True;
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
  ContentTypeLine := Copy(Headers, ContentTypePos, Length(Headers));
  EndLinePos := Pos(#13#10, ContentTypeLine);
  if EndLinePos > 0 then
    ContentTypeLine := Copy(ContentTypeLine, 1, EndLinePos - 1);
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


end.
