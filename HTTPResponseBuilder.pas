{
  HTTPResponseBuilder - Simple HTTP Server Component
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

unit HTTPResponseBuilder;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections, System.NetEncoding,
  System.Hash, IdGlobalProtocols;

type
  // Class for building responses
  THTTPUploadedFile = class
  private
    FFilename: string;
    FContentType: string;
    FData: TBytes;
  public
    constructor Create(const AFilename, AContentType: string; const AData: TBytes);
    property Filename: string read FFilename write FFilename;
    property ContentType: string read FContentType write FContentType;
    property Data: TBytes read FData write FData;
  end;
  THTTPContentItem = class
  private
    FName: string;
    FContentType: string;
    FData: TBytes;
    FHeaders: TDictionary<string, string>;
    FFilename: string;
  public
    constructor Create(const AName, AContentType: string);
    destructor Destroy; override;
    property Name: string read FName write FName;
    property ContentType: string read FContentType write FContentType;
    property Data: TBytes read FData write FData;
    property Headers: TDictionary<string, string> read FHeaders;
    property Filename: string read FFilename write FFilename;
    procedure AddHeader(const AName, AValue: string);
    procedure SetTextData(const AText: string; AEncoding: TEncoding = nil);
    function GetTextData(AEncoding: TEncoding = nil): string;
  end;

  THTTPResponseBuilder = class
  private
    FStatusCode: Integer;
    FStatusText: string;
    FHeaders: TDictionary<string, string>;
    FContentItems: TObjectList<THTTPContentItem>;
    FBoundary: string;
    FIsMultipart: Boolean;
    function GenerateRandomBoundary: string;
    function CalculateContentLength: Integer;
    function BuildHeadersSection: string;
    function BuildMultipartBody: TBytes;
    function BuildSingleBody: TBytes;
    function BuildMultipartBodyAsString: string;
    function BuildSingleBodyAsString: string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SetStatus(AStatusCode: Integer; const AStatusText: string = '');
    procedure AddHeader(const AName, AValue: string);
    function GetHeader(const AName: string): string;
    procedure RemoveHeader(const AName: string);
    function AddContent(const AName, AContentType: string): THTTPContentItem;
    function AddTextContent(const AName, AContentType, AContent: string; AEncoding: TEncoding = nil): THTTPContentItem;
    function AddBinaryContent(const AName, AContentType: string; const AData: TBytes): THTTPContentItem;
    function AddFileContent(const AName, AContentType, AFilename: string; const AData: TBytes): THTTPContentItem;
    function AddUploadedFile(const AName: string; const AFile: THTTPUploadedFile): THTTPContentItem;
    procedure ClearContent;
    property StatusCode: Integer read FStatusCode write FStatusCode;
    property StatusText: string read FStatusText write FStatusText;
    property IsMultipart: Boolean read FIsMultipart write FIsMultipart;
    property Boundary: string read FBoundary;
    function ToBytes: TBytes;
    function ToString: string; override;
    class function CreateOkResponse(const AContentType: string; const AContent: string): THTTPResponseBuilder;
    class function CreateJsonResponse(const AContent: string): THTTPResponseBuilder;
    class function CreateNotFoundResponse: THTTPResponseBuilder;
    class function CreateBadRequestResponse: THTTPResponseBuilder;
    class function CreateInternalErrorResponse: THTTPResponseBuilder;
  end;

implementation

uses GHTTPConstants;

{ THTTPUploadedFile }
constructor THTTPUploadedFile.Create(const AFilename, AContentType: string; const AData: TBytes);
begin
  inherited Create;
  FFilename := AFilename;
  FContentType := AContentType;
  FData := AData;
end;

{ THTTPContentItem }
constructor THTTPContentItem.Create(const AName, AContentType: string);
begin
  inherited Create;
  FName := AName;
  FContentType := AContentType;
  FHeaders := TDictionary<string, string>.Create;
end;

destructor THTTPContentItem.Destroy;
begin
  FHeaders.Free;
  inherited;
end;

procedure THTTPContentItem.AddHeader(const AName, AValue: string);
begin
  FHeaders.AddOrSetValue(AName, AValue);
end;

procedure THTTPContentItem.SetTextData(const AText: string; AEncoding: TEncoding);
begin
  if AEncoding = nil then
    AEncoding := TEncoding.UTF8;
  FData := AEncoding.GetBytes(AText);
end;

function THTTPContentItem.GetTextData(AEncoding: TEncoding = nil): string;
begin
  if AEncoding = nil then
    AEncoding := TEncoding.UTF8;
  if Length(FData) > 0 then
    Result := AEncoding.GetString(FData)
  else
    Result := '';
end;

{ THTTPResponseBuilder }
constructor THTTPResponseBuilder.Create;
begin
  inherited Create;
  FStatusCode := 200;
  FStatusText := 'OK';
  FHeaders := TDictionary<string, string>.Create;
  FContentItems := TObjectList<THTTPContentItem>.Create(True);
  FBoundary := GenerateRandomBoundary;
  FIsMultipart := False;
  AddHeader('Server', 'GHTTPServer/1.0');
  AddHeader('Connection', 'close');
  AddHeader('Date', FormatDateTime('ddd, dd mmm yyyy hh:nn:ss', Now) + ' GMT');
end;

destructor THTTPResponseBuilder.Destroy;
begin
  FHeaders.Free;
  FContentItems.Free;
  inherited;
end;

function THTTPResponseBuilder.GenerateRandomBoundary: string;
var
  Guid: TGUID;
begin
  CreateGUID(Guid);
  Result := 'boundary-' + GUIDToString(Guid).Replace('{', '').Replace('}', '').Replace('-', '');
end;

procedure THTTPResponseBuilder.SetStatus(AStatusCode: Integer; const AStatusText: string);
begin
  FStatusCode := AStatusCode;
  if AStatusText = '' then
  begin
    case AStatusCode of
      HTTP_STATUS_OK: FStatusText := HTTP_MSG_OK;
      HTTP_STATUS_CREATED: FStatusText := HTTP_MSG_CREATED;
      HTTP_STATUS_NO_CONTENT: FStatusText := HTTP_MSG_NO_CONTENT;
      HTTP_STATUS_BAD_REQUEST: FStatusText := HTTP_MSG_BAD_REQUEST;
      HTTP_STATUS_UNAUTHORIZED: FStatusText := HTTP_MSG_UNAUTHORIZED;
      HTTP_STATUS_FORBIDDEN: FStatusText := HTTP_MSG_FORBIDDEN;
      HTTP_STATUS_NOT_FOUND: FStatusText := HTTP_MSG_NOT_FOUND;
      HTTP_STATUS_METHOD_NOT_ALLOWED: FStatusText := HTTP_MSG_METHOD_NOT_ALLOWED;
      HTTP_STATUS_INTERNAL_SERVER_ERROR: FStatusText := HTTP_MSG_INTERNAL_SERVER_ERROR;
    else
      FStatusText := IP_VALUE_UNKNOWN;
    end;
  end
  else
    FStatusText := AStatusText;
end;

procedure THTTPResponseBuilder.AddHeader(const AName, AValue: string);
begin
  FHeaders.AddOrSetValue(AName, AValue);
end;

function THTTPResponseBuilder.GetHeader(const AName: string): string;
begin
  if not FHeaders.TryGetValue(AName, Result) then
    Result := '';
end;

procedure THTTPResponseBuilder.RemoveHeader(const AName: string);
begin
  FHeaders.Remove(AName);
end;

function THTTPResponseBuilder.AddContent(const AName, AContentType: string): THTTPContentItem;
begin
  Result := THTTPContentItem.Create(AName, AContentType);
  FContentItems.Add(Result);
  if FContentItems.Count > 1 then
    FIsMultipart := True;
end;

function THTTPResponseBuilder.AddTextContent(const AName, AContentType, AContent: string;
  AEncoding: TEncoding): THTTPContentItem;
begin
  Result := AddContent(AName, AContentType);
  Result.SetTextData(AContent, AEncoding);
end;

function THTTPResponseBuilder.AddBinaryContent(const AName, AContentType: string;
  const AData: TBytes): THTTPContentItem;
begin
  Result := AddContent(AName, AContentType);
  Result.Data := AData;
end;

function THTTPResponseBuilder.AddFileContent(const AName, AContentType, AFilename: string;
  const AData: TBytes): THTTPContentItem;
begin
  Result := AddBinaryContent(AName, AContentType, AData);
  Result.Filename := AFilename;
  Result.AddHeader('Content-Disposition', Format('attachment; filename="%s"', [AFilename]));
end;

function THTTPResponseBuilder.AddUploadedFile(const AName: string;
  const AFile: THTTPUploadedFile): THTTPContentItem;
begin
  if AFile = nil then
    Result := nil
  else
    Result := AddFileContent(AName, AFile.ContentType, AFile.Filename, AFile.Data);
end;

procedure THTTPResponseBuilder.ClearContent;
begin
  FContentItems.Clear;
  FIsMultipart := False;
end;

function THTTPResponseBuilder.CalculateContentLength: Integer;
begin
  if FIsMultipart then
  begin
    var TempBytes := BuildMultipartBody;
    Result := Length(TempBytes);
  end
  else if FContentItems.Count > 0 then
  begin
    Result := Length(FContentItems[0].Data);
  end
  else
    Result := 0;
end;

function THTTPResponseBuilder.BuildHeadersSection: string;
var
  StatusLine: string;
  HeaderStr: string;
  Key: string;
begin
  StatusLine := Format('HTTP/1.1 %d %s', [FStatusCode, FStatusText]);
  HeaderStr := '';
  for Key in FHeaders.Keys do
    HeaderStr := HeaderStr + Format('%s: %s'#13#10, [Key, FHeaders[Key]]);
  if FContentItems.Count > 0 then
  begin
    if FIsMultipart then
    begin
      if not FHeaders.ContainsKey('Content-Type') then
        HeaderStr := HeaderStr + Format('Content-Type: multipart/mixed; boundary=%s'#13#10, [FBoundary]);
    end
    else
    begin
      if not FHeaders.ContainsKey('Content-Type') then
        HeaderStr := HeaderStr + Format('Content-Type: %s'#13#10, [FContentItems[0].ContentType]);
    end;
    if not FHeaders.ContainsKey('Content-Length') then
      HeaderStr := HeaderStr + Format('Content-Length: %d'#13#10, [CalculateContentLength]);
  end
  else
  begin
    if not FHeaders.ContainsKey('Content-Length') then
      HeaderStr := HeaderStr + 'Content-Length: 0'#13#10;
  end;
  Result := StatusLine + #13#10 + HeaderStr + #13#10;
end;

function THTTPResponseBuilder.BuildSingleBody: TBytes;
begin
  if FContentItems.Count > 0 then
    Result := FContentItems[0].Data
  else
    SetLength(Result, 0);
end;

function THTTPResponseBuilder.BuildSingleBodyAsString: string;
begin
  if (FContentItems.Count > 0) and (FContentItems[0].ContentType.Contains(CONTENT_TYPE_TEXT_PREFIX) or
      FContentItems[0].ContentType.Contains(MIME_TYPE_JSON) or
      FContentItems[0].ContentType.Contains(MIME_TYPE_XML) or
      FContentItems[0].ContentType.Contains(CONTENT_TYPE_CHARSET)) then
  begin
    Result := FContentItems[0].GetTextData;
  end
  else if FContentItems.Count > 0 then
  begin
    Result := Format(BINARY_DATA_FORMAT, [Length(FContentItems[0].Data)]);
  end
  else
    Result := EMPTY_STRING;
end;

function THTTPResponseBuilder.BuildMultipartBody: TBytes;
var
  MS: TMemoryStream;
  Item: THTTPContentItem;
  BoundaryStart, BoundaryEnd: string;
  HeaderStr: string;
  Key: string;
  TempBytes: TBytes;
begin
  MS := TMemoryStream.Create;
  try
    BoundaryStart := Format(BOUNDARY_START_FORMAT, [FBoundary]);
    BoundaryEnd := Format(BOUNDARY_END_FORMAT, [FBoundary]);

    for Item in FContentItems do
    begin
      TempBytes := TEncoding.ASCII.GetBytes(BoundaryStart);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));

      HeaderStr := Format(HEADER_CONTENT_TYPE_FORMAT, [Item.ContentType]);

      if Item.Filename <> EMPTY_STRING then
        HeaderStr := HeaderStr + Format(HEADER_CONTENT_DISPOSITION_ATTACHMENT, [Item.Filename])
      else if Item.Name <> EMPTY_STRING then
        HeaderStr := HeaderStr + Format(HEADER_CONTENT_DISPOSITION_FORM_DATA, [Item.Name]);

      for Key in Item.Headers.Keys do
        HeaderStr := HeaderStr + Format(HEADER_CUSTOM_FORMAT, [Key, Item.Headers[Key]]);

      HeaderStr := HeaderStr + CRLF;
      TempBytes := TEncoding.ASCII.GetBytes(HeaderStr);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));

      if Length(Item.Data) > 0 then
        MS.WriteBuffer(Item.Data[0], Length(Item.Data));

      TempBytes := TEncoding.ASCII.GetBytes(CRLF);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));
    end;

    TempBytes := TEncoding.ASCII.GetBytes(BoundaryEnd);
    MS.WriteBuffer(TempBytes[0], Length(TempBytes));

    SetLength(Result, MS.Size);
    MS.Position := 0;
    MS.ReadBuffer(Result[0], MS.Size);
  finally
    MS.Free;
  end;
end;

function THTTPResponseBuilder.BuildMultipartBodyAsString: string;
var
  SB: TStringBuilder;
  Item: THTTPContentItem;
  BoundaryStart, BoundaryEnd: string;
  HeaderStr: string;
  Key: string;
  IsTextual: Boolean;
begin
  SB := TStringBuilder.Create;
  try
    BoundaryStart := Format(BOUNDARY_START_FORMAT, [FBoundary]);
    BoundaryEnd := Format(BOUNDARY_END_FORMAT, [FBoundary]);

    for Item in FContentItems do
    begin
      SB.Append(BoundaryStart);

      HeaderStr := Format(HEADER_CONTENT_TYPE_FORMAT, [Item.ContentType]);

      if Item.Filename <> EMPTY_STRING then
        HeaderStr := HeaderStr + Format(HEADER_CONTENT_DISPOSITION_ATTACHMENT, [Item.Filename])
      else if Item.Name <> EMPTY_STRING then
        HeaderStr := HeaderStr + Format(HEADER_CONTENT_DISPOSITION_FORM_DATA, [Item.Name]);

      for Key in Item.Headers.Keys do
        HeaderStr := HeaderStr + Format(HEADER_CUSTOM_FORMAT, [Key, Item.Headers[Key]]);

      HeaderStr := HeaderStr + CRLF;
      SB.Append(HeaderStr);

      IsTextual := Item.ContentType.Contains(CONTENT_TYPE_TEXT_PREFIX) or
                   Item.ContentType.Contains(MIME_TYPE_JSON) or
                   Item.ContentType.Contains(MIME_TYPE_XML) or
                   Item.ContentType.Contains(CONTENT_TYPE_CHARSET);

      if IsTextual then
        SB.Append(Item.GetTextData)
      else
        SB.AppendFormat(BINARY_DATA_FORMAT, [Length(Item.Data)]);

      SB.Append(CRLF);
    end;

    SB.Append(BoundaryEnd);
    Result := SB.ToString;
  finally
    SB.Free;
  end;
end;

function THTTPResponseBuilder.ToBytes: TBytes;
var
  HeadersBytes, BodyBytes, ResultBytes: TBytes;
  HeadersLength, BodyLength: Integer;
begin
  HeadersBytes := TEncoding.ASCII.GetBytes(BuildHeadersSection);
  HeadersLength := Length(HeadersBytes);
  if FIsMultipart then
    BodyBytes := BuildMultipartBody
  else
    BodyBytes := BuildSingleBody;
  BodyLength := Length(BodyBytes);
  SetLength(ResultBytes, HeadersLength + BodyLength);
  if HeadersLength > 0 then
    Move(HeadersBytes[0], ResultBytes[0], HeadersLength);
  if BodyLength > 0 then
    Move(BodyBytes[0], ResultBytes[HeadersLength], BodyLength);
  Result := ResultBytes;
end;

function THTTPResponseBuilder.ToString: string;
var
  HeadersStr: string;
  BodyStr: string;
begin
  HeadersStr := BuildHeadersSection;
  if FIsMultipart then
    BodyStr := BuildMultipartBodyAsString
  else
    BodyStr := BuildSingleBodyAsString;
  Result := HeadersStr + BodyStr;
end;

class function THTTPResponseBuilder.CreateOkResponse(const AContentType: string;
  const AContent: string): THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(200);
  Result.AddTextContent('content', AContentType, AContent);
end;

class function THTTPResponseBuilder.CreateJsonResponse(const AContent: string): THTTPResponseBuilder;
begin
  Result := CreateOkResponse(MIME_TYPE_JSON_UTF8, AContent);
end;

class function THTTPResponseBuilder.CreateNotFoundResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(HTTP_STATUS_NOT_FOUND);
  Result.AddTextContent(ERR_ERROR, MIME_TYPE_TEXT, HTTP_MSG_NOT_FOUND);
end;

class function THTTPResponseBuilder.CreateBadRequestResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(HTTP_STATUS_BAD_REQUEST);
  Result.AddTextContent(ERR_ERROR, MIME_TYPE_TEXT, HTTP_MSG_BAD_REQUEST);
end;

class function THTTPResponseBuilder.CreateInternalErrorResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR);
  Result.AddTextContent(ERR_ERROR, MIME_TYPE_TEXT, HTTP_MSG_INTERNAL_SERVER_ERROR);
end;

end.
