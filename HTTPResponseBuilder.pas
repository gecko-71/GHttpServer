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
    // Setting response status
    procedure SetStatus(AStatusCode: Integer; const AStatusText: string = '');
    // Adding header
    procedure AddHeader(const AName, AValue: string);
    function GetHeader(const AName: string): string;
    procedure RemoveHeader(const AName: string);
    // Adding Content
    function AddContent(const AName, AContentType: string): THTTPContentItem;
    function AddTextContent(const AName, AContentType, AContent: string; AEncoding: TEncoding = nil): THTTPContentItem;
    function AddBinaryContent(const AName, AContentType: string; const AData: TBytes): THTTPContentItem;
    function AddFileContent(const AName, AContentType, AFilename: string; const AData: TBytes): THTTPContentItem;
    function AddUploadedFile(const AName: string; const AFile: THTTPUploadedFile): THTTPContentItem;
    // Removing content
    procedure ClearContent;
    // Response status
    property StatusCode: Integer read FStatusCode write FStatusCode;
    property StatusText: string read FStatusText write FStatusText;
    property IsMultipart: Boolean read FIsMultipart write FIsMultipart;
    property Boundary: string read FBoundary;
    // Conversion to TBytes
    function ToBytes: TBytes;
    // Conversion to String
    function ToString: string; override;
    // Helper methods for quickly creating standard responses
    class function CreateOkResponse(const AContentType: string; const AContent: string): THTTPResponseBuilder;
    class function CreateJsonResponse(const AContent: string): THTTPResponseBuilder;
    class function CreateNotFoundResponse: THTTPResponseBuilder;
    class function CreateBadRequestResponse: THTTPResponseBuilder;
    class function CreateInternalErrorResponse: THTTPResponseBuilder;
  end;

implementation

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
  // Default headers
  AddHeader('Server', 'Delphi HTTPServer/1.0');
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
    // Standard HTTP statuses
    case AStatusCode of
      200: FStatusText := 'OK';
      201: FStatusText := 'Created';
      204: FStatusText := 'No Content';
      400: FStatusText := 'Bad Request';
      401: FStatusText := 'Unauthorized';
      403: FStatusText := 'Forbidden';
      404: FStatusText := 'Not Found';
      405: FStatusText := 'Method Not Allowed';
      500: FStatusText := 'Internal Server Error';
    else
      FStatusText := 'Unknown';
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
  // If we have more than one element, automatically set multipart
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
    // Calculating body length in multipart requires considering all parts,
    // headers and boundaries
    var TempBytes := BuildMultipartBody;
    Result := Length(TempBytes);
  end
  else if FContentItems.Count > 0 then
  begin
    // Check limit
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
  // Status line
  StatusLine := Format('HTTP/1.1 %d %s', [FStatusCode, FStatusText]);
  // Headers
  HeaderStr := '';
  for Key in FHeaders.Keys do
    HeaderStr := HeaderStr + Format('%s: %s'#13#10, [Key, FHeaders[Key]]);
  // If we have content, add appropriate headers
  if FContentItems.Count > 0 then
  begin
    if FIsMultipart then
    begin
      // For multipart
      if not FHeaders.ContainsKey('Content-Type') then
        HeaderStr := HeaderStr + Format('Content-Type: multipart/mixed; boundary=%s'#13#10, [FBoundary]);
    end
    else
    begin
      // For single part
      if not FHeaders.ContainsKey('Content-Type') then
        HeaderStr := HeaderStr + Format('Content-Type: %s'#13#10, [FContentItems[0].ContentType]);
    end;
    // Add Content-Length
    if not FHeaders.ContainsKey('Content-Length') then
      HeaderStr := HeaderStr + Format('Content-Length: %d'#13#10, [CalculateContentLength]);
  end
  else
  begin
    // If there is no content, set Content-Length: 0
    if not FHeaders.ContainsKey('Content-Length') then
      HeaderStr := HeaderStr + 'Content-Length: 0'#13#10;
  end;
  // Combine everything
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
  if (FContentItems.Count > 0) and (FContentItems[0].ContentType.Contains('text/') or
      FContentItems[0].ContentType.Contains('application/json') or
      FContentItems[0].ContentType.Contains('application/xml') or
      FContentItems[0].ContentType.Contains('charset=')) then
  begin
    Result := FContentItems[0].GetTextData;
  end
  else if FContentItems.Count > 0 then
  begin
    // For binary data return information about its length
    Result := Format('[Binary data, %d bytes]', [Length(FContentItems[0].Data)]);
  end
  else
    Result := '';
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
    BoundaryStart := '--' + FBoundary + #13#10;
    BoundaryEnd := '--' + FBoundary + '--' + #13#10;
    for Item in FContentItems do
    begin
      // Beginning of part
      TempBytes := TEncoding.ASCII.GetBytes(BoundaryStart);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));
      // Part headers
      HeaderStr := Format('Content-Type: %s'#13#10, [Item.ContentType]);
      if Item.Filename <> '' then
        HeaderStr := HeaderStr + Format('Content-Disposition: attachment; filename="%s"'#13#10, [Item.Filename])
      else if Item.Name <> '' then
        HeaderStr := HeaderStr + Format('Content-Disposition: form-data; name="%s"'#13#10, [Item.Name]);
      for Key in Item.Headers.Keys do
        HeaderStr := HeaderStr + Format('%s: %s'#13#10, [Key, Item.Headers[Key]]);
      HeaderStr := HeaderStr + #13#10; // Empty line after headers
      TempBytes := TEncoding.ASCII.GetBytes(HeaderStr);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));
      // Part data
      if Length(Item.Data) > 0 then
        MS.WriteBuffer(Item.Data[0], Length(Item.Data));
      // New line after part
      TempBytes := TEncoding.ASCII.GetBytes(#13#10);
      MS.WriteBuffer(TempBytes[0], Length(TempBytes));
    end;
    // Multipart ending
    TempBytes := TEncoding.ASCII.GetBytes(BoundaryEnd);
    MS.WriteBuffer(TempBytes[0], Length(TempBytes));
    // Conversion to TBytes
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
    BoundaryStart := '--' + FBoundary + #13#10;
    BoundaryEnd := '--' + FBoundary + '--' + #13#10;
    for Item in FContentItems do
    begin
      // Beginning of part
      SB.Append(BoundaryStart);
      // Part headers
      HeaderStr := Format('Content-Type: %s'#13#10, [Item.ContentType]);
      if Item.Filename <> '' then
        HeaderStr := HeaderStr + Format('Content-Disposition: attachment; filename="%s"'#13#10, [Item.Filename])
      else if Item.Name <> '' then
        HeaderStr := HeaderStr + Format('Content-Disposition: form-data; name="%s"'#13#10, [Item.Name]);
      for Key in Item.Headers.Keys do
        HeaderStr := HeaderStr + Format('%s: %s'#13#10, [Key, Item.Headers[Key]]);
      HeaderStr := HeaderStr + #13#10; // Empty line after headers
      SB.Append(HeaderStr);
      // Part data - check if it's textual data
      IsTextual := Item.ContentType.Contains('text/') or
                   Item.ContentType.Contains('application/json') or
                   Item.ContentType.Contains('application/xml') or
                   Item.ContentType.Contains('charset=');
      if IsTextual then
        SB.Append(Item.GetTextData)
      else
        SB.AppendFormat('[Binary data, %d bytes]', [Length(Item.Data)]);
      // New line after part
      SB.Append(#13#10);
    end;
    // Multipart ending
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
  // Generating header section
  HeadersBytes := TEncoding.ASCII.GetBytes(BuildHeadersSection);
  HeadersLength := Length(HeadersBytes);
  // Generating body section
  if FIsMultipart then
    BodyBytes := BuildMultipartBody
  else
    BodyBytes := BuildSingleBody;
  BodyLength := Length(BodyBytes);
  // Combining headers and body
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
  // Generating header section
  HeadersStr := BuildHeadersSection;
  // Generating body section as string
  if FIsMultipart then
    BodyStr := BuildMultipartBodyAsString
  else
    BodyStr := BuildSingleBodyAsString;
  Result := HeadersStr + BodyStr;
end;

// Helper class methods for quickly creating standard responses
class function THTTPResponseBuilder.CreateOkResponse(const AContentType: string;
  const AContent: string): THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(200);
  Result.AddTextContent('content', AContentType, AContent);
end;

class function THTTPResponseBuilder.CreateJsonResponse(const AContent: string): THTTPResponseBuilder;
begin
  Result := CreateOkResponse('application/json; charset=utf-8', AContent);
end;

class function THTTPResponseBuilder.CreateNotFoundResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(404);
  Result.AddTextContent('error', 'text/plain', 'Not Found');
end;

class function THTTPResponseBuilder.CreateBadRequestResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(400);
  Result.AddTextContent('error', 'text/plain', 'Bad Request');
end;

class function THTTPResponseBuilder.CreateInternalErrorResponse: THTTPResponseBuilder;
begin
  Result := THTTPResponseBuilder.Create;
  Result.SetStatus(500);
  Result.AddTextContent('error', 'text/plain', 'Internal Server Error');
end;
end.
