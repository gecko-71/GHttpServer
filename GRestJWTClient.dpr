program GRestJWTClient;

{$APPTYPE CONSOLE}
uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.NetEncoding;

var
  HttpClient: THTTPClient;
  Response: IHTTPResponse;
  LoginJson, ResponseJson: TJSONObject;
  Token: string;
begin
  try
      HttpClient := THTTPClient.Create;
      try
        HttpClient.ConnectionTimeout := 3000;
        HttpClient.ResponseTimeout := 3000;
        WriteLn('=== Test GRestSvrJWTPrj ===');
        WriteLn;

        WriteLn('1. Getting JWT token...');
        LoginJson := TJSONObject.Create;
        try
          LoginJson.AddPair('username', 'admin');
          LoginJson.AddPair('password', 'admin');
          try
            Response := HttpClient.Post(
              'http://localhost:3042/api/token',
              TStringStream.Create(LoginJson.ToJSON),
              nil,
              TNetHeaders.Create(TNameValuePair.Create('Content-Type', 'application/json'))
            );
            WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
            WriteLn('Response: ', Response.ContentAsString);
            WriteLn;
            if Response.StatusCode = 200 then
            begin
              ResponseJson := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
              try
                if Assigned(ResponseJson) then
                begin
                  Token := ResponseJson.GetValue<string>('token', '');
                  if Token <> '' then
                  begin
                    WriteLn('JWT Token obtained successfully!');

                    WriteLn('2. Calling protected endpoint with JWT token...');
                    try
                      Response := HttpClient.Get(
                        'http://localhost:3042/api/autotest',
                        nil,
                        TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer ' + Token))
                      );
                      WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
                      WriteLn('Response: ', Response.ContentAsString);
                      WriteLn;

                      WriteLn('3. Calling protected endpoint with invalid token...');
                      Response := HttpClient.Get(
                        'http://localhost:3042/api/autotest',
                        nil,
                        TNetHeaders.Create(TNameValuePair.Create('Authorization', 'Bearer invalid.token.value'))
                      );
                      WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
                      WriteLn('Response: ', Response.ContentAsString);
                      WriteLn;

                      WriteLn('4. Calling protected endpoint without token...');
                      Response := HttpClient.Get('http://localhost:3042/api/autotest');
                      WriteLn('Status: ', Response.StatusCode, ' ', Response.StatusText);
                      WriteLn('Response: ', Response.ContentAsString);
                      WriteLn;
                    except
                      on E: Exception do
                        WriteLn('Error calling protected endpoint: ', E.Message);
                    end;
                  end
                  else
                    WriteLn('Error: Token not found in response.');
                end
                else
                  WriteLn('Error: Invalid JSON response.');
              finally
                ResponseJson.Free;
              end;
            end
            else
              WriteLn('Error: Could not obtain token. Check if server is running.');
          except
            on E: Exception do
              WriteLn('Error obtaining token: ', E.Message);
          end;
        finally
          LoginJson.Free;
        end;
      finally
        HttpClient.Free;
      end;
      WriteLn;
      WriteLn('=== End of test ===');
      WriteLn('Press Enter to exit...');
      ReadLn;
  except
    on E: Exception do
    begin
      WriteLn('Unexpected error: ', E.Message);
      ReadLn;
    end;
  end;
end.
