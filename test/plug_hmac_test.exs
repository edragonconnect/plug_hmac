defmodule ExAuthTest do
  use ExUnit.Case
  doctest PlugHmac

  defmodule Handler do
    def auth_error(conn, _error) do
      conn
    end
  end

  test "split params from string" do
    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce=asd123"
    assert PlugHmac.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "asd123",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }

    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce="
    assert PlugHmac.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }

    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce"
    assert PlugHmac.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }
  end

  test "check signature" do
    Application.put_env(
      :plug_hmac,
      :secrets,
      %{"test_id" => "/dXOQgl57dXHT5LxHgtjXrxcbgGrUODvVZjcC8h4iFhTLGVTlwZw0W+vsA2lCOK8"}
    )

    conn = make_conn(
      %{
        "id" => "test_id",
        "method" => "GET",
        "path" => "/api/test_auth",
        "query_string" => "a1=123&a2=456",
        "body" => ""
      }
    )

    body_conn = make_conn(
      %{
        "id" => "test_id",
        "method" => "POST",
        "path" => "/api/test_auth",
        "query_string" => "",
        "body" => "{\"hello\": \"world\"}"
      }
    )

    assert PlugHmac.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123"
             },
             conn
           ) == false

    assert PlugHmac.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => ""
             },
             conn
           ) == false

    assert PlugHmac.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => "error_sign"
             },
             conn
           ) == false

    assert PlugHmac.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "R/FZs7+3lVLa5ElXTust",
               "signature" => "xgKFxeIO0TeNZNyjZl/6vffYGZf2ZttPDTZElziCgeE="
             },
             conn
           ) == true

    assert PlugHmac.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "R/FZs7+3lVLa5ElXTust",
               "signature" => "wFFcDWCXFNn54+x23WoJahn4BxUJzhw5kQ5TjbQq92M="
             },
             body_conn
           ) == true

  end

  test "plug init" do
    error_handler = fn c, _error -> c end

    assert PlugHmac.init(error_handler: error_handler)
           |> is_list() == true

    assert PlugHmac.init(error_handler: Handler)
           |> is_list() == true

    assert_raise RuntimeError,
                 "Must defined error_handler when use the PlugHmac plug.",
                 fn -> PlugHmac.init([]) end

    assert_raise RuntimeError,
                 "Wrong error_handler: 1",
                 fn -> PlugHmac.init([error_handler: 1]) end

    assert_raise RuntimeError,
                 ~r/^Wrong error_handler:*/,
                 fn -> PlugHmac.init([error_handler: & &1]) end
  end

  test "plug call" do
    Application.put_env(
      :plug_hmac,
      :secrets,
      %{"test_id" => "/dXOQgl57dXHT5LxHgtjXrxcbgGrUODvVZjcC8h4iFhTLGVTlwZw0W+vsA2lCOK8"}
    )

    conn = make_conn(
      %{
        "id" => "test_id",
        "method" => "GET",
        "path" => "/api/test_auth",
        "query_string" => "a1=123&a2=456",
        "body" => ""
      }
    )

    error_handler = fn c, _error -> c end

    assert PlugHmac.call(conn, error_handler: error_handler).halted == false

    assert PlugHmac.call(%{conn | method: "POST"}, error_handler: error_handler).halted == true
  end

  def make_conn(map) do
    id = Map.get(map, "id")
    method = Map.get(map, "method")
    path = Map.get(map, "path")
    query_string = Map.get(map, "query_string", "")
    body = Map.get(map, "body", "")

    string = PlugHmac.make_header(id, method, path, query_string, body)
    %Plug.Conn{
      req_headers: [{"authorization", string}],
      method: method,
      request_path: path,
      query_string: query_string,
      assigns: %{
        raw_body: body
      }
    }
  end
end