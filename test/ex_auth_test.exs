defmodule ExAuthTest do
  use ExUnit.Case
  doctest ExAuth

  defmodule Handler do
    def auth_error(conn, _error) do
      conn
    end
  end
  defmodule WrongHandler do
    def auth_error(conn) do
      conn
    end
  end

  test "split params from string" do
    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce=asd123"
    assert ExAuth.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "asd123",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }

    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce="
    assert ExAuth.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }

    string = "id=test_id,signature=hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk%3D,nonce"
    assert ExAuth.split_params_from_string(string) == %{
             "id" => "test_id",
             "nonce" => "",
             "signature" => "hMQB2X2ATYntgVskMVW0qOOn729J0mipCvQtqmWnQrk="
           }
  end

  test "check signature" do
    Application.put_env(
      :ex_auth,
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

    assert ExAuth.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123"
             },
             conn
           ) == false

    assert ExAuth.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => ""
             },
             conn
           ) == false

    assert ExAuth.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => "error_sign"
             },
             conn
           ) == false

    assert ExAuth.check_sign?(
             %{
               "id" => "test_id",
               "nonce" => "R/FZs7+3lVLa5ElXTust",
               "signature" => "xgKFxeIO0TeNZNyjZl/6vffYGZf2ZttPDTZElziCgeE="
             },
             conn
           ) == true

    assert ExAuth.check_sign?(
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

    assert ExAuth.init(error_handler: error_handler)
           |> is_list() == true

    assert ExAuth.init(error_handler: Handler)
           |> is_list() == true

    assert_raise RuntimeError,
                 "Must defined auth_error/2 for Elixir.ExAuthTest.WrongHandler when use the ExAuth plug.",
                 fn -> ExAuth.init(error_handler: WrongHandler) end

    assert_raise RuntimeError,
                 "Must defined error_handler when use the ExAuth plug.",
                 fn -> ExAuth.init([]) end

    assert_raise RuntimeError,
                 "Wrong error_handler: 1",
                 fn -> ExAuth.init([error_handler: 1]) end

    assert_raise RuntimeError,
                 ~r/^Wrong error_handler:*/,
                 fn -> ExAuth.init([error_handler: & &1]) end
  end

  test "plug call" do
    Application.put_env(
      :ex_auth,
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

    assert ExAuth.call(conn, error_handler: error_handler).halted == false

    assert ExAuth.call(%{conn | method: "POST"}, error_handler: error_handler).halted == true
  end

  def make_conn(map) do
    id = Map.get(map, "id")
    method = Map.get(map, "method")
    path = Map.get(map, "path")
    query_string = Map.get(map, "query_string", "")
    body = Map.get(map, "body", "")

    string = ExAuth.make_header(id, method, path, query_string, body)
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
