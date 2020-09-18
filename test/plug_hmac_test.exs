defmodule ExAuthTest do
  use ExUnit.Case
  doctest PlugHmac

  defmodule ErrorHandler do
    @behaviour PlugHmac.ErrorHandler

    def handle(conn, _error) do
      conn
    end
  end

  defmodule SecretHandler do
    @behaviour PlugHmac.SecretHandler

    def get_secret("test_id") do
      {:ok, "/dXOQgl57dXHT5LxHgtjXrxcbgGrUODvVZjcC8h4iFhTLGVTlwZw0W+vsA2lCOK8"}
    end

    def get_secret(_) do
      {:error, :secret_not_found}
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
    conn =
      make_conn(%{
        "id" => "test_id",
        "method" => "GET",
        "path" => "/api/test_auth",
        "query_string" => "a1=123&a2=456",
        "body" => ""
      })

    body_conn =
      make_conn(%{
        "id" => "test_id",
        "method" => "POST",
        "path" => "/api/test_auth",
        "query_string" => "",
        "body" => "{\"hello\": \"world\"}"
      })

    secret_handler = &SecretHandler.get_secret/1

    assert PlugHmac.check_sign?(
             :sha256,
             secret_handler,
             %{
               "id" => "test_id",
               "nonce" => "asd123"
             },
             conn
           ) == false

    assert PlugHmac.check_sign?(
             :sha256,
             secret_handler,
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => ""
             },
             conn
           ) == false

    assert PlugHmac.check_sign?(
             :sha256,
             secret_handler,
             %{
               "id" => "test_id",
               "nonce" => "asd123",
               "signature" => "error_sign"
             },
             conn
           ) == false

    nonce = PlugHmac.make_nonce()

    "hmac " <> credential =
      PlugHmac.make_header(
        :sha256,
        SecretHandler,
        "test_id",
        conn.method,
        conn.request_path,
        conn.query_string,
        conn.assigns[:raw_body],
        nonce
      )

    credential = PlugHmac.split_params_from_string(credential)

    assert PlugHmac.check_sign?(:sha256, secret_handler, credential, conn) == true

    nonce = PlugHmac.make_nonce()

    "hmac " <> credential =
      PlugHmac.make_header(
        :sha256,
        SecretHandler,
        "test_id",
        body_conn.method,
        body_conn.request_path,
        body_conn.query_string,
        body_conn.assigns[:raw_body],
        nonce
      )

    credential = PlugHmac.split_params_from_string(credential)

    assert PlugHmac.check_sign?(:sha256, secret_handler, credential, body_conn) == true
  end

  test "plug init" do
    assert PlugHmac.init(
             error_handler: ErrorHandler,
             secret_handler: SecretHandler,
             hmac_algo: :sha256
           )
           |> is_list() == true

    assert_raise RuntimeError,
                 ~r/^check_opts_error*/,
                 fn -> PlugHmac.init([]) end

    assert_raise RuntimeError,
                 ~r/^check_opts_error*/,
                 fn -> PlugHmac.init(error_handler: 1) end

    assert_raise RuntimeError,
                 ~r/^check_opts_error*/,
                 fn -> PlugHmac.init(error_handler: & &1) end
  end

  test "plug call" do
    conn =
      make_conn(%{
        "id" => "test_id",
        "method" => "GET",
        "path" => "/api/test_auth",
        "query_string" => "a1=123&a2=456",
        "body" => ""
      })

    error_handler = ErrorHandler
    secret_handler = &SecretHandler.get_secret/1
    hmac_algo = :sha256

    assert PlugHmac.call(conn,
             error_handler: error_handler,
             secret_handler: secret_handler,
             hmac_algo: hmac_algo
           ).halted == false

    assert PlugHmac.call(%{conn | method: "POST"},
             error_handler: error_handler,
             secret_handler: secret_handler,
             hmac_algo: hmac_algo
           ).halted == true
  end

  def make_conn(map) do
    id = Map.get(map, "id")
    method = Map.get(map, "method")
    path = Map.get(map, "path")
    query_string = Map.get(map, "query_string", "")
    body = Map.get(map, "body", "")

    string = PlugHmac.make_header(:sha256, SecretHandler, id, method, path, query_string, body)

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
