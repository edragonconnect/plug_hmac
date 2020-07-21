defmodule PlugHmac do
  @moduledoc """
  A Plug to validate and generate `Authorization` header.
  Authorization = hmac id=URI_encode(client_id),signature=URI_encode(Signature),nonce=URI_encode(Nonce)
  Signature = HMAC_SHA256(client_secret, HTTP verb + Path + Query string + Body + Nonce )
  Nonce = Random string
  """
  @behaviour Plug
  import Plug.Conn

  def init(opts) do
    case opts[:error_handler] do
      nil ->
        raise "Must defined error_handler when use the PlugHmac plug."
      error_handler when is_atom(error_handler) ->
        Keyword.put(opts, :error_handler, &error_handler.auth_error/2)
      error_handler when is_function(error_handler, 2) ->
        opts
      error_handler ->
        raise "Wrong error_handler: #{inspect(error_handler)}"
    end
  end

  def call(conn, opts) do
    case get_req_header(conn, "authorization") do
      ["hmac " <> credential] ->
        credential = split_params_from_string(credential)

        if check_sign?(credential, conn) do
          assign(conn, :client_id, credential["id"])
        else
          error_handler = opts[:error_handler]
          conn
          |> error_handler.(:permission_denied)
          |> halt()
        end
      _ ->
        error_handler = opts[:error_handler]
        conn
        |> error_handler.(:invalid_auth_header)
        |> halt()
    end
  end

  defp get_secret(client_id) do
    Application.get_env(:plug_hmac, :secrets)[client_id]
  end

  @compile {:inline, split_params_from_string: 1}
  def split_params_from_string(string) do
    string
    |> String.split(",", trim: true)
    |> Map.new(
         fn part ->
           String.split(part, "=", trim: true)
           |> Enum.map(
                fn v ->
                  String.trim(v)
                  |> URI.decode_www_form()
                end
              )
           |> case do
                [k, v] -> {k, v}
                [k] -> {k, ""}
              end
         end
       )
  end

  def check_sign?(credential, conn) do
    with signature when signature != nil and signature != "" <- credential["signature"],
         id when id != nil and id != "" <- credential["id"],
         secret when secret != nil <- get_secret(id) do
      sign(
        secret,
        [
          conn.method,
          conn.request_path,
          conn.query_string,
          conn.assigns[:raw_body],
          credential["nonce"]
        ]
      ) == signature
    else
      _ -> false
    end
  end

  @compile {:inline, sign: 2}
  def sign(secret, content_to_sign) do
    :crypto.hmac(:sha256, secret, Enum.join(content_to_sign))
    |> Base.encode64()
  end

  def make_header(client_id, method, path, query_string, body) do
    nonce =
      :crypto.strong_rand_bytes(20)
      |> Base.encode64()
      |> binary_part(0, 20)

    secret = get_secret(client_id)
    signature =
      sign(secret, [method, path, query_string, body, nonce])
      |> URI.encode_www_form()

    client_id = URI.encode_www_form(client_id)
    uriencode_nonce = URI.encode_www_form(nonce)
    "hmac id=#{client_id},signature=#{signature},nonce=#{uriencode_nonce}"
  end
end
