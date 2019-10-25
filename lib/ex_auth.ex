defmodule ExAuth do
  @moduledoc """
  A Plug to validate and generate `Authorization` header.
  Authorization = hmac id=URI_encode(client_id),signature=URI_encode(Signature),nonce=URI_encode(Nonce)
  Signature = HMAC_SHA256(client_secret, HTTP verb + Path + Query string + Body + Nonce )
  Nonce = Random string
  """
  @behaviour Plug
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, error_handler: error_handler) do
    case get_req_header(conn, "authorization") do
      ["hmac " <> credential] ->
        credential =
          credential
          |> String.split(",", trim: true)
          |> Enum.map(fn part ->
            [k, v] = String.split(part, "=", trim: true)
            {URI.decode_www_form(String.trim(k)), URI.decode_www_form(String.trim(v))}
          end)
          |> Enum.into(%{})

        secret = get_secret(credential["id"])

        if secret == nil ||
             sign(secret, [
               conn.method,
               conn.request_path,
               conn.query_string,
               conn.assigns[:raw_body],
               credential["nonce"]
             ]) != credential["signature"] do
          conn
          |> error_handler.auth_error(:permission_denied)
          |> halt
        else
          assign(conn, :client_id, credential["id"])
        end

      _ ->
        conn
        |> error_handler.auth_error(:invalid_auth_header)
        |> halt
    end
  end

  defp get_secret(client_id) do
    Application.get_env(:ex_auth, :secrets)[client_id]
  end

  def sign(secret, content_to_sign) do
    Base.encode64(:crypto.hmac(:sha256, secret, Enum.join(content_to_sign)))
  end

  def make_header(client_id, method, path, query_string, body) do
    secret = get_secret(client_id)

    nonce = :crypto.strong_rand_bytes(20) |> Base.encode64() |> binary_part(0, 20)

    uriencode_nonce = nonce |> URI.encode_www_form()

    signature = sign(secret, [method, path, query_string, body, nonce]) |> URI.encode_www_form()
    client_id = URI.encode_www_form(client_id)
    "hmac id=#{client_id},signature=#{signature},nonce=#{uriencode_nonce}"
  end
end
