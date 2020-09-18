defmodule PlugHmac do
  @moduledoc """
  A Plug to validate and generate `Authorization` header.
  Authorization = hmac id=URI_encode(client_id),signature=URI_encode(Signature),nonce=URI_encode(Nonce)
  Signature = HMAC_SHA256(client_secret, HTTP verb + Path + Query string + Body + Nonce )
  Nonce = Random string
  """
  @behaviour Plug
  import Plug.Conn

  require Logger

  @base_hamc_algo [
    :md5,
    :md4,
    :sha,
    :sha224,
    :sha256,
    :sha384,
    :sha512,
    :sha3_224,
    :sha3_256,
    :sha3_384,
    :sha3_512
  ]

  def init(opts) do
    with {:check_error_handler, true} <-
           {:check_error_handler,
            is_atom(opts[:error_handler]) and Code.ensure_loaded?(opts[:error_handler])},
         {:check_secret_handler, true} <-
           {:check_secret_handler,
            is_atom(opts[:secret_handler]) and Code.ensure_loaded?(opts[:secret_handler])},
         {:check_hmac_algo, true} <- {:check_hmac_algo, opts[:hmac_algo] in @base_hamc_algo},
         {:check_client_signature_name, true} <-
           {:check_client_signature_name,
            is_bitstring(opts[:client_signature_name]) or is_nil(opts[:client_signature_name])} do
      opts
    else
      error ->
        raise "check_opts_error with #{inspect(error)} with opts: #{inspect(opts)}"
    end
  end

  def call(conn, opts) do
    error_handler = opts[:error_handler]
    secret_handler = opts[:secret_handler]
    hmac_algo = opts[:hmac_algo]
    client_signature_name = Keyword.get(opts, :client_signature_name, "authorization")

    case get_req_header(conn, client_signature_name) do
      ["hmac " <> credential] ->
        credential = split_params_from_string(credential)

        if check_sign?(hmac_algo, secret_handler, credential, conn) do
          assign(conn, :client_id, credential["id"])
        else
          conn
          |> error_handler.handle(:permission_denied)
          |> halt()
        end

      _ ->
        conn
        |> error_handler.handle(:invalid_auth_header)
        |> halt()
    end
  end

  @compile {:inline, split_params_from_string: 1}
  def split_params_from_string(string) do
    string
    |> String.split(",", trim: true)
    |> Map.new(fn part ->
      String.split(part, "=", trim: true)
      |> Enum.map(fn v ->
        String.trim(v)
        |> URI.decode_www_form()
      end)
      |> case do
        [k, v] -> {k, v}
        [k] -> {k, ""}
      end
    end)
  end

  def check_sign?(hmac_algo, secret_handler, credential, conn) do
    with {:get_signature, signature} when signature != nil and signature != "" <-
           {:get_signature, credential["signature"]},
         {:get_client_id, id} when id != nil and id != "" <- {:get_client_id, credential["id"]},
         {:ok, secret} when secret != nil <- secret_handler.get_secret(id) do
      sign(
        hmac_algo,
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
      error ->
        Logger.info(fn -> "check_sign with error: #{inspect(error)}" end)
        false
    end
  end

  @compile {:inline, sign: 3}
  def sign(hmac_algo, secret, content_to_sign) do
    :crypto.hmac(hmac_algo, secret, Enum.join(content_to_sign))
    |> Base.encode64()
  end

  def make_header(hmac_algo, get_secret_fun, method, path, query_string, body, nonce)
      when is_function(get_secret_fun, 0) do
    {:ok, client_id, secret} = get_secret_fun.()
    make_header(hmac_algo, client_id, secret, method, path, query_string, body, nonce)
  end

  def make_header(
        hmac_algo,
        secret_handler,
        client_id,
        method,
        path,
        query_string,
        body,
        nonce \\ nil
      )

  def make_header(hmac_algo, secret_handler, client_id, method, path, query_string, body, nonce)
      when is_atom(secret_handler) and is_binary(client_id) do
    {:ok, secret} = secret_handler.get_secret(client_id)
    make_header(hmac_algo, client_id, secret, method, path, query_string, body, nonce)
  end

  def make_header(hmac_algo, client_id, secret, method, path, query_string, body, nonce)
      when is_binary(client_id) and is_binary(secret) do
    nonce =
      if is_nil(nonce) do
        make_nonce()
      else
        nonce
      end

    signature =
      sign(hmac_algo, secret, [method, path, query_string, body, nonce])
      |> URI.encode_www_form()

    client_id = URI.encode_www_form(client_id)
    uriencode_nonce = URI.encode_www_form(nonce)
    "hmac id=#{client_id},signature=#{signature},nonce=#{uriencode_nonce}"
  end

  def make_nonce() do
    :crypto.strong_rand_bytes(20)
    |> Base.encode64()
    |> binary_part(0, 20)
  end
end
