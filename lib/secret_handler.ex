defmodule PlugHmac.SecretHandler do
  @type client_id :: String.t()
  @type secret_result :: {:ok, String.t()} | {:error, any()}
  @callback get_secret(client_id()) :: secret_result()
end
