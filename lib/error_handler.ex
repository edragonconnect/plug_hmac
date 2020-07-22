defmodule PlugHmac.ErrorHandler do
  alias Plug.Conn
  @type reason :: :permission_denied | :invalid_auth_header | any()
  @type conn :: %Conn{}
  @callback handle(conn, reason) :: conn
end
