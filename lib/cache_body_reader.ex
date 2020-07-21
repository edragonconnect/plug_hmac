defmodule PlugHmac.CacheBodyReader do
  def read_body(conn, opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn, opts)
    conn = Plug.Conn.assign(conn, :raw_body, body || "")
    {:ok, body, conn}
  end
end
