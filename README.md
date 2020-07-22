# PlugHmac

**Auth Plug**

## Installation

The package can be installed by adding `plug_hmac` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:plug_hmac, "~> 0.4"}
  ]
end
```

## Usage

### Configuration

Add `body_reader` to your Phoenix's `Endpoint`
```elixir
plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    body_reader: {PlugHmac.CacheBodyReader, :read_body, []},
    json_decoder: Phoenix.json_library()
```

### For Backend

* error_handler: setting error handler module
* secret_handler: setting secret handler module
* hmac_algo: hmac support algorithem **[:md5, :md4, :sha, :sha224, :sha256, :sha384, :sha512, :sha3_224, :sha3_256, :sha3_384, :sha3_512]**
* client_signature_name: the http header name which use for get authorization data

```elixir
plug PlugHmac,
  error_handler: __MODULE__,
  secret_handler: __MODULE__,
  hmac_algo: :sha256,
  client_signature_name: "authorization"

@behaviour PlugHmac.ErrorHandler
@behaviour PlugHmac.SecretHandler

## callback for error_handler
def handle(conn, _error) do
  # you can case error here 
  # or update conn here
  # must return conn
  conn
end

## callback for secret_handler
def get_secret(client_id) do
  # get your secret key
  {:ok, your_secret_key}
end
```

### For Client
```elixir
# make_header(
#         hmac_algo,
#         secret_handler,
#         client_id,
#         method,
#         path,
#         query_string,
#         body,
#         nonce \\ nil
#      )
PlugHmac.make_header(:sha256, __MODULE__, "test_id", "GET", "/api/test_auth", "a1=123&a2=456", "body string")
```

## Principle

客户端在请求时，需要在`HTTP`的`Header`增加`Authorization`:

```
Authorization: hmac id=test_id,signature=xpSI4lZe5c%2BxlNe%2BUK6MQU8RHZNTjL1CTgQLbFamoYU%3D,nonce=vrlaY%2BzdC2S7cdWEXLiN
```

`PlugHmac` `plug` 会校验 `Authorization` 值的有效性

### 参数说明

在开始之前先说明将要用到的参数：

| 参数名      | 参数值               | 说明                         |
| ----------- | -------------------- | ---------------------------- |
| Method      | GET                  | 请求方法(全大写)             |
| Path        | /api/test_auth       | 请求路径                     |
| QueryString | "a1=123&a2=456"      | 将请求参数用`&`和`=`拼接起来 |
| Body        | "body string"        | 请求的body字符串             |
| ClientID    | test_id              | 由接口提供方提供             |
| SecretKey   | qhN8mkCzaxjC1jWD4fDW | 由接口提供方提供             |
| Nonce       | asd123               | 随机值字符串                 |



### 1. Authorization值

在拼接之前先使用 `URI-encode`，分别对各个参数值进行`encode`，然后再将其拼接起来，如下：

```
"hmac " + "id=" + ClientID + ",signature=" + Signature + ",nonce=" + Nonce
```

### 2. Signature值

首先按如下顺序拼接各个参数值：

```
ConcatString = Method+Path+QueryString+Body+Nonce
GET/api/test_autha1=123&a2=456body stringasd123
```

采用`HMAC_SHA256`算法使用`SecretKey`加密`ConcatString`的值，然后在进行`Base64-encode`，得到`Signature` 值，求值公式如下:

```
hmac.new(SecretKey, ConcatString, hashlib.sha256).digest().encode('base64')
Nop1kEtdf04S8Rr5U409Jmsx8Ic6zeWx2/HJZnLDRuM=
```

