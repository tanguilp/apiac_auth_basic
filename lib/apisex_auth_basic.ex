defmodule APISexAuthBasic do
  @behaviour Plug

  use Bitwise

  @default_realm_name "Default realm"

  @spec init(Plug.opts) :: Plug.opts
  def init(opts) do
    opts = %{
      clients: Keyword.get(opts, :clients, []),
      callback: Keyword.get(opts, :callback, nil),
      advertise_wwwauthenticate_header: Keyword.get(opts, :advertise_wwwauthenticate_header, true),
      realm: Keyword.get(opts, :realm, @default_realm_name),
      halt_on_authentication_failure: Keyword.get(opts, :halt_on_authentication_failure, true)
    }

    # https://tools.ietf.org/html/rfc7235#section-2.2
    #
    #    For historical reasons, a sender MUST only generate the quoted-string
    #    syntax.  Recipients might have to support both token and
    #    quoted-string syntax for maximum interoperability with existing
    #    clients that have been accepting both notations for a long time.
    if Regex.match?(APISex.Utils.rfc7230_quotedstring_regex(), opts[:realm]) do
      opts
    else
      raise "Invalid realm string (do not conform with RFC7230 quoted string)"
    end
  end

  @spec call(Plug.Conn, Plug.opts) :: Plug.Conn
  def call(conn, %{} = opts) do
    call_parse(conn, opts, Plug.Conn.get_req_header(conn, "authorization"))
  end

  # Only one header value should be returned
  # (https://stackoverflow.com/questions/29282578/multiple-http-authorization-headers)
  defp call_parse(conn, opts, ["Basic " <> auth_token]) do
    # rfc7235 syntax allows multiple spaces before the base64 token
    case Base.decode64(String.trim_leading(auth_token, "\s")) do
      {:ok, req_client_id_secret} -> parse_req_client_id_secret(conn, opts, req_client_id_secret)
      :error -> authenticate_failure(conn, opts)
    end
  end
  defp call_parse(conn, opts, _), do: authenticate_failure(conn, opts)

  defp parse_req_client_id_secret(conn, opts, req_client_id_secret) do
    case String.split(req_client_id_secret, ":") do
      [req_client_id, req_client_secret] -> authenticate(conn, opts, req_client_id, req_client_secret)
      _ -> authenticate_failure(conn, opts)
    end
  end

  defp authenticate(conn, opts = %{callback: callback}, req_client_id, req_client_secret) when is_function(callback) do
    case callback.(opts[:realm], req_client_id) do
      nil -> authenticate_failure(conn, opts)
      client_secret -> if Expwd.secure_compare(req_client_secret, client_secret) == :ok do
        authenticate_success(conn, opts, req_client_id)
      else
        authenticate_failure(conn, opts)
      end
    end
  end

  defp authenticate(conn, opts, req_client_id, req_client_secret) do
    case Enum.find(opts[:clients], fn({client_id, _}) -> client_id == req_client_id end) do
      nil -> authenticate_failure(conn, opts)
      {_client_id, client_secret} ->
        if Expwd.secure_compare(req_client_secret, client_secret) == :ok do
          authenticate_success(conn, opts, req_client_id)
        else
          authenticate_failure(conn, opts)
        end
    end
  end

  defp authenticate_success(conn, opts, client_id) do
    result = %{
      auth_scheme: :httpbasic,
      realm: opts[:realm],
      client: client_id
    }

    Plug.Conn.put_private(conn, :apisex, result)
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: true,
                              halt_on_authentication_failure: true
                            } = opts) do
    conn
    |> set_WWWAuthenticate_challenge(opts)
    |> Plug.Conn.put_status(:unauthorized)
    |> Plug.Conn.halt
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: false,
                              halt_on_authentication_failure: true
                            }) do
    conn
    |> Plug.Conn.put_status(:unauthorized)
    |> Plug.Conn.halt
  end

  defp authenticate_failure(conn,
                            %{
                              advertise_wwwauthenticate_header: true,
                              halt_on_authentication_failure: false
                            } = opts) do
    conn
    |> set_WWWAuthenticate_challenge(opts)
  end

  defp authenticate_failure(conn, _opts), do: conn

  defp set_WWWAuthenticate_challenge(conn, opts) do
    case Plug.Conn.get_resp_header(conn, "www-authenticate") do
      [] -> Plug.Conn.put_resp_header(conn, "www-authenticate", "Basic realm=\"#{opts[:realm]}\"")
      [header_val|_] -> Plug.Conn.put_resp_header(conn, "www-authenticate", header_val <> ", Basic realm=\"#{opts[:realm]}\"")
    end
  end
end
