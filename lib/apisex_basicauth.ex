defmodule APISexBasicAuth do
  @behaviour Plug

  use Bitwise

  @spec init(Plug.opts) :: APISexBasicAuthConfig.t
  def init(opts) do
    APISexBasicAuthConfig.init(opts)
  end

  @spec call(Plug.Conn, APISexBasicAuthConfig.t) :: Plug.Conn
  def call(conn, opts) do
    call_parse(conn, opts, Plug.Conn.get_req_header(conn, "authorization"))
  end

  # Only one header value should be returned
  # (https://stackoverflow.com/questions/29282578/multiple-http-authorization-headers)
  defp call_parse(conn, opts, ["Basic " <> auth_token]) do
    # rfc7235 syntax allows multiple spaces before the base64 token68
    case Base.decode64(String.trim_leading(auth_token, "\s")) do
      {:ok, client_id_secret} -> parse_client_id_secret(conn, opts, client_id_secret)
      :error -> authenticate_failure(conn, opts)
    end
  end

  defp call_parse(conn, opts, _) do
    authenticate_failure(conn, opts)
  end

  defp parse_client_id_secret(conn, opts, client_id_secret) do
    case String.split(client_id_secret, ":") do
      [client_id, client_secret] -> authenticate(conn, opts, client_id, client_secret)
      _ -> authenticate_failure(conn, opts)
    end
  end

  defp authenticate(conn, opts = %APISexBasicAuthConfig{callback: callback}, client_id, client_secret) when is_function(callback) do
    case callback.(opts.realm, client_id) do
      nil -> authenticate_failure(conn, opts)
      val -> if secure_compare(client_secret, val) do
        authenticate_success(conn, opts, client_id)
      else
        authenticate_failure(conn, opts)
      end
    end
  end

  defp authenticate(conn, opts, client_id, client_secret) do
    case Enum.find(opts.clients, fn({conf_client_id, _}) -> conf_client_id == client_id end) do
      nil -> authenticate_failure(conn, opts)
      {_conf_client_id, conf_client_secret} ->
        if secure_compare(client_secret, conf_client_secret) do
          authenticate_success(conn, opts, client_id)
        else
          authenticate_failure(conn, opts)
        end
    end
  end

  defp authenticate_success(conn, opts, client_id) do
    result = %{
      auth_scheme: :httpbasic,
      realm: opts.realm,
      client: client_id
    }

    Plug.Conn.put_private(conn, :apisex, result)
  end

  defp authenticate_failure(conn, opts) do
    conn =
      if opts.halt_on_authentication_failure do
        conn
        |> Plug.Conn.put_status(:unauthorized)
        |> set_WWWAuthenticate_challenge(opts)
        |> Plug.Conn.halt
      else
        conn
      end

    conn
  end

  defp set_WWWAuthenticate_challenge(conn, opts) do
    case Plug.Conn.get_resp_header(conn, "www-authenticate") do
      nil -> Plug.Conn.put_resp_header(conn, "www-authenticate", "Basic realm=\"#{opts.realm}\"")
      header_val -> Plug.Conn.put_resp_header(conn, "www-authenticate", header_val <> ", Basic realm=\"#{opts.realm}\"")
    end
  end

  # prevents timing attacks
  defp secure_compare(left, right) do
    hashed_left = :crypto.hash(:sha256, left)
    hashed_right = :crypto.hash(:sha256, right)

    secure_compare(hashed_left, hashed_right, 0) == 0
  end

  defp secure_compare(<<x, left :: binary>>, <<y, right :: binary>>, acc) do
    secure_compare(left, right, acc ||| (x ^^^ y))
  end

  defp secure_compare(<<>>, <<>>, acc) do
    acc
  end
end
