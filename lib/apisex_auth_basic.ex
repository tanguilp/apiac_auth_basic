defmodule APISexAuthBasic do
  @behaviour Plug
  @behaviour APISex.Authenticator

  use Bitwise

  @default_realm_name "default_realm"

  @typedoc """
    The callback function returns an Expwd.Hashed.t or a client_secret (String.t) so as
    to prevent developers to [unsecurely compare passwords](https://codahale.com/a-lesson-in-timing-attacks/).

    Return `nil` if the client could not be gound for this realm
  """
  @type callback_fun :: (APISex.realm, APISex.client -> Expwd.Hashed.t | client_secret | nil)
  @type client_secret :: String.t

  @spec init(Plug.opts) :: Plug.opts
  def init(opts) do
    realm = Keyword.get(opts, :realm, @default_realm_name)

    if not APISex.rfc7230_quotedstring?("\"#{realm}\""), do: raise "Invalid realm string (do not conform with RFC7230 quoted string)"

    %{
      realm: realm,
      clients: Application.get_env(:apisex_auth_basic, :clients)[realm] || [],
      callback: Keyword.get(opts, :callback, nil),
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true)
    }
  end

  @spec call(Plug.Conn, Plug.opts) :: Plug.Conn
  def call(conn, %{} = opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts) do
      conn
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{} = error} ->
        conn = if opts[:halt_on_authn_failure], do: Plug.Conn.halt(conn), else: conn

        if opts[:set_authn_error_response], do: set_error_response(conn, error, opts), else: conn
    end
  end

  def extract_credentials(conn, _opts) do
    parse_authz_header(conn)
  end

  defp parse_authz_header(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      # Only one header value should be returned
      # (https://stackoverflow.com/questions/29282578/multiple-http-authorization-headers)
      ["Basic " <> auth_token] ->
        # rfc7235 syntax allows multiple spaces before the base64 token
        case Base.decode64(String.trim_leading(auth_token, "\s")) do
          {:ok, decodedbinary} ->
            # nothing indicates we should trim extra whitespaces (a passowrd could contain one for instance)
            case String.split(decodedbinary, ":", trim: false) do
              [client_id, client_secret] ->
                if not ctl_char?(client_secret) and not ctl_char?(client_secret) do
                  {:ok, conn, {client_id, client_secret}}
                else
                  {:error,
                    conn,
                    %APISex.Authenticator.Unauthorized{
                      authenticator: __MODULE__,
                      reason: :invalid_client_id_or_client_secret}}
                end

              _ ->
                {:error, conn, %APISex.Authenticator.Unauthorized{
                  authenticator: __MODULE__,
                  reason: :invalid_credential_format}}
            end

          _ ->
            {:error, conn, %APISex.Authenticator.Unauthorized{
              authenticator: __MODULE__,
              reason: :invalid_credential_format}}
        end
      _ ->
        {:error, conn, %APISex.Authenticator.Unauthorized{
          authenticator: __MODULE__,
          reason: :unrecognized_scheme}}
    end
  end

  defp ctl_char?(str) do
    Regex.run(~r/[\x00-\x1F\x7F]/, str) != nil
  end

  def validate_credentials(conn, {client_id, client_secret}, %{callback: callback} = opts) when is_function(callback) do
    case callback.(opts[:realm], client_id) do
      nil ->
        {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :client_not_found}}

      stored_client_secret ->
        if Expwd.secure_compare(client_secret, stored_client_secret) == true do
          conn =
            conn
            |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
            |> Plug.Conn.put_private(:apisex_client, client_id)
            |> Plug.Conn.put_private(:apisex_realm, opts[:realm])

          {:ok, conn}
        else
          {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :invalid_client_secret}}
        end
    end
  end

  def validate_credentials(conn, {client_id, client_secret}, opts) do
    case List.keyfind(opts[:clients], client_id, 0) do
      nil ->
        {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :client_not_found}}

      {_stored_client_id, stored_client_secret} ->
        if Expwd.secure_compare(client_secret, stored_client_secret) == true do
          conn =
            conn
            |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
            |> Plug.Conn.put_private(:apisex_client, client_id)
            |> Plug.Conn.put_private(:apisex_realm, opts[:realm])

          {:ok, conn}
        else
          {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :invalid_client_secret}}
        end
    end
  end

  def set_error_response(conn, _error, opts) do
    conn
    |> Plug.Conn.put_status(:unauthorized)
    |> APISex.set_WWWauthenticate_challenge("Basic", %{"realm" => "#{opts[:realm]}"})
  end
end
