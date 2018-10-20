defmodule APISexAuthBasic do
  @behaviour Plug
  @behaviour APISex.Authenticator

  use Bitwise

  @moduledoc """
  An `APISex.Authenticator` plug for API authentication using the HTTP `Basic` scheme

  The HTTP `Basic` scheme simply consists in transmitting a client and its password
  in the `Authorization` HTTP header. It is base64-encoded:
  ```http
  GET /api/accounts HTTP/1.1
  Host: example.com
  Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9wYXNzd29yZA==
  Accept: */*
  ```
  The decoded value of `Y2xpZW50X2lkOmNsaWVudF9wYXNzd29yZA==` is `client_id:client_password`

  This scheme is also sometimes called *APIKey* by some API managers.

  ## Security considerations

  The password is transmitted in cleartext form (base64 is not a encryption scheme). Therefore, you should only use this scheme on encrypted connections (HTTPS).

  ## Plug options

  - `realm`: a mandatory `String.t` that conforms to the HTTP quoted-string syntax, however without the surrounding quotes (which will be added automatically when needed). Defaults to `default_realm`
  - `callback`: a function that will return the password of a client. When a callback is configured, it takes precedence over the clients in the config files, which will not be used. The returned value can be:
    - A cleartext password (`String.t`)
    - An `Expwd.Hashed{}` (hashed password)
    - `nil` if the client is not known
    - `set_authn_error_response`: if `true`, sets the error response accordingly to the standard: changing the HTTP status code to `401` and setting the `WWW-Authenticate` value. If false, does not change them. Defaults to `true`
    - `halt_on_authn_failure`: if set to `true`, halts the connection and directly sends the response. When set to `false`, does nothing and therefore allows chaining several authenticators. Defaults to `true`

  ## Application configuration

  `{client_id, client_secret}` pairs can be configured in you application configuration files. There will be compiled at **compile time**. If you need runtime configurability,
  use the `callback` option instead.

  Storing cleartext password requires special care, for instance: using *.secret.exs files, encrypted storage of these config files, etc. Consider using hashed password instead, such
  as `%Expwd.Hashed{}`.

  Pairs a to be set separately for each realm in the `clients` key, as following:
  ``` elixir
  config :apisex_auth_basic,
    clients: %{
      # using Expwd Hashed portable password
      "realm_a" => [
        {"client_1", {:expwd, :sha256, "lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"}},
        {"client_2", {:expwd, :sha256, "mnAWHn1tSHEOCj6sMDIrB9BTRuD4yZkiLbjx9x2i3ug"}},
        {"client_3", {:expwd, :sha256, "9RYrMJSmXJSN4CSJZtOX0Xs+vP94meTaSzGc+oFcwqM"}},
        {"client_4", {:expwd, :sha256, "aCL154jd8bNw868cbsCUw3skHun1n6fGYhBiITSmREw"}},
        {"client_5", {:expwd, :sha256, "xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}}
      ],
      "realm_b" => [
        {"client_1", {:expwd, :sha256, "lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"}}
      ],
      # UNSAFE: cleartext passwords set directly in the config file
      "realm_c" => [
        {"client_6", "cleartext password"},
        {"client_7", "cleartext password again"}
      ]
    }
  ```
  """

  @default_realm_name "default_realm"

  @typedoc """
    The callback function returns an Expwd.Hashed.t or a client_secret (String.t) so as
    to prevent developers to [unsecurely compare passwords](https://codahale.com/a-lesson-in-timing-attacks/).

    Return `nil` if the client could not be gound for this realm
  """
  @type callback_fun :: (APISex.realm, APISex.client -> Expwd.Hashed.t | client_secret | nil)
  @type client_secret :: String.t

  @doc """
  Plug initialization callback
  """

  @impl true
  @spec init(Plug.opts) :: Plug.opts
  def init(opts) do
    realm = Keyword.get(opts, :realm, @default_realm_name)

    if not is_binary(realm), do: raise "Invalid realm, must be a string"

    if not APISex.rfc7230_quotedstring?("\"#{realm}\""), do: raise "Invalid realm string (do not conform with RFC7230 quoted string)"

    %{
      realm: realm,
      clients: Application.get_env(:apisex_auth_basic, :clients)[realm] || [],
      callback: Keyword.get(opts, :callback, nil),
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true)
    }
  end

  @doc """
  Plug pipeline callback
  """

  @impl true
  @spec call(Plug.Conn, Plug.opts) :: Plug.Conn
  def call(conn, %{} = opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts) do
      conn
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{} = error} ->
        conn =
          if opts[:set_authn_error_response] do
            set_error_response(conn, error, opts)
          else
            conn
          end

        if opts[:halt_on_authn_failure] do
          conn
          |> Plug.Conn.send_resp()
          |> Plug.Conn.halt()
        else
          conn
        end
    end
  end

  @doc """
  `APISex.Authenticator` credential extractor callback
  """

  @impl true
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

  @doc """
  `APISex.Authenticator` credential validator callback
  """

  @impl true
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

  @impl true
  def validate_credentials(conn, {client_id, client_secret}, opts) do
    case List.keyfind(opts[:clients], client_id, 0) do
      nil ->
        {:error, conn, %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :client_not_found}}

      {_stored_client_id, stored_client_secret} ->
        cs = case stored_client_secret do
          {:expwd, alg, b64_secret} when is_atom(alg) and is_binary(b64_secret) ->
            Expwd.Hashed.Portable.from_portable(stored_client_secret)

          str when is_binary(str) ->
            str
        end

        if Expwd.secure_compare(client_secret, cs) == true do
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

  @doc """
  `APISex.Authenticator` error response callback
  """
  @impl true
  def set_error_response(conn, _error, opts) do
    conn
    |> APISex.set_WWWauthenticate_challenge("Basic", %{"realm" => "#{opts[:realm]}"})
    |> Plug.Conn.resp(:unauthorized, "")
  end
end
