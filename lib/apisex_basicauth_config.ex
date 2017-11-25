defmodule APISexBasicAuthConfig do
  @type t :: %__MODULE__{
    clients: list({String.t, String.t}),
    callback: nil | (String.t, String.t -> String.t | nil),
    advertise_wwwauthenticate_header: boolean(),
    realm: String.t,
    halt_on_authentication_failure: boolean()
  }

  @default_realm_name "Default realm"

  defstruct clients: [],
            callback: nil,
            advertise_wwwauthenticate_header: true,
            realm: @default_realm_name,
            halt_on_authentication_failure: true

  def init({app, configkey}) do
    conf = Application.get_env(app, configkey)
    init_check_values(
      %__MODULE__{
        clients: Keyword.get(conf, :clients, []),
        callback: Keyword.get(conf, :callback, nil),
        advertise_wwwauthenticate_header:
          Keyword.get(conf, :advertise_wwwauthenticate_header, true),
        realm: Keyword.get(conf, :realm, @default_realm_name)
      }
    )
  end

  def init(conf) when is_list(conf) do
    init_check_values(struct(__MODULE__, conf))
  end

  defp init_check_values(conf) do
    # https://tools.ietf.org/html/rfc7235#section-2.2
    #
    #    For historical reasons, a sender MUST only generate the quoted-string
    #    syntax.  Recipients might have to support both token and
    #    quoted-string syntax for maximum interoperability with existing
    #    clients that have been accepting both notations for a long time.
    if Regex.match?(APISexBasicAuthUtils.rfc7230_quotedstring_regex(), conf.realm) do
      conf
    else
      raise "Invalid realm string (do not conform with RFC7230 quoted string)"
    end
  end
end
