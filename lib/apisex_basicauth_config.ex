defmodule APISexBasicAuthConfig do
  @type t :: %__MODULE__{
    clients: list({String.t, String.t}),
    callback: nil | (String.t, String.t -> String.t),
    advertise_wwwauthenticate_header: boolean(),
    realm: String.t,
    halt_on_authentication_failure: boolean()
  }

  defstruct clients: [],
            callback: nil,
            advertise_wwwauthenticate_header: true,
            realm: "Default realm",
            halt_on_authentication_failure: true

  def init({app, configkey}) do
    conf = Application.get_env(app, configkey)
    init_check_values(
      %__MODULE__{
        clients: Keyword.get(conf, :clients, []),
        callback: Keyword.get(conf, :callback),
        advertise_wwwauthenticate_header:
          Keyword.get(conf, :advertise_wwwauthenticate_header, true),
        realm: Keyword.get(conf, :realm)
      }
    )
  end

  def init(conf) when is_list(conf) do
    init_check_values(struct(__MODULE__, conf))
  end

  defp init_check_values(conf) do
    if Regex.match?(APISexBasicAuthUtils.rfc7230_quotedstring_regex(), conf.realm) do
      conf
    else
      raise "Invalid realm string (do not conform with RFC7230 quoted string)"
    end
  end
end
