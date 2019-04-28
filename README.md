# APIacBasicAuth

An `APIac.Authenticator` plug for API authentication using the HTTP `Basic` scheme

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

## Installation

```elixir
def deps do
  [
    {:apiac_auth_basic, github: "tanguilp/apiac_auth_basic", tag: "v0.2.0"}
  ]
end
```

## Example with callback function

The callback function will be called with the `realm` and `client` and return string password or an `%Expwd.Hashed{}` struct:

```elixir
plug APIacAuthBasic, realm: "my realm",
		      callback: &Module.get_client_password/2
```


## Example with configuration file

`{client_id, client_secret}` pairs can be configured in you application configuration files.
There will be compiled at **compile time**. If you need runtime configurability,
use the `callback` option instead.

Storing cleartext password requires special care, for instance: using \*.secret.exs files,
encrypted storage of these config files, etc. Consider using hashed password instead, such
as `Expwd.Hashed.Portable.t`

Pairs a to be set separately for each realm in the `clients` key, as following:
``` elixir
config :apiac_auth_basic,
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

the in your Plug pipeline:

```elixir
Plug APIacAuthBasic, realm: "realm_a"
```

