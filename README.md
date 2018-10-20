# APISexBasicAuth

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

## Example (with callback function)

The callback function will be called with the `realm` and `client` and return string password or an `%Expwd.Hashed{}` struct:

```elixir
Plug APISexAuthBasic, realm: "my realm",
		      callback: &Module.get_client_password/2
```

This plug follows the APISex standard. To get the client:
```elixir

```

## Documentation

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
