use Mix.Config

config :apisex_basicauth,
  test_realm:
  [
    clients:
    [
      {"client_id1", "client_secret1"},
      {"client_id2", "client_secret2"}
    ],
    realm: "Test realm",
    advertise_wwwauthenticate_header: false
  ]
