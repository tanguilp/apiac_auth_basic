defmodule APISexBasicAuthConfigTest do
  use ExUnit.Case, async: true
  doctest APISexBasicAuth

  test "configuration init" do
    assert %APISexBasicAuthConfig{} = APISexBasicAuthConfig.init([])
  end

  test "configuration init with invalid realm" do
    assert_raise RuntimeError, fn ->
      APISexBasicAuthConfig.init(realm: ~s(Invalid " realm name))
    end
  end

  test "configuration from conf file" do
    opts = APISexBasicAuthConfig.init({:apisex_basicauth, :test_realm})

    assert opts.realm == "Test realm"
    assert opts.advertise_wwwauthenticate_header == false
    assert opts.halt_on_authentication_failure == true
    assert Enum.at(opts.clients, 0) == {"client_id1", "client_secret1"}
    assert Enum.at(opts.clients, 1) == {"client_id2", "client_secret2"}
  end
end
