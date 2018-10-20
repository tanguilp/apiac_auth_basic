defmodule APISexAuthBasicTest do
  use ExUnit.Case, async: true
  use Plug.Test

  @valid_client_id "my_client"
  @valid_client_secret "My secret"
  @test_realm_name "It's closed"

  setup_all do
    Application.put_env(:apisex_auth_basic,
                        :clients,
                        %{@test_realm_name =>
                          [
                            {@valid_client_id, @valid_client_secret},
                            {"expwd_client", {:expwd, :sha256, "xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}} # password is "Yg03EosS+2I7XxozZyMfshph1r4khGgLrj92nyEvmak"
                          ]})
  end

  test "Correct credentials - check APISex attributes are correctly set" do
    opts = APISexAuthBasic.init([realm: @test_realm_name])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
    assert APISex.authenticated?(conn) == true
    assert APISex.machine_to_machine?(conn) == true
    assert APISex.authenticator(conn) == APISexAuthBasic
    assert APISex.client(conn) == @valid_client_id
  end

  test "Correct credentials with additional white spaces" do
    opts = APISexAuthBasic.init([realm: @test_realm_name])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic      " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Correct credentials with Expwd portable format" do
    opts = APISexAuthBasic.init([realm: @test_realm_name])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64("expwd_client:Yg03EosS+2I7XxozZyMfshph1r4khGgLrj92nyEvmak"))
      |> APISexAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Incorrect credentials" do
    opts = APISexAuthBasic.init([clients: [{@valid_client_id, @valid_client_secret}]])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check www-authenticate header" do
    opts = APISexAuthBasic.init([realm: @test_realm_name])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts)

    assert ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check www-authenticate not set" do
    opts = APISexAuthBasic.init([set_error_response: false])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts)

    refute ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check plug not halted" do
    opts = APISexAuthBasic.init([halt_on_authn_failure: false])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts)

    refute conn.halted
  end

  test "Check incorrect authentication scheme" do
    opts = APISexAuthBasic.init([])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer xaidfnaz")
      |> APISexAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check function callback returning correct secret" do
    opts = APISexAuthBasic.init([callback: fn _realm, _client_id -> @valid_client_secret end])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Check function callback returning invalid secret" do
    opts = APISexAuthBasic.init([callback: fn _realm, _client_id -> "invalid client_secret" end])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check mutliples realms in www-authenticate header" do
    opts1 = APISexAuthBasic.init([realm: "realm1"])
    opts2 = APISexAuthBasic.init([realm: "realm2"])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts1)
      |> APISexAuthBasic.call(opts2)

    assert ["Basic realm=\"realm1\", Basic realm=\"realm2\""] == get_resp_header(conn, "www-authenticate")
  end
end
