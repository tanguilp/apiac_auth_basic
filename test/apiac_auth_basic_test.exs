defmodule APIacAuthBasicTest do
  use ExUnit.Case, async: true
  use Plug.Test

  @valid_client_id "my_client"
  @valid_client_secret "My secret"
  @test_realm_name "It's closed"

  setup_all do
    Application.put_env(
      :apiac_auth_basic,
      :clients,
      %{
        @test_realm_name => [
          {@valid_client_id, @valid_client_secret},
          # password is "Yg03EosS+2I7XxozZyMfshph1r4khGgLrj92nyEvmak"
          {"expwd_client", {:expwd, :sha256, "xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}}
        ]
      }
    )
  end

  test "Correct credentials - check APIac attributes are correctly set" do
    opts = APIacAuthBasic.init(realm: @test_realm_name)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret)
      )
      |> APIacAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
    assert APIac.authenticated?(conn) == true
    assert APIac.machine_to_machine?(conn) == true
    assert APIac.authenticator(conn) == APIacAuthBasic
    assert APIac.client(conn) == @valid_client_id
  end

  test "Correct credentials with additional white spaces" do
    opts = APIacAuthBasic.init(realm: @test_realm_name)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic      " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret)
      )
      |> APIacAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Correct credentials with Expwd portable format" do
    opts = APIacAuthBasic.init(realm: @test_realm_name)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64("expwd_client:Yg03EosS+2I7XxozZyMfshph1r4khGgLrj92nyEvmak")
      )
      |> APIacAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Incorrect credentials" do
    opts = APIacAuthBasic.init(clients: [{@valid_client_id, @valid_client_secret}])

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret")
      )
      |> APIacAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check www-authenticate header" do
    opts = APIacAuthBasic.init(realm: @test_realm_name)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret")
      )
      |> APIacAuthBasic.call(opts)

    assert ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check APIacAuthBasic.set_WWWauthenticate_header/3 function" do
    opts =
      APIacAuthBasic.init(
        realm: @test_realm_name,
        set_error_response: &APIacAuthBasic.set_WWWauthenticate_header/3
      )

    conn =
      conn(:get, "/")
      |> APIacAuthBasic.call(opts)

    assert ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
    refute conn.halted
    refute conn.status == 401
  end

  test "Check incorrect authentication scheme" do
    opts = APIacAuthBasic.init([])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer xaidfnaz")
      |> APIacAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check function callback returning correct secret" do
    opts = APIacAuthBasic.init(callback: fn _realm, _client_id -> @valid_client_secret end)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret)
      )
      |> APIacAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Check function callback returning invalid secret" do
    opts = APIacAuthBasic.init(callback: fn _realm, _client_id -> "invalid client_secret" end)

    conn =
      conn(:get, "/")
      |> put_req_header(
        "authorization",
        "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret)
      )
      |> APIacAuthBasic.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check mutliples realms in www-authenticate header" do
    opts1 =
      APIacAuthBasic.init(
        realm: "realm1",
        set_error_response: &APIacAuthBasic.set_WWWauthenticate_header/3
      )

    opts2 = APIacAuthBasic.init(realm: "realm2")

    conn =
      conn(:get, "/")
      |> APIacAuthBasic.call(opts1)
      |> APIacAuthBasic.call(opts2)

    assert ["Basic realm=\"realm1\", Basic realm=\"realm2\""] ==
             get_resp_header(conn, "www-authenticate")
  end
end
