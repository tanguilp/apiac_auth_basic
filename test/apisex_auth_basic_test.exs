defmodule APISexAuthBasicTest do
  use ExUnit.Case, async: true
  use Plug.Test
  doctest APISexAuthBasic

  @valid_client_id "my_client"
  @valid_client_secret "My secret"
  @test_realm_name "It's closed"

  test "Correct credentials" do
    opts = APISexAuthBasic.init([clients: [{@valid_client_id, @valid_client_secret}]])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Correct credentials with additional white spaces" do
    opts = APISexAuthBasic.init([clients: [{@valid_client_id, @valid_client_secret}]])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic      " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
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
    opts = APISexAuthBasic.init([advertise_wwwauthenticate_header: false])

    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(opts)

    refute ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check plug not halted" do
    opts = APISexAuthBasic.init([halt_on_authentication_failure: false])

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
