defmodule APISexAuthBasicTest do
  use ExUnit.Case, async: true
  use Plug.Test
  doctest APISexAuthBasic

  @valid_client_id "my_client"
  @valid_client_secret "My secret"
  @test_realm_name "It's closed"

  test "Correct credentials (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{clients: [{@valid_client_id, @valid_client_secret}]})

    refute conn.status == 401
    refute conn.halted == true
  end

  test "Correct credentials (inlined conf) with additional white spaces" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic      " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{clients: [{@valid_client_id, @valid_client_secret}]})

    refute conn.status == 401
    refute conn.halted == true
  end

  test "Incorrect credentials (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{clients: [{@valid_client_id, @valid_client_secret}]})

    assert conn.status == 401
    assert conn.halted == true
  end

  test "Check www-authenticate header (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{realm: @test_realm_name})

    assert ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check www-authenticate not set (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{advertise_wwwauthenticate_header: false})

    refute ["Basic realm=\"#{@test_realm_name}\""] == get_resp_header(conn, "www-authenticate")
  end

  test "Check plug not halted (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> "invalid_secret"))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{halt_on_authentication_failure: false})

    refute conn.halted == true
  end

  test "Check incorrect authentication scheme (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Bearer xaidfnaz")
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{})

    assert conn.status == 401
    assert conn.halted == true
  end

  test "Check function callback returning correct secret (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{callback: fn _realm, _client_id -> @valid_client_secret end})

    refute conn.status == 401
    refute conn.halted == true
  end

  test "Check function callback returning invalid secret (inlined conf)" do
    conn =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic " <> Base.encode64(@valid_client_id <> ":" <> @valid_client_secret))
      |> APISexAuthBasic.call(%APISexAuthBasicConfig{callback: fn _realm, _client_id -> "invalid client_secret" end})

    assert conn.status == 401
    assert conn.halted == true
  end
end
