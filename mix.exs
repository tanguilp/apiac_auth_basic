defmodule APIacAuthBasic.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_basic,
      version: "0.3.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.0"},
      {:expwd, github: "tanguilp/expwd", tag: "v0.2.1"},
      {:apiac, github: "tanguilp/apiac", tag: "0.2.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
