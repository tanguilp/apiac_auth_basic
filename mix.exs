defmodule APISexAuthBasic.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apisex_auth_basic,
      version: "0.1.0",
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
      {:expwd, github: "tanguilp/expwd", tag: "master"},
      {:apisex, github: "tanguilp/apisex", tag: "0.1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
