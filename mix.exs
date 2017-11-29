defmodule APISexAuthBasic.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apisex_auth_basic,
      version: "0.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:cowboy, :plug]
    ]
  end

  defp deps do
    [
      {:cowboy, "~> 1.0.0"},
      {:plug, "~> 1.0"},
      {:expwd, git: "https://github.com/sergeypopol/expwd.git", tag: "master"},
      {:apisex, git: "https://github.com/sergeypopol/apisex.git", tag: "master"}
    ]
  end
end
