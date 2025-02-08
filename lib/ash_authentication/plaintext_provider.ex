defmodule AshAuthentication.PlaintextProvider do
  @moduledoc """
  Provides an implementation of `AshAuthentication.HashProvider` using plaintext.
  """
  @behaviour AshAuthentication.HashProvider

  @doc """
  Given some user input as a string, just let it ride.

  ## Example

      iex> {:ok, hashed} = hash("Marty McFly")
      ...> hashed == "Marty McFly"
      true
  """
  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  def hash(input) when is_binary(input), do: {:ok, input}
  def hash(_), do: :error

  @doc """
  Check if the user input matches the hash.

  ## Example

      iex> valid?("Marty McFly", "Marty McFly")
      true

  """
  @impl true
  @spec valid?(input :: String.t(), hash :: String.t()) :: boolean
  def valid?(input, hash) when is_binary(input) and is_binary(hash),
    do: input == hash

  @doc """
  Simulate a password check to help avoid timing attacks.

  ## Example

      iex> simulate()
      false
  """
  @impl true
  @spec simulate :: false
  def simulate, do: false
end
