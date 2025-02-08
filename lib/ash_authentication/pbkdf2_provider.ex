defmodule AshAuthentication.Pbkdf2Provider do
  @moduledoc """
  Provides implementation of `AshAuthentication.HashProvider` using `Pbkdf2`.
  """
  @behaviour AshAuthentication.HashProvider

  @doc """
  Given some user input as a string, convert it into it's hashed form using `Pbkdf2`.

  ## Example

      iex> {:ok, hashed} = hash("Marty McFly")
      ...> String.starts_with?(hashed, "$pbkdf2")
      true
  """
  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  def hash(input) when is_binary(input), do: {:ok, Pbkdf2.hash_pwd_salt(input)}
  def hash(_), do: :error

  @doc """
  Check if the user input matches the hash.

  ## Example

      iex> valid?("Marty McFly", "$pbkdf2-sha512$160000$TWFydHkgTWNGbHkgaW4gdGhlIHBhc3Qgd2l0aCB0aGUgRGVsb3JlYW4$P68TJzQJ2bfQddw5se4PhaqZiXja7ccJ0qsAsarI5cfq2oBi5rJ6QLdaoG9wJNorxrSiaVDv6nxXjIEY7NhglQ")
      true

  """
  @impl true
  @spec valid?(input :: String.t(), hash :: String.t()) :: boolean
  def valid?(input, hash) when is_binary(input) and is_binary(hash),
    do: Pbkdf2.verify_pass(input, hash)

  @doc """
  Simulate a password check to help avoid timing attacks.

  ## Example

      iex> simulate()
      false
  """
  @impl true
  @spec simulate :: false
  def simulate, do: Pbkdf2.no_user_verify()
end
