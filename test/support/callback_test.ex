defmodule Asteroid.CallbackTest do
  def add_scp99_scope(requested_scope, _ctx) do
    MapSet.put(requested_scope, "scp99")
  end
end
