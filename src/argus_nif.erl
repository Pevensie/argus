-module(argus_nif).

-export([hash/7, gen_salt/0]).

hash(Password, Salt, Algorithm, TimeCost, MemoryCost, Parallelism, HashLength) ->
  case jargon:hash(Password, Salt, Algorithm, TimeCost, MemoryCost, Parallelism, HashLength)
  of
    {ok, RawHash, EncodedHash} ->
      {ok, {RawHash, EncodedHash}};
    {error, Error} ->
      {error, Error}
  end.

gen_salt() ->
  base64:encode(crypto:strong_rand_bytes(16)).
