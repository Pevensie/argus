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

gen_random_int(Min, Max) ->
  crypto:strong_rand_bytes(4),
  <<Int:32/integer>> = crypto:strong_rand_bytes(4),
  Int rem (Max - Min) + Min.

%% Use a min of 64 bytes rather than the default of 32
%% for additional security.
gen_salt() ->
  Bytes = gen_random_int(64, 1024),
  base64:encode(crypto:strong_rand_bytes(Bytes)).


