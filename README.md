# Argus

Argon2 password hashing library for Gleam, based on the reference C implementation.

[![Package Version](https://img.shields.io/hexpm/v/argus)](https://hex.pm/packages/argus)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/argus/)

This library uses another Pevensie project, [jargon](https://github.com/Pevensie/jargon), to provide the underlying NIF.

It currently only supports Gleam's Erlang backend.

## Example

```bash
gleam add argus
```

```gleam
import argus

pub fn main() {
  // Hash a password using the recommended settings for Argon2id.
  let assert Ok(hashes) =
    argus.hasher()
    |> argus.hash("password", argus.gen_salt())

  // Hash a password with custom settings and a custom salt.
  let assert Ok(hashes) =
    argus.hasher()
    |> argus.algorithm(argus.Argon2id)
    |> argus.time_cost(3)
    |> argus.memory_cost(12228) // 12 mebibytes
    |> argus.parallelism(1)
    |> argus.hash_length(32)
    |> argus.hash("password", "custom_salt")

  // Verify a password.
  let assert Ok(True) = argus.verify(hashes.encoded_hash, "password")
}
```

More information can be found in the [documentation](https://hexdocs.pm/argus/).

## Why 'Argus'?

[Argus](https://en.wikipedia.org/wiki/Argus_(Argonaut)) was the builder of the
[Argo](https://en.wikipedia.org/wiki/Argo) ship and was one of the
[Argonauts](https://en.wikipedia.org/wiki/Argonauts).
