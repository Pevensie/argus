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
    |> argus.hash("password")

  // Hash a password with custom settings.
  let assert Ok(hashes) =
    argus.hasher()
    |> argus.algorithm(argus.Argon2id)
    |> argus.time_cost(3)
    |> argus.memory_cost(12288) // 12 mebibytes
    |> argus.parallelism(1)
    |> argus.hash_length(32)
    |> argus.hash("password")

  // Verify a password.
  let assert Ok(True) = argus.verify(hashes.encoded_hash, "password")
}
```

More information can be found in the [documentation](https://hexdocs.pm/argus/).

## Default settings

Argus' default settings follow [OWASP's minimum recommended configuration guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#introduction),
and are as follows:

| Setting | Value |
| --- | --- |
| Algorithm | Argon2id |
| Time cost (iterations) | 2 |
| Memory cost | 19MiB |
| Parallelism | 1 |
| Hash length | 32 |

## Using in Docker

If you want to deploy a Gleam application using Argus in a Docker container, you'll
need to make sure your image includes a C compiler to build the Jargon NIF.

### Alpine

```dockerfile
RUN apk add --no-cache build-base
```

### Debian

```dockerfile
RUN apt-get update && apt-get install -y build-essential
```

## Using on Windows

Please see the [Jargon README](https://github.com/Pevensie/jargon#using-on-windows) for details
on how to ensure Argus will compile on Windows.

## Why 'Argus'?

[Argus](<https://en.wikipedia.org/wiki/Argus_(Argonaut)>) was the builder of the
[Argo](https://en.wikipedia.org/wiki/Argo) ship and was one of the
[Argonauts](https://en.wikipedia.org/wiki/Argonauts).
