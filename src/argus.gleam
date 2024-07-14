pub type Argon2Algorithm {
  Argon2d
  Argon2i
  Argon2id
}

pub opaque type ArgusHasher {
  ArgusHasher(
    algorithm: Argon2Algorithm,
    time_cost: Int,
    memory_cost: Int,
    parallelism: Int,
    hash_length: Int,
  )
}

pub type ArgusHash {
  ArgusHash(raw_hash: BitArray, encoded_hash: String)
}

pub type HashError {
  OutputPointerIsNull
  OutputTooShort
  OutputTooLong
  PasswordTooShort
  PasswordTooLong
  SaltTooShort
  SaltTooLong
  AssociatedDataTooShort
  AssociatedDataTooLong
  SecretTooShort
  SecretTooLong
  TimeCostTooSmall
  TimeCostTooLarge
  MemoryCostTooSmall
  MemoryCostTooLarge
  TooFewLanes
  TooManyLanes
  PasswordPointerMismatch
  SaltPointerMismatch
  SecretPointerMismatch
  AssociatedDataPointerMismatch
  MemoryAllocationError
  FreeMemoryCallbackNull
  AllocateMemoryCallbackNull
  IncorrectParameter
  IncorrectType
  InvalidAlgorithm
  OutputPointerMismatch
  TooFewThreads
  TooManyThreads
  NotEnoughMemory
  EncodingFailed
  DecodingFailed
  ThreadFailure
  DecodingLengthFailure
  VerificationFailure
  UnknownErrorCode
}

/// Create a new hasher with default settings based on the
/// [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id).
///
/// Note: if you change the algorithm to Argon2i, you will need to change the
/// `memory_cost` to 12_228 (12 mebibytes) or less for performance reasons.
///
/// The `hasher_argon2i` function is provided with the recommended settings for
/// Argon2i.
pub fn hasher() -> ArgusHasher {
  ArgusHasher(
    Argon2id,
    2,
    // 19 mebibytes
    19_456,
    1,
    32,
  )
}

/// Create a new hasher with default settings based on the
/// [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) for
/// Argon2i.
pub fn hasher_argon2i() -> ArgusHasher {
  ArgusHasher(
    Argon2i,
    3,
    // 12 mebibytes
    12_228,
    1,
    32,
  )
}

/// Set the algorithm to use for the hasher.
pub fn algorithm(hasher: ArgusHasher, algorithm: Argon2Algorithm) -> ArgusHasher {
  ArgusHasher(..hasher, algorithm: algorithm)
}

/// Set the time cost to use for the hasher.
pub fn time_cost(hasher: ArgusHasher, time_cost: Int) -> ArgusHasher {
  ArgusHasher(..hasher, time_cost: time_cost)
}

/// Set the memory cost to use for the hasher.
pub fn memory_cost(hasher: ArgusHasher, memory_cost: Int) -> ArgusHasher {
  ArgusHasher(..hasher, memory_cost: memory_cost)
}

/// Set the parallelism to use for the hasher.
pub fn parallelism(hasher: ArgusHasher, parallelism: Int) -> ArgusHasher {
  ArgusHasher(..hasher, parallelism: parallelism)
}

/// Set the hash length to use for the hasher.
pub fn hash_length(hasher: ArgusHasher, hash_length: Int) -> ArgusHasher {
  ArgusHasher(..hasher, hash_length: hash_length)
}

/// Hash a password using the provided hasher.
/// 
/// ## Examples
/// 
/// ```gleam
/// import argus
/// 
/// let assert Ok(hashes) =
///   argus.hasher()
///   |> argus.algorithm(argus.Argon2id)
///   |> argus.time_cost(3)
///   |> argus.memory_cost(12228)
///   |> argus.parallelism(1)
///   |> argus.hash_length(32)
///   |> argus.hash("password", gen_salt())
/// 
/// let assert Ok(True) = argus.verify(hashes.encoded_hash, "password")
/// ```
pub fn hash(
  hasher: ArgusHasher,
  password: String,
  salt: String,
) -> Result(ArgusHash, HashError) {
  let result =
    jargon_hash(
      password,
      salt,
      hasher.algorithm,
      hasher.time_cost,
      hasher.memory_cost,
      hasher.parallelism,
      hasher.hash_length,
    )
  case result {
    Ok(#(raw_hash, encoded_hash)) -> Ok(ArgusHash(raw_hash, encoded_hash))
    Error(error) -> Error(error)
  }
}

/// Verify a password using the provided encoded hash.
pub fn verify(encoded_hash: String, password: String) -> Result(Bool, HashError) {
  jargon_verify(encoded_hash, password)
}

/// Generate a random salt of at least 64 bytes.
@external(erlang, "argus_nif", "gen_salt")
pub fn gen_salt() -> String

@external(erlang, "argus_nif", "hash")
fn jargon_hash(
  password: String,
  salt: String,
  algorithm: Argon2Algorithm,
  time_cost: Int,
  memory_cost: Int,
  parallelism: Int,
  hash_length: Int,
) -> Result(#(BitArray, String), HashError)

@external(erlang, "jargon", "verify")
fn jargon_verify(
  encoded_hash: String,
  password: String,
) -> Result(Bool, HashError)
