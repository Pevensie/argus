import gleam/bit_array

pub type Argon2Algorithm {
  Argon2d
  Argon2i
  Argon2id
}

/// A value containing validated bytes for
/// [salting](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#salting)
/// a password.
///
/// Usually produced via the [`gen_salt`](#gen_salt) function.
pub opaque type Salt {
  Salt(bytes: BitArray)
}

pub opaque type Hasher {
  Hasher(
    algorithm: Argon2Algorithm,
    time_cost: Int,
    memory_cost: Int,
    parallelism: Int,
    hash_length: Int,
  )
}

pub type HashOutput {
  HashOutput(raw_hash: BitArray, encoded_hash: String)
}

/// All possible Argon2 hashing errors.
/// Most are unlikely to occur, but it's good to be aware of them.
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
/// `memory_cost` to 12_288 (12 mebibytes) or less for performance reasons.
///
/// The `hasher_argon2i` function is provided with the recommended settings for
/// Argon2i.
pub fn hasher() -> Hasher {
  Hasher(
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
pub fn hasher_argon2i() -> Hasher {
  Hasher(
    Argon2i,
    3,
    // 12 mebibytes
    12_288,
    1,
    32,
  )
}

/// Set the algorithm to use for the hasher.
pub fn algorithm(hasher: Hasher, algorithm: Argon2Algorithm) -> Hasher {
  Hasher(..hasher, algorithm: algorithm)
}

/// Set the time cost to use for the hasher.
pub fn time_cost(hasher: Hasher, time_cost: Int) -> Hasher {
  Hasher(..hasher, time_cost: time_cost)
}

/// Set the memory cost to use for the hasher.
pub fn memory_cost(hasher: Hasher, memory_cost: Int) -> Hasher {
  Hasher(..hasher, memory_cost: memory_cost)
}

/// Set the parallelism to use for the hasher.
pub fn parallelism(hasher: Hasher, parallelism: Int) -> Hasher {
  Hasher(..hasher, parallelism: parallelism)
}

/// Set the hash length to use for the hasher.
pub fn hash_length(hasher: Hasher, hash_length: Int) -> Hasher {
  Hasher(..hasher, hash_length: hash_length)
}

/// Hash a password using the provided hasher.
///
/// This will use [`gen_salt`](#gen_salt) to generate a random
/// salt.
///
/// ## Examples
///
/// ```gleam
/// import argus
///
/// let assert Ok(hash_output) =
///   argus.hasher()
///   |> argus.algorithm(argus.Argon2id)
///   |> argus.time_cost(3)
///   |> argus.memory_cost(12288)
///   |> argus.parallelism(1)
///   |> argus.hash_length(32)
///   |> argus.hash("password")
///
/// let assert Ok(True) = argus.verify(hash_output.encoded_hash, "password")
/// ```
pub fn hash(hasher: Hasher, password: String) -> Result(HashOutput, HashError) {
  do_hash(hasher, password, gen_salt())
}

/// Verify a password using the provided encoded hash.
pub fn verify(
  encoded_hash: String,
  password: String,
) -> Result(Bool, HashError) {
  jargon_verify(encoded_hash, password)
}

/// Derive an encryption key from a password.
///
/// You do not need to use this function for password hashing. If you're
/// using Argus for password hashing, prefer the [`hash`](#hash) function.
///
/// You only need this function if you're using Argus to derive fixed-size
/// cryptographic keys suitable for encryption, such as when encrypting a
/// file.
///
/// In order to be able to re-derive an identical key, you must use the same
/// salt and set of Argon2 parameters as when the original key was created.
/// It's recommended that you store these alongside the ciphertext.
pub fn derive_encryption_key(
  hasher: Hasher,
  password: String,
  salt: Salt,
) -> Result(BitArray, HashError) {
  case do_hash(hasher, password, salt) {
    Ok(hash_output) -> Ok(hash_output.raw_hash)
    Error(error) -> Error(error)
  }
}

fn do_hash(
  hasher: Hasher,
  password: String,
  salt: Salt,
) -> Result(HashOutput, HashError) {
  let result =
    jargon_hash(
      password,
      salt_bytes(salt),
      hasher.algorithm,
      hasher.time_cost,
      hasher.memory_cost,
      hasher.parallelism,
      hasher.hash_length,
    )
  case result {
    Ok(#(raw_hash, encoded_hash)) -> Ok(HashOutput(raw_hash, encoded_hash))
    Error(error) -> Error(error)
  }
}

/// Make a salt from a `BitArray`. You'll only need to do this when using
/// [`derive_encryption_key`](#derive_encryption_key) with a pre-existing
/// stored salt. For most use cases, [`hash`](#hash) will generate a secure
/// salt for you.
///
/// Returns `Error(Nil)` if the provided `BitArray` does not contain whole
/// bytes.
pub fn make_salt(from bytes: BitArray) -> Result(Salt, Nil) {
  case bit_array.bit_size(bytes) % 8 == 0 {
    True -> Ok(Salt(bytes))
    False -> Error(Nil)
  }
}

/// Generate a random 16-byte salt.
pub fn gen_salt() -> Salt {
  // `gen_salt_bytes` always returns whole bytes in its return value,
  // so we can bypass `make_salt`'s checks here.
  Salt(gen_salt_bytes())
}

@external(erlang, "argus_nif", "gen_salt")
fn gen_salt_bytes() -> BitArray

/// Retrieve the raw bytes from a [`Salt`](#Salt) value.
pub fn salt_bytes(salt: Salt) -> BitArray {
  salt.bytes
}

@external(erlang, "argus_nif", "hash")
fn jargon_hash(
  password: String,
  salt_bytes: BitArray,
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
