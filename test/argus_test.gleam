import argus
import gleam/bit_array
import gleam/set
import startest.{describe, it}
import startest/expect

pub fn main() {
  startest.run(startest.default_config())
}

pub fn hash_tests() {
  describe("hash", [
    describe("Argon2d", [
      it("should verify a valid argon2d password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2d)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2d$v=13$m=12,t=3,p=1$",
        )

        expect.to_equal(argus.verify(hashes.encoded_hash, "password"), Ok(True))
      }),
      it("should not verify an invalid argon2d password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2d)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2d$v=13$m=12,t=3,p=1$",
        )

        expect.to_equal(
          argus.verify(hashes.encoded_hash, "not the password"),
          Ok(False),
        )
      }),
    ]),

    describe("Argon2i", [
      it("should verify an argon2i password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2i$v=13$m=12,t=3,p=1$",
        )

        expect.to_equal(argus.verify(hashes.encoded_hash, "password"), Ok(True))
      }),
      it("should not verify an invalid argon2i password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.to_equal(
          argus.verify(hashes.encoded_hash, "not the password"),
          Ok(False),
        )
      }),
    ]),

    describe("Argon2id", [
      it("should verify an argon2id password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2id)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2id$v=13$m=12,t=3,p=1$",
        )

        expect.to_equal(argus.verify(hashes.encoded_hash, "password"), Ok(True))
      }),
      it("should not verify an invalid argon2id password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2id)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password")

        expect.to_equal(
          argus.verify(hashes.encoded_hash, "not the password"),
          Ok(False),
        )
      }),
    ]),

    describe("config", [
      it("should hash with default settings", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2id$v=13$m=19456,t=2,p=1$",
        )
      }),
      it("should hash with default settings for Argon2i", fn() {
        let assert Ok(hashes) =
          argus.hasher_argon2i()
          |> argus.hash("password")

        expect.string_to_start_with(
          hashes.encoded_hash,
          "$argon2i$v=13$m=12288,t=3,p=1$",
        )
      }),
    ]),

    describe("encryption keys", [
      it("should produce the same key when called with the same settings", fn() {
        let hasher = argus.hasher()
        let salt = argus.gen_salt()

        expect.to_equal(
          argus.derive_encryption_key(hasher, "password", salt),
          argus.derive_encryption_key(hasher, "password", salt),
        )
      }),
    ]),
  ])
}

pub fn gen_salt_tests() {
  describe("gen_salt", [
    it("should generate random salts", fn() {
      let num_salts = 100
      let salts =
        repeat(num_salts, fn() { argus.gen_salt() |> argus.salt_bytes }, [])
      salts
      |> set.from_list
      |> set.size
      |> expect.to_equal(num_salts)
    }),
    it("produces 16-byte salts", fn() {
      argus.gen_salt()
      |> argus.salt_bytes
      |> bit_array.byte_size
      |> expect.to_equal(16)
    }),
  ])
}

pub fn make_salt_tests() {
  describe("make_salt", [
    it("allows whole-byte bit arrays", fn() {
      argus.make_salt(<<255, 255, 255>>)
      |> expect.to_be_ok
      Nil
    }),
    it("rejects non-whole-byte bit arrays", fn() {
      argus.make_salt(<<1:1>>)
      |> expect.to_be_error
      Nil
    }),
  ])
}

fn repeat(n: Int, f: fn() -> a, result: List(a)) -> List(a) {
  case n {
    0 -> result
    n -> repeat(n - 1, f, [f(), ..result])
  }
}
