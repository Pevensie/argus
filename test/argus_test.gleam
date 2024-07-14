import argus
import gleam/set
import startest.{describe, it}
import startest/expect

pub fn main() {
  startest.run(startest.default_config())
}

pub fn hash_tests() {
  describe("Hash", [
    describe("Argon2d", [
      it("should hash an argon2d password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2d)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        expect.to_equal(
          hashes.encoded_hash,
          "$argon2d$v=13$m=12,t=3,p=1$c2FsdHNhbHQ$FZoKXluPGiYgTTPgemiEhhyn6AnLTR5oQiTUKU5pAM8",
        )
      }),
      it("should verify an argon2d password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "password")
        expect.to_equal(ok_bool, True)
      }),
      it("should not verify an invalid argon2d password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2d)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "invalid")
        expect.to_equal(ok_bool, False)
      }),
      it("should hash an argon2i password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        expect.to_equal(
          hashes.encoded_hash,
          "$argon2i$v=13$m=12,t=3,p=1$c2FsdHNhbHQ$+y3u+EVJhccL1wJGG4vXY9RFyQmGtR/0Zj51i/PSZ9g",
        )
      }),
      it("should verify an argon2i password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "password")
        expect.to_equal(ok_bool, True)
      }),
      it("should not verify an invalid argon2i password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2i)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "invalid")
        expect.to_equal(ok_bool, False)
      }),
      it("should hash an argon2id password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2id)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        expect.to_equal(
          hashes.encoded_hash,
          "$argon2id$v=13$m=12,t=3,p=1$c2FsdHNhbHQ$vioGjMw4tiYtYqhIl9crwYiqTKf0862+bnO/K/Ld0RE",
        )
      }),
      it("should verify an argon2id password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2id)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "password")
        expect.to_equal(ok_bool, True)
      }),
      it("should not verify an invalid argon2id password", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.algorithm(argus.Argon2id)
          |> argus.time_cost(3)
          |> argus.memory_cost(12)
          |> argus.parallelism(1)
          |> argus.hash_length(32)
          |> argus.hash("password", "saltsalt")

        let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "invalid")
        expect.to_equal(ok_bool, False)
      }),
      it("should hash with default settings", fn() {
        let assert Ok(hashes) =
          argus.hasher()
          |> argus.hash("password", "saltsalt")

        expect.to_equal(
          hashes.encoded_hash,
          "$argon2id$v=13$m=19456,t=2,p=1$c2FsdHNhbHQ$POzLcySqb5GaYV/ACchFwvjlNtvs+q+cMeSKBDmSvTc",
        )
      }),
      it("should hash with default settings for Argon2i", fn() {
        let assert Ok(hashes) =
          argus.hasher_argon2i()
          |> argus.hash("password", "saltsalt")

        expect.to_equal(
          hashes.encoded_hash,
          "$argon2i$v=13$m=12228,t=3,p=1$c2FsdHNhbHQ$3seW16YOH1IuwgYOU6PVqP8xulRl1xmNjZ+ITRrsCFc",
        )
      }),
    ]),
  ])
}

pub fn gen_salt_tests() {
  describe("gen_salt", [
    it("should generate random salts", fn() {
      let num_salts = 100
      let salts = repeat(num_salts, argus.gen_salt, [])
      salts
      |> set.from_list
      |> set.size
      |> expect.to_equal(num_salts)
    }),
    it("should generate salts usable by the Argon2 algorithms", fn() {
      let salt = argus.gen_salt()
      let assert Ok(hashes) =
        argus.hasher()
        |> argus.algorithm(argus.Argon2id)
        |> argus.time_cost(3)
        |> argus.memory_cost(12)
        |> argus.parallelism(1)
        |> argus.hash_length(32)
        |> argus.hash("password", salt)

      let assert Ok(ok_bool) = argus.verify(hashes.encoded_hash, "password")
      expect.to_equal(ok_bool, True)
    }),
  ])
}

fn repeat(n: Int, f: fn() -> a, result: List(a)) -> List(a) {
  case n {
    0 -> result
    n -> repeat(n - 1, f, [f(), ..result])
  }
}
