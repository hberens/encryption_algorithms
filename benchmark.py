import csv
import sys
import time
from pathlib import Path

from algorithms import des3, vigenere, aes_cipher, rsa


SIZES = {
  "1kb": 1024,
  "10kb": 10 * 1024,
  "100kb": 100 * 1024,
}

VIGENERE_KEY = "AARONELEANORHELENASADIE"
AES_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
AES_KEY_BITS = 256
DES3_KEYS = (
  "0123456789ABCDEF",
  "23456789ABCDEF01",
  "456789ABCDEF0123",
)


def make_payload(size_bytes: int) -> bytes:
  pattern = b"The quick brown fox jumps over the lazy dog. 0123456789 "
  repeats = (size_bytes // len(pattern)) + 1
  return (pattern * repeats)[:size_bytes]


def format_ms(elapsed_ns: int) -> str:
  return f"{elapsed_ns / 1_000_000:.3f}"


def time_call(fn) -> tuple[object, int]:
  start_ns = time.perf_counter_ns()
  result = fn()
  end_ns = time.perf_counter_ns()
  return result, end_ns - start_ns


def benchmark_vigenere(payload: bytes) -> list[dict[str, object]]:
  plaintext = payload.decode("ascii")
  encrypted, encrypt_ns = time_call(lambda: vigenere(plaintext, VIGENERE_KEY, "encrypt"))
  decrypted, decrypt_ns = time_call(lambda: vigenere(encrypted["text"], VIGENERE_KEY, "decrypt"))

  if decrypted["text"] != plaintext:
    raise ValueError("Vigenere round-trip failed.")

  return [
    {"operation": "encrypt", "elapsed_ns": encrypt_ns},
    {"operation": "decrypt", "elapsed_ns": decrypt_ns},
  ]


def benchmark_aes(payload: bytes) -> list[dict[str, object]]:
  ciphertext, encrypt_ns = time_call(lambda: aes_cipher(payload, AES_KEY_HEX, AES_KEY_BITS, "encrypt"))
  decrypted, decrypt_ns = time_call(lambda: aes_cipher(ciphertext, AES_KEY_HEX, AES_KEY_BITS, "decrypt"))

  if decrypted != payload:
    raise ValueError("AES round-trip failed.")

  return [
    {"operation": "encrypt", "elapsed_ns": encrypt_ns},
    {"operation": "decrypt", "elapsed_ns": decrypt_ns},
  ]


def benchmark_des3(payload: bytes) -> list[dict[str, object]]:
  ciphertext, encrypt_ns = time_call(lambda: des3(payload, *DES3_KEYS, "encrypt"))
  decrypted, decrypt_ns = time_call(lambda: des3(ciphertext, *DES3_KEYS, "decrypt"))

  if decrypted != payload:
    raise ValueError("3DES round-trip failed.")

  return [
    {"operation": "encrypt", "elapsed_ns": encrypt_ns},
    {"operation": "decrypt", "elapsed_ns": decrypt_ns},
  ]


def generate_rsa_keys() -> dict[str, int]:
  out = rsa("", "encrypt", regenerate=True)
  if out["error"] or not out["keys"]:
    raise ValueError(out["error"] or "RSA key generation failed.")
  return out["keys"]


def benchmark_rsa(payload: bytes, keys: dict[str, int]) -> list[dict[str, object]]:
  ciphertext_out, encrypt_ns = time_call(
    lambda: rsa(
      payload,
      "encrypt",
      n_str=str(keys["n"]),
      e_str=str(keys["e"]),
      d_str=str(keys["d"]),
      p_str=str(keys["p"]),
      q_str=str(keys["q"]),
      phi_str=str(keys["phi"]),
    )
  )
  if ciphertext_out["error"]:
    raise ValueError(f"RSA encrypt failed: {ciphertext_out['error']}")

  plaintext_out, decrypt_ns = time_call(
    lambda: rsa(
      ciphertext_out["text"],
      "decrypt",
      n_str=str(keys["n"]),
      e_str=str(keys["e"]),
      d_str=str(keys["d"]),
      p_str=str(keys["p"]),
      q_str=str(keys["q"]),
      phi_str=str(keys["phi"]),
    )
  )
  if plaintext_out["error"]:
    raise ValueError(f"RSA decrypt failed: {plaintext_out['error']}")

  if plaintext_out["raw_out"] != payload:
    raise ValueError("RSA round-trip failed.")

  return [
    {"operation": "encrypt", "elapsed_ns": encrypt_ns},
    {"operation": "decrypt", "elapsed_ns": decrypt_ns},
  ]


def write_csv(rows: list[dict[str, object]], output_path: Path) -> None:
  with output_path.open("w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(
      fh,
      fieldnames=[
        "algorithm",
        "size_label",
        "size_bytes",
        "operation",
        "elapsed_ns",
        "elapsed_ms",
      ],
    )
    writer.writeheader()
    writer.writerows(rows)


def print_summary(rows: list[dict[str, object]]) -> None:
  print(f"{'Algorithm':<10} {'Size':<6} {'Op':<8} {'Time (ms)':>12}")
  print("-" * 42)
  for row in rows:
    print(
      f"{row['algorithm']:<10} {row['size_label']:<6} {row['operation']:<8} {row['elapsed_ms']:>12}"
    )



def main() -> int:
  rows: list[dict[str, object]] = []

  rsa_keys = generate_rsa_keys()
  benchmarks = {
    "vigenere": lambda payload: benchmark_vigenere(payload),
    "aes": lambda payload: benchmark_aes(payload),
    "des3": lambda payload: benchmark_des3(payload),
    "rsa": lambda payload: benchmark_rsa(payload, rsa_keys),
  }

  for size_label, size_bytes in SIZES.items():
    payload = make_payload(size_bytes)
    for algorithm, runner in benchmarks.items():
      results = runner(payload)
      for result in results:
        rows.append(
          {
            "algorithm": algorithm,
            "size_label": size_label,
            "size_bytes": size_bytes,
            "operation": result["operation"],
            "elapsed_ns": result["elapsed_ns"],
            "elapsed_ms": format_ms(result["elapsed_ns"]),
          }
        )

  output_path = Path("benchmarks.csv")
  write_csv(rows, output_path)
  print_summary(rows)
  print(f"\nResults written to {output_path}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
