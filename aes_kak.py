"""
AES implementation aligned with Avi Kak, Lecture 8 (Computer and Network Security):
- 128-bit blocks as a 4×4 state (column-major: state[r][c] = byte r+4c).
- Encryption: AddRoundKey, then rounds of SubBytes → ShiftRows → MixColumns → AddRoundKey,
  except the last round omits MixColumns.
- Decryption: inverse round order (InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns),
  last round omits InvMixColumns (see Lecture 8, §8.3).
- Key expansion per §8.8.2 (128 / 192 / 256-bit), including the 256-bit SubWord-only step.
- CBC mode + PKCS#7 padding for the web app (IV prepended to ciphertext).
"""

from __future__ import annotations

import re
import secrets

_BLOCK = 16


def _xtime(x: int) -> int:
  return ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
  # classic shift-and-add multiply in gf(2^8)
  p = 0
  for _ in range(8):
    if b & 1:
      p ^= a
    hi = a & 0x80
    a = (a << 1) & 0xFF
    if hi:
      a ^= 0x1B
    b >>= 1
  return p


def _gf_inv(a: int) -> int:
  if a == 0:
    return 0
  # inverse in GF(2^8) mod x^8+x^4+x^3+x+1 via a^(254)
  p, r = 1, a
  e = 254
  while e:
    if e & 1:
      p = _gf_mul(p, r)
    r = _gf_mul(r, r)
    e >>= 1
  return p


def _affine_forward(x: int) -> int:
  """SubBytes: MI in GF(2^8) then affine (Kak §8.5.2, matrix with c = 0x63)."""
  if x == 0:
    y = 0
  else:
    y = _gf_inv(x)
  z = 0
  for i in range(8):
    bi = (y >> i) & 1
    t = bi
    t ^= (y >> ((i + 4) % 8)) & 1
    t ^= (y >> ((i + 5) % 8)) & 1
    t ^= (y >> ((i + 6) % 8)) & 1
    t ^= (y >> ((i + 7) % 8)) & 1
    t ^= (0x63 >> i) & 1
    z |= t << i
  return z


def _affine_inverse(x: int) -> int:
  """Inverse affine (decryption S-box), then MI (Kak §8.5.2)."""
  z = 0
  for i in range(8):
    bi = (x >> i) & 1
    t = bi
    t ^= (x >> ((i + 2) % 8)) & 1
    t ^= (x >> ((i + 5) % 8)) & 1
    t ^= (x >> ((i + 7) % 8)) & 1
    t ^= (0x05 >> i) & 1
    z |= t << i
  if z == 0:
    return 0
  return _gf_inv(z)


_SBOX = tuple(_affine_forward(i) for i in range(256))
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
  _INV_SBOX[_v] = _i


def _bytes_to_state(block: bytes) -> list[list[int]]:
  """Kak layout: column j holds bytes block[4*j : 4*j+4] down rows 0..3."""
  # keep state in column-major order to match aes spec
  s = [[0] * 4 for _ in range(4)]
  for r in range(4):
    for c in range(4):
      s[r][c] = block[r + 4 * c]
  return s


def _state_to_bytes(s: list[list[int]]) -> bytes:
  out = bytearray(16)
  for r in range(4):
    for c in range(4):
      out[r + 4 * c] = s[r][c]
  return bytes(out)


def _add_round_key(s: list[list[int]], rk: bytes) -> None:
  for r in range(4):
    for c in range(4):
      s[r][c] ^= rk[r + 4 * c]


def _sub_bytes(s: list[list[int]]) -> None:
  for r in range(4):
    for c in range(4):
      s[r][c] = _SBOX[s[r][c]]


def _inv_sub_bytes(s: list[list[int]]) -> None:
  for r in range(4):
    for c in range(4):
      s[r][c] = _INV_SBOX[s[r][c]]


def _shift_rows(s: list[list[int]]) -> None:
  for r in range(1, 4):
    row = [s[r][c] for c in range(4)]
    for c in range(4):
      s[r][c] = row[(c + r) % 4]


def _inv_shift_rows(s: list[list[int]]) -> None:
  for r in range(1, 4):
    row = [s[r][c] for c in range(4)]
    for c in range(4):
      s[r][c] = row[(c - r) % 4]


def _mix_columns(s: list[list[int]]) -> None:
  for c in range(4):
    a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
    s[0][c] = _gf_mul(0x02, a0) ^ _gf_mul(0x03, a1) ^ a2 ^ a3
    s[1][c] = a0 ^ _gf_mul(0x02, a1) ^ _gf_mul(0x03, a2) ^ a3
    s[2][c] = a0 ^ a1 ^ _gf_mul(0x02, a2) ^ _gf_mul(0x03, a3)
    s[3][c] = _gf_mul(0x03, a0) ^ a1 ^ a2 ^ _gf_mul(0x02, a3)


def _inv_mix_columns(s: list[list[int]]) -> None:
  for c in range(4):
    a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
    s[0][c] = _gf_mul(0x0E, a0) ^ _gf_mul(0x0B, a1) ^ _gf_mul(0x0D, a2) ^ _gf_mul(0x09, a3)
    s[1][c] = _gf_mul(0x09, a0) ^ _gf_mul(0x0E, a1) ^ _gf_mul(0x0B, a2) ^ _gf_mul(0x0D, a3)
    s[2][c] = _gf_mul(0x0D, a0) ^ _gf_mul(0x09, a1) ^ _gf_mul(0x0E, a2) ^ _gf_mul(0x0B, a3)
    s[3][c] = _gf_mul(0x0B, a0) ^ _gf_mul(0x0D, a1) ^ _gf_mul(0x09, a2) ^ _gf_mul(0x0E, a3)


def _xor_word(a: bytes, b: bytes) -> bytes:
  return bytes(x ^ y for x, y in zip(a, b))


def _rot_word(w: bytes) -> bytes:
  return w[1:4] + w[0:1]


def _sub_word(w: bytes) -> bytes:
  return bytes(_SBOX[b] for b in w)


def _key_expansion(key: bytes) -> list[bytes]:
  # derive all round keys once so block ops stay simple
  nk = len(key) // 4
  nr = {4: 10, 6: 12, 8: 14}[nk]
  n_words = 4 * (nr + 1)

  rcon = 1
  w: list[bytes] = [key[4 * i : 4 * i + 4] for i in range(nk)]

  for i in range(nk, n_words):
    temp = w[i - 1]
    if i % nk == 0:
      # every nk words: rotate, sub, then mix in round constant
      temp = _xor_word(_sub_word(_rot_word(temp)), bytes([rcon, 0, 0, 0]))
      rcon = _xtime(rcon)
    elif nk > 6 and i % nk == 4:
      temp = _sub_word(temp)
    w.append(_xor_word(w[i - nk], temp))

  return [b"".join(w[4 * r : 4 * r + 4]) for r in range(nr + 1)]


def _aes_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
  nr = len(round_keys) - 1
  s = _bytes_to_state(block)
  _add_round_key(s, round_keys[0])
  for rnd in range(1, nr):
    _sub_bytes(s)
    _shift_rows(s)
    _mix_columns(s)
    _add_round_key(s, round_keys[rnd])
  _sub_bytes(s)
  _shift_rows(s)
  _add_round_key(s, round_keys[nr])
  return _state_to_bytes(s)


def _aes_decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
  """Inverse cipher structure per Kak §8.3 (decryption round order)."""
  nr = len(round_keys) - 1
  s = _bytes_to_state(block)
  _add_round_key(s, round_keys[nr])
  for rnd in range(nr - 1, 0, -1):
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, round_keys[rnd])
    _inv_mix_columns(s)
  _inv_shift_rows(s)
  _inv_sub_bytes(s)
  _add_round_key(s, round_keys[0])
  return _state_to_bytes(s)


def _pkcs7_pad(data: bytes) -> bytes:
  n = _BLOCK - (len(data) % _BLOCK)
  return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
  if not data or len(data) % _BLOCK != 0:
    raise ValueError("Invalid padded data length.")
  n = data[-1]
  if n < 1 or n > _BLOCK or data[-n:] != bytes([n]) * n:
    raise ValueError("Invalid PKCS#7 padding.")
  return data[:-n]


def _cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
  rks = _key_expansion(key)
  iv = secrets.token_bytes(_BLOCK)
  prev = iv
  out = bytearray()
  padded = _pkcs7_pad(plaintext)
  for i in range(0, len(padded), _BLOCK):
    chunk = padded[i : i + _BLOCK]
    # chain with previous ciphertext block (or iv for first block)
    x = bytes(a ^ b for a, b in zip(chunk, prev))
    enc = _aes_encrypt_block(x, rks)
    out.extend(enc)
    prev = enc
  return iv + bytes(out)


def _cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
  if len(ciphertext) < _BLOCK or (len(ciphertext) - _BLOCK) % _BLOCK != 0:
    raise ValueError("Ciphertext length invalid for AES-CBC.")
  rks = _key_expansion(key)
  iv = ciphertext[:_BLOCK]
  body = ciphertext[_BLOCK:]
  prev = iv
  plain = bytearray()
  for i in range(0, len(body), _BLOCK):
    block = body[i : i + _BLOCK]
    dec = _aes_decrypt_block(block, rks)
    plain.extend(a ^ b for a, b in zip(dec, prev))
    prev = block
  return _pkcs7_unpad(bytes(plain))


def aes_cipher(data: bytes, key_hex: str, key_bits: int, action: str) -> bytes:
  """
  AES-128/192/256 in CBC mode with PKCS#7 padding (IV prepended).
  Block cipher follows Kak Lecture 8 / FIPS-197 structure; no external crypto libs.
  """
  if key_bits not in (128, 192, 256):
    raise ValueError("Key size must be 128, 192, or 256 bits.")

  # allow pasted keys with spaces or line breaks
  key_hex = re.sub(r"\s+", "", key_hex or "")
  key_len = key_bits // 8
  expected_hex = key_len * 2
  if len(key_hex) != expected_hex:
    raise ValueError(
      f"Key must be exactly {expected_hex} hex digits ({key_bits} bits, {key_len} bytes)."
    )

  try:
    key = bytes.fromhex(key_hex)
  except ValueError as exc:
    raise ValueError("Key must contain only hexadecimal characters.") from exc

  if len(key) != key_len:
    raise ValueError("Invalid key length after decoding hex.")

  action = (action or "encrypt").lower()
  if action == "encrypt":
    return _cbc_encrypt(data, key)

  if len(data) < _BLOCK:
    raise ValueError("Ciphertext must include IV plus at least one block.")

  return _cbc_decrypt(data, key)
