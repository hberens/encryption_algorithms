import math
import secrets
import string
from typing import Optional

import des

from aes_kak import aes_cipher


def vigenere(message, key, action):
  """
  Vigenère cipher on A–Z. Key repeats; only letters in the message are transformed
  (key advances per letter). Returns {"text": str, "steps": list} for a short UI blurb.
  """
  # Build the repeating key- check that each upper case letter is between A and Z
  key_letters = [c.upper() for c in (key or "") if "A" <= c.upper() <= "Z"]

  # if there isn't a key, return the message unchanged
  if not key_letters:
    return {
      "text": message or "",
      "steps": [
        {
          "type": "note",
          "text": "No letters found in the key, so the message is left unchanged.",
        }
      ],
    }

  klen = len(key_letters)
  key_i = 0  # index into key_letters; advances once per message letter

  # get the action (encrypt or decrypt)
  decrypt = (action or "").lower() == "decrypt"  # True → (value − key) mod 26; else (value + key) mod 26
  out = []
  first_example = None  # one sample swap for the UI, optional


  for ch in message or "":
    cu = ch.upper()

    # check it is a letter
    if "A" <= cu <= "Z":
      p = ord(cu) - 65
      k = ord(key_letters[key_i % klen]) - 65  # shift from the current key letter

      # get the key letter
      key_letter = key_letters[key_i % klen]
      key_i += 1

      # decrypt or encrypt (p-k mod 26 for decrypt, p+k mod 26 for encrypt)
      if decrypt:
        t = (p - k) % 26
      else:
        t = (p + k) % 26

      # convert back to a letter
      c_out = chr(t + 65)
      if ch.islower():
        c_out = c_out.lower()

      # store the first letter as an example for the output
      if first_example is None:
        first_example = {
          "in": ch,
          "key": key_letter,
          "out": c_out,
        }

      out.append(c_out)
    else:
      out.append(ch)

  # explanation for the decryption/encryption
  verb = "Decrypting" if decrypt else "Encrypting"
  mode_line = (
    "To decrypt, each letter’s number minus the key’s number (wrap 0–25), then back to a letter."
    if decrypt
    else "To encrypt, each letter’s number plus the key’s number (wrap 0–25), then back to a letter."
  )
  steps = [
    {
      "type": "summary",
      "title": f"{verb} with key “{''.join(key_letters)}”",
      "lines": [
        "A–Z are treated as 0–25. The key repeats: first message letter uses the first key letter, then the next, and so on.",
        mode_line,
        "Spaces, digits, and punctuation are copied as-is and do not use a key letter.",
      ],
      "example": first_example,
    }
  ]

  return {"text": "".join(out), "steps": steps}


def des3(msg, k1, k2, k3, action):
  k1 = f"{int(k1 if len(k1) < 16 else k1[-16:], 16):0{64}b}"
  k2 = f"{int(k2, 16):0{64}b}"
  k3 = f"{int(k3, 16):0{64}b}"
  if action == "encrypt":
    # pad up to 8 bytes (make multiple of 8)
    msg = des.pad(msg)
    
    data = [''.join(f'{byte:08b}' for byte in msg[i:i+8]) for i in range(0, len(msg), 8)]
    # DES encryption with k1
    data = [des.des(datum, k1, "encrypt") for datum in data]
    # DES decryption with k2
    data = [des.des(datum, k2, "decrypt") for datum in data]
    # DES encryption with k3
    data = [des.des(datum, k3, "encrypt") for datum in data]
    return b''.join(bytes(int(datum[i:i+8], 2) for i in range(0, 64, 8)) for datum in data)
  else:
    if len(msg) % 8 != 0:
      return "Improper encoding"
    data = [''.join(f'{byte:08b}' for byte in msg[i:i+8]) for i in range(0, len(msg), 8)]
    # DES decryption with k3
    data = [des.des(datum, k3, "decrypt") for datum in data]
    # DES encryption with k2
    data = [des.des(datum, k2, "encrypt") for datum in data]
    # DES decryption with k1
    data = [des.des(datum, k1, "decrypt") for datum in data]
    # unpad up to 8 bytes (make multiple of 8)
    return des.unpad(b''.join(bytes(int(datum[i:i+8], 2) for i in range(0, 64, 8)) for datum in data))


# functions for rsa prime numebers
def _is_prime(n):
  if n < 2:
    return False
  if n == 2:
    return True
  if n % 2 == 0:
    return False
  limit = int(math.isqrt(n)) + 1
  for i in range(3, limit, 2):
    if n % i == 0:
      return False
  return True


def _random_prime(low, high):
  while True:
    # sample in range and nudge to odd before primality test
    x = secrets.randbelow(high - low) + low
    if x % 2 == 0:
      x += 1
    if x < high and _is_prime(x):
      return x


def _rsa_choose_distinct_primes(low: int = 101, high: int = 600) -> tuple[int, int]:
  # keep sampling until we get two different primes
  while True:
    p = _random_prime(low, high)
    q = _random_prime(low, high)
    if p != q:
      return p, q


def _rsa_compute_phi(p: int, q: int) -> int:
  # euler totient for n = p*q when p and q are prime
  return (p - 1) * (q - 1)


def _rsa_choose_public_exponent(tot_n: int, max_tries: int = 2048) -> int:
  # choose random e such that 1 < e < tot_n and gcd(e, tot_n) = 1
  for _ in range(max_tries):
    cand = secrets.randbelow(tot_n - 2) + 2
    if math.gcd(cand, tot_n) == 1:
      return cand
  raise RuntimeError("Could not find a suitable public exponent e.")


def _rsa_generate_keys_from_primes(p: int, q: int) -> dict:
  if p == q:
    raise ValueError("p and q must be distinct primes.")
  if not _is_prime(p) or not _is_prime(q):
    raise ValueError("p and q must both be prime.")
  n = p * q
  if n <= 255:
    raise ValueError("p*q must be greater than 255 for this byte-wise RSA demo.")
  phi = _rsa_compute_phi(p, q)
  e = _rsa_choose_public_exponent(phi)
  d = pow(e, -1, phi)
  return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


# generate rsa keys- pick p,q; n=p*q; phi(n)=(p−1)(q−1); choose e coprime to phi(n); compute d so e*d ≡ 1 (mod phi(n)).
def _rsa_generate_keys():
  """
  Demo-sized keys: n large enough that each byte (0–255) is a valid block (n > 255).
  Production RSA uses 2048–4096 bit moduli; this is for learning only.
  """
  while True:
    p, q = _rsa_choose_distinct_primes(101, 600)
    try:
      # centralize key math + validation in one helper
      return _rsa_generate_keys_from_primes(p, q)
    except ValueError:
      continue


# encrypt: C ≡ M^e (mod n), one block per message byte (text or arbitrary bytes)
def _rsa_encrypt_bytes(data: bytes, e, n):
  # encrypt one byte at a time for this teaching/demo variant
  out = []
  for b in data:
    if b >= n:
      raise ValueError(
        "This message needs a larger modulus n. Click “Generate key pair” again."
      )
    out.append(str(pow(b, e, n)))
  return ",".join(out)


# decrypt: M ≡ C^d (mod n) → raw bytes (UTF-8 text or any binary you encrypted)
def _rsa_decrypt_bytes(ciphertext_str, d, n) -> bytes:
  # parse the comma-separated integer blocks from the ui
  raw = ciphertext_str.replace("\n", " ").strip()
  if not raw:
    return b""
  parts = [p.strip() for p in raw.split(",") if p.strip()]
  try:
    blocks = [int(x) for x in parts]
  except ValueError as exc:
    raise ValueError(
      "Ciphertext must be comma-separated integers (paste the encryption output)."
    ) from exc

  bs = []
  for c in blocks:
    # each block maps back to one original byte in this demo scheme
    m = pow(c, d, n)
    if not (0 <= m < 256):
      raise ValueError("Decryption produced invalid bytes; check ciphertext and keys.")
    bs.append(m)
  return bytes(bs)


# format the keys for display
def _keys_for_display(keys):
  return {
    "p": keys["p"] if keys.get("p") is not None else "—",
    "q": keys["q"] if keys.get("q") is not None else "—",
    "n": keys["n"],
    "phi": keys["phi"] if keys.get("phi") is not None else "—",
    "e": keys["e"] if keys.get("e") is not None else "—",
    "d": keys["d"] if keys.get("d") is not None else "—",
  }


# summary steps for the rsa algorithm
def _rsa_summary_steps(keys):
  return [
    {
      "type": "summary",
      "title": "RSA — asymmetric cipher",
      "lines": [
        "Type: asymmetric — public key (e, n) encrypts; private key (d, n) decrypts.",
        "Strength: factoring n into p and q is believed infeasible for large n. This page uses "
        "small primes for speed.",
        "Key generation step 1: choose two distinct primes p and q.",
        "Key generation step 2: compute modulus n = p×q.",
        "Key generation step 3: compute Euler totient φ(n) = (p−1)(q−1).",
        "Key generation step 4: choose e so that 1 < e < φ(n) and gcd(e, φ(n)) = 1.",
        "Key generation step 5: compute d as the modular inverse of e modulo φ(n), so e×d ≡ 1 (mod φ(n)).",
        "Public key is (n, e). Private key is (n, d).",
        "Encryption: C ≡ M^e (mod n). Decryption: M ≡ C^d (mod n).",
        f"Current demo values — p = {keys['p']}, q = {keys['q']}, n = {keys['n']}, "
        f"φ(n) = {keys['phi']}, e = {keys['e']}, d = {keys['d']} "
        "(in practice d must stay secret).",
      ],
      "example": None,
    }
  ]


# main rsa function to generate keys, encrypt, and decrypt
def rsa(
  message,
  action,
  n_str="",
  e_str="",
  d_str="",
  p_str="",
  q_str="",
  phi_str="",
  regenerate=False,
):

  if message is None:
    message = ""
  elif not isinstance(message, bytes):
    message = message or ""

  action = (action or "encrypt").lower()

  if regenerate:
    # this path only refreshes keys and explanatory steps
    if p_str and str(p_str).strip() and q_str and str(q_str).strip():
      try:
        p_in = int(str(p_str).strip())
        q_in = int(str(q_str).strip())
        keys = _rsa_generate_keys_from_primes(p_in, q_in)
      except ValueError as exc:
        return {
          "text": "",
          "raw_out": None,
          "steps": [],
          "keys": None,
          "error": str(exc),
        }
    else:
      keys = _rsa_generate_keys()
    return {
      "text": "",
      "raw_out": None,
      "steps": _rsa_summary_steps(keys),
      "keys": keys,
      "error": None,
    }

  if not n_str or not str(n_str).strip():
    if action == "decrypt":
      return {
        "text": "",
        "raw_out": None,
        "steps": [
          {
            "type": "note",
            "text": "Decrypt needs modulus n and private exponent d. Generate a key pair first, "
            "then encrypt; or paste n and d if you have them.",
          }
        ],
        "keys": None,
        "error": "Missing keys.",
      }
    keys = _rsa_generate_keys()
  else:
    try:
      # accept partial key bundles; missing parts are validated per action
      n = int(str(n_str).strip())
      e = int(str(e_str).strip()) if e_str and str(e_str).strip() else None
      d = int(str(d_str).strip()) if d_str and str(d_str).strip() else None
      p = int(str(p_str).strip()) if p_str and str(p_str).strip() else None
      q = int(str(q_str).strip()) if q_str and str(q_str).strip() else None
      phi = int(str(phi_str).strip()) if phi_str and str(phi_str).strip() else None
    except ValueError:
      return {
        "text": "",
        "raw_out": None,
        "steps": [],
        "keys": None,
        "error": "Key fields must be integers.",
      }
    keys = {"n": n, "e": e, "d": d, "p": p, "q": q, "phi": phi}

  # validate key relationships when enough information is available
  if keys["n"] is not None and keys["n"] <= 1:
    return {
      "text": "",
      "raw_out": None,
      "steps": [],
      "keys": keys,
      "error": "Modulus n must be greater than 1.",
    }
  if keys.get("p") is not None and keys.get("q") is not None and keys["p"] * keys["q"] != keys["n"]:
    return {
      "text": "",
      "raw_out": None,
      "steps": [],
      "keys": keys,
      "error": "Key fields are inconsistent: n must equal p*q.",
    }

  phi_eff = keys.get("phi")
  if keys.get("p") is not None and keys.get("q") is not None:
    phi_calc = (keys["p"] - 1) * (keys["q"] - 1)
    if phi_eff is None:
      phi_eff = phi_calc
  if keys.get("phi") is not None and phi_eff is not None and keys["phi"] != phi_eff:
    return {
      "text": "",
      "raw_out": None,
      "steps": [],
      "keys": keys,
      "error": "Key fields are inconsistent: phi(n) does not match p and q.",
    }

  if keys.get("e") is not None:
    if keys["e"] <= 1:
      return {
        "text": "",
        "raw_out": None,
        "steps": [],
        "keys": keys,
        "error": "Public exponent e must be greater than 1.",
      }
    if phi_eff is not None:
      if keys["e"] >= phi_eff:
        return {
          "text": "",
          "raw_out": None,
          "steps": [],
          "keys": keys,
          "error": "Public exponent e must satisfy 1 < e < phi(n).",
        }
      if math.gcd(keys["e"], phi_eff) != 1:
        return {
          "text": "",
          "raw_out": None,
          "steps": [],
          "keys": keys,
          "error": "Public exponent e must be coprime with phi(n).",
        }

  if keys.get("d") is not None and phi_eff is not None and keys.get("e") is not None:
    if (keys["d"] * keys["e"]) % phi_eff != 1:
      return {
        "text": "",
        "raw_out": None,
        "steps": [],
        "keys": keys,
        "error": "Private exponent d must satisfy (d*e) mod phi(n) = 1.",
      }

  steps = []
  err = None
  out_text = ""
  raw_out: Optional[bytes] = None

  try:
    if action == "encrypt":
      if keys["e"] is None:
        return {
          "text": "",
          "raw_out": None,
          "steps": [],
          "keys": keys,
          "error": "Public exponent e is missing.",
        }
      if isinstance(message, bytes):
        data = message
      else:
        # message mode uses utf-8 text; file mode already provides bytes
        data = (message or "").encode("utf-8")
      out_text = _rsa_encrypt_bytes(data, keys["e"], keys["n"])
      steps = _rsa_summary_steps(_keys_for_display(keys))
    else:
      if keys["d"] is None:
        return {
          "text": "",
          "raw_out": None,
          "steps": [],
          "keys": keys,
          "error": "Private exponent d is required for decryption.",
        }
      msg_str = message.decode("utf-8", errors="replace") if isinstance(message, bytes) else (message or "")
      raw_out = _rsa_decrypt_bytes(msg_str, keys["d"], keys["n"])
      out_text = raw_out.decode("utf-8", errors="replace")
      steps = _rsa_summary_steps(_keys_for_display(keys))
  except ValueError as exc:
    err = str(exc)
    steps = (
      _rsa_summary_steps(_keys_for_display(keys))
      if keys.get("n") is not None
      else []
    )

  return {"text": out_text, "raw_out": raw_out, "steps": steps, "keys": keys, "error": err}


if __name__ == "__main__":
  print(des3(bytes([0]*16),"111133337777fff5685854ff","1111222244448888","1111222244448888","encrypt"))
  # print(bytes([16]+[0]*7+[8]*8))
  # print(des3(b'\x92\x95\xb5\x9b\xb3\x84sn\x92\x95\xb5\x9b\xb3\x84sn\xac\xb2\xcf\x12Aa\x8c\x8b',"0"*64,"1"*64,"0"*64,"decrypt"))