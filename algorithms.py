import math
import secrets
import string


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


def des3(message, k1, k2, k3, action):
  pass


def aes():
  pass


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
    x = secrets.randbelow(high - low) + low
    if x % 2 == 0:
      x += 1
    if x < high and _is_prime(x):
      return x


# generate rsa keys- pick primes p and q; n = p×q; φ(n) = (p−1)(q−1); choose e coprime to φ(n); choose d so that e×d ≡ 1 (mod φ(n)).
def _rsa_generate_keys():
  """
  Demo-sized keys: n large enough that each byte (0–255) is a valid block (n > 255).
  Production RSA uses 2048–4096 bit moduli; this is for learning only.
  """
  while True:
    p = _random_prime(101, 600)
    q = _random_prime(101, 600)
    if p == q:
      continue
    n = p * q
    if n > 255:
      break

  phi = (p - 1) * (q - 1)
  e = None
  for candidate in (65537, 257, 17, 5, 3):
    if math.gcd(candidate, phi) == 1:
      e = candidate
      break
  if e is None:
    raise RuntimeError("Could not find a suitable public exponent e.")

  d = pow(e, -1, phi)
  return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


# encrypt the message- C ≡ M^e (mod n)
def _rsa_encrypt_text(plaintext, e, n):
  out = []
  for b in plaintext.encode("utf-8"):
    if b >= n:
      raise ValueError(
        "This message needs a larger modulus n. Click “Generate key pair” again."
      )
    out.append(str(pow(b, e, n)))
  return ",".join(out)


# decrypt the message- M ≡ C^d (mod n)
def _rsa_decrypt_text(ciphertext_str, d, n):
  raw = ciphertext_str.replace("\n", " ").strip()
  if not raw:
    return ""
  parts = [p.strip() for p in raw.split(",") if p.strip()]
  try:
    blocks = [int(x) for x in parts]
  except ValueError as exc:
    raise ValueError(
      "Ciphertext must be comma-separated integers (paste the encryption output)."
    ) from exc

  bs = []
  for c in blocks:
    m = pow(c, d, n)
    if not (0 <= m < 256):
      raise ValueError("Decryption produced invalid bytes; check ciphertext and keys.")
    bs.append(m)
  return bytes(bs).decode("utf-8")


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
        "Key generation: pick primes p and q; n = p×q; φ(n) = (p−1)(q−1); choose e coprime "
        "to φ(n); choose d so that e×d ≡ 1 (mod φ(n)).",
        "Encryption: C ≡ M^e (mod n). Decryption: M ≡ C^d (mod n).",
        "Strength: factoring n into p and q is believed infeasible for large n. This page uses "
        "small primes for speed; TLS and similar systems use 2048–4096 bit keys.",
        "Uses: TLS/SSL, digital signatures, key exchange.",
        f"Current demo values — p = {keys['p']}, q = {keys['q']}, n = {keys['n']}, "
        f"φ(n) = {keys['phi']}, e = {keys['e']}, d = {keys['d']} (in practice d must stay secret).",
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

  message = message or ""
  action = (action or "encrypt").lower()

  if regenerate:
    keys = _rsa_generate_keys()
    return {
      "text": "",
      "steps": _rsa_summary_steps(keys),
      "keys": keys,
      "error": None,
    }

  if not n_str or not str(n_str).strip():
    if action == "decrypt":
      return {
        "text": "",
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
      n = int(str(n_str).strip())
      e = int(str(e_str).strip()) if e_str and str(e_str).strip() else None
      d = int(str(d_str).strip()) if d_str and str(d_str).strip() else None
      p = int(str(p_str).strip()) if p_str and str(p_str).strip() else None
      q = int(str(q_str).strip()) if q_str and str(q_str).strip() else None
      phi = int(str(phi_str).strip()) if phi_str and str(phi_str).strip() else None
    except ValueError:
      return {
        "text": "",
        "steps": [],
        "keys": None,
        "error": "Key fields must be integers.",
      }
    keys = {"n": n, "e": e, "d": d, "p": p, "q": q, "phi": phi}

  steps = []
  err = None
  out_text = ""

  try:
    if action == "encrypt":
      if keys["e"] is None:
        return {
          "text": "",
          "steps": [],
          "keys": keys,
          "error": "Public exponent e is missing.",
        }
      out_text = _rsa_encrypt_text(message, keys["e"], keys["n"])
      steps = _rsa_summary_steps(_keys_for_display(keys))
    else:
      if keys["d"] is None:
        return {
          "text": "",
          "steps": [],
          "keys": keys,
          "error": "Private exponent d is required for decryption.",
        }
      out_text = _rsa_decrypt_text(message, keys["d"], keys["n"])
      steps = _rsa_summary_steps(_keys_for_display(keys))
  except ValueError as exc:
    err = str(exc)
    steps = (
      _rsa_summary_steps(_keys_for_display(keys))
      if keys.get("n") is not None
      else []
    )

  return {"text": out_text, "steps": steps, "keys": keys, "error": err}
