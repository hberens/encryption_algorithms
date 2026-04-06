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


def rsa():
  pass
