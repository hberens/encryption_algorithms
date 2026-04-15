"""Read uploaded key files and parse RSA key bundles."""

from __future__ import annotations

import json
import re


def read_upload_text(file_storage, max_bytes: int = 16 * 1024 * 1024) -> str | None:
  if file_storage is None or not file_storage.filename:
    return None
  # read one extra byte so we can reliably detect oversized uploads
  raw = file_storage.read(max_bytes + 1)
  if len(raw) > max_bytes:
    raise ValueError(f"Key file too large (max {max_bytes} bytes).")
  return raw.decode("utf-8", errors="replace").strip()


def merge_key_field(form_value: str, file_text: str | None) -> str:
  # uploaded content wins over whatever is typed in the form
  if file_text:
    return file_text
  return form_value or ""


def parse_rsa_key_file(content: str) -> dict[str, str]:
  """Return keys for n, e, d, p, q, phi from JSON or KEY=value lines."""
  out: dict[str, str] = {}
  content = (content or "").strip()
  if not content:
    return out
  if content.startswith("{"):
    # json format is easiest for full key bundles
    data = json.loads(content)
    for k in ("n", "e", "d", "p", "q", "phi"):
      if k in data and data[k] is not None:
        out[k] = str(data[k]).strip()
    return out
  for line in content.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    # also accept key:value in addition to key=value
    m = re.match(r"^(\w+)\s*[:=]\s*(.+)$", line)
    if m:
      key, val = m.group(1).lower(), m.group(2).strip().strip('"').strip("'")
      if key in ("n", "e", "d", "p", "q", "phi"):
        out[key] = val
  return out
