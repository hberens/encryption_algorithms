"""Parse optional key files and normalize text read from uploads."""

import json
import re


def read_upload_text(file_storage, max_bytes: int = 16 * 1024 * 1024) -> str | None:
  if file_storage is None or not file_storage.filename:
    return None
  raw = file_storage.read(max_bytes + 1)
  if len(raw) > max_bytes:
    raise ValueError(f"Key file too large (max {max_bytes} bytes).")
  return raw.decode("utf-8", errors="replace").strip()


def merge_key_field(form_value: str, file_text: str | None) -> str:
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
    data = json.loads(content)
    for k in ("n", "e", "d", "p", "q", "phi"):
      if k in data and data[k] is not None:
        out[k] = str(data[k]).strip()
    return out
  for line in content.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    m = re.match(r"^(\w+)\s*[:=]\s*(.+)$", line)
    if m:
      key, val = m.group(1).lower(), m.group(2).strip().strip('"').strip("'")
      if key in ("n", "e", "d", "p", "q", "phi"):
        out[key] = val
  return out


def parse_des_keys_file(content: str) -> tuple[str, str, str] | None:
  """Three lines of 16 hex chars, or one line with three hex tokens."""
  content = (content or "").strip()
  if not content:
    return None
  lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
  if len(lines) >= 3:
    return lines[0][:16], lines[1][:16], lines[2][:16]
  parts = content.split()
  if len(parts) >= 3:
    return parts[0][:16], parts[1][:16], parts[2][:16]
  return None


def parse_aes_key_hex(content: str) -> str | None:
  s = re.sub(r"\s+", "", (content or "").strip())
  return s if s else None
