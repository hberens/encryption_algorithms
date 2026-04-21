from __future__ import annotations

from flask import Flask, request, render_template
import os
import re
import time
import base64
import csv
from datetime import datetime, timezone

import des as des_module

from algorithms import vigenere, des3, aes_cipher, rsa
from io_helpers import (
  read_upload_text,
  merge_key_field,
  parse_rsa_key_file,
)

app = Flask(__name__)

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]+")
_BENCHMARK_CSV = os.path.join(os.path.dirname(__file__), "benchmark_results.csv")


def _input_size_bytes(data: bytes | str | None) -> int:
  # normalize text/bytes inputs so benchmark size is comparable
  if data is None:
    return 0
  if isinstance(data, bytes):
    return len(data)
  return len(data.encode("utf-8"))


def _log_benchmark(algorithm: str, action: str, input_type: str, input_size_bytes: int, elapsed_ns: int | None):
  # keep benchmark logging best-effort and non-blocking for user requests
  if elapsed_ns is None:
    return
  row = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "algorithm": algorithm,
    "action": action,
    "input_type": input_type,
    "input_size_bytes": input_size_bytes,
    "elapsed_ns": elapsed_ns,
  }
  try:
    write_header = not os.path.exists(_BENCHMARK_CSV) or os.path.getsize(_BENCHMARK_CSV) == 0
    with open(_BENCHMARK_CSV, "a", newline="", encoding="utf-8") as fh:
      writer = csv.DictWriter(
        fh,
        fieldnames=["timestamp_utc", "algorithm", "action", "input_type", "input_size_bytes", "elapsed_ns"],
      )
      if write_header:
        writer.writeheader()
      writer.writerow(row)
  except OSError:
    # logging should never break encryption/decryption requests
    pass


def _safe_export_name(name: str, fallback: str) -> str:
  name = (name or "").strip()
  if not name:
    return fallback
  # keep filenames portable and avoid odd shell/path chars
  name = _SAFE_NAME.sub("_", name)
  return (name[:120] or fallback)


def _apply_output_mode(
  output_mode: str,
  text_display: str,
  *,
  download_bytes: bytes | None = None,
  default_filename: str = "output.bin",
):
  """Either show full result in the textbox or offer a single file download."""
  mode = (output_mode or "textbox").lower()
  if mode == "file":
    payload = download_bytes if download_bytes is not None else (text_display or "").encode("utf-8")
    return {
      "show_textbox": False,
      "answer": "Output is ready for download",
      "download_data": base64.b64encode(payload).decode("ascii"),
      "download_filename": default_filename,
    }
  return {
    "show_textbox": True,
    "answer": text_display,
    "download_data": None,
    "download_filename": None,
  }


@app.route("/", methods=["GET"])
def home_page():
  return render_template("home.html", current="home")


@app.route("/vigenere", methods=["GET", "POST"])
def vigenere_page():
  message, key, action = "", "", "encrypt"
  answer = None
  elapsed_ns = None
  benchmark_input_size = None
  vigenere_steps = None
  show_textbox = True
  download_data = None
  download_filename = None

  if request.method == "POST":
    message = request.form.get("message", "")
    key = merge_key_field(request.form.get("key", ""), read_upload_text(request.files.get("key_file")))
    action = request.form.get("action", "")
    output_mode = request.form.get("output_mode", "textbox")
    export_name = _safe_export_name(request.form.get("export_name", ""), "vigenere_output.txt")
    start_ns = time.perf_counter_ns()
    out = vigenere(message, key, action)
    answer = out["text"]
    vigenere_steps = out["steps"]
    end_ns = time.perf_counter_ns()
    elapsed_ns = end_ns - start_ns
    benchmark_input_size = _input_size_bytes(message)
    _log_benchmark("vigenere", action, "message", benchmark_input_size, elapsed_ns)
    o = _apply_output_mode(
      output_mode,
      answer,
      download_bytes=answer.encode("utf-8"),
      default_filename=export_name if export_name.endswith(".txt") else export_name + ".txt",
    )
    answer = o["answer"]
    show_textbox = o["show_textbox"]
    download_data = o["download_data"]
    download_filename = o["download_filename"]

  return render_template(
    "vigenere.html",
    current="vigenere",
    message=message,
    key=key,
    action=action,
    answer=answer,
    elapsed_time=elapsed_ns,
    benchmark_algorithm="vigenere",
    benchmark_action=action,
    benchmark_input_type="message",
    benchmark_input_size=benchmark_input_size,
    vigenere_steps=vigenere_steps,
    show_textbox=show_textbox,
    download_data=download_data,
    download_filename=download_filename,
  )


@app.route("/rsa", methods=["GET", "POST"])
def rsa_page():
  message = ""
  action = "encrypt"
  input_type = "message"  # message | file
  p_input = ""
  q_input = ""
  answer = None
  elapsed_ns = None
  benchmark_input_size = None
  rsa_steps = None
  rsa_keys = None
  rsa_error = None
  show_textbox = True
  download_data = None
  download_filename = None

  if request.method == "POST":
    input_type = request.form.get("input_type", "message")
    action = request.form.get("action", "encrypt")
    regenerate = bool(request.form.get("generate"))
    output_mode = request.form.get("output_mode", "textbox")
    export_name = _safe_export_name(request.form.get("export_name", ""), "rsa_output")

    n_f = request.form.get("n_saved", "")
    e_f = request.form.get("e_saved", "")
    d_f = request.form.get("d_saved", "")
    p_f = request.form.get("p_saved", "")
    q_f = request.form.get("q_saved", "")
    phi_f = request.form.get("phi_saved", "")
    p_input = request.form.get("p_input", "").strip()
    q_input = request.form.get("q_input", "").strip()
    parse_error = None
    kf = read_upload_text(request.files.get("key_file"))
    if kf:
      # key file may provide direct rsa key values (n/e/d)
      parsed = parse_rsa_key_file(kf)
      if not parsed:
        parse_error = "Could not parse key file. Expected entries like n=..., e=..., d=... (or JSON)."
      n_f = parsed.get("n", n_f)
      e_f = parsed.get("e", e_f)
      d_f = parsed.get("d", d_f)
      # uploaded key bundles should stand on their own
      p_f = ""
      q_f = ""
      phi_f = ""
    elif regenerate:
      # generation mode: use user primes only when both are explicitly provided
      if p_input and q_input:
        p_f = p_input
        q_f = q_input
      else:
        p_f = ""
        q_f = ""

    msg_arg: str | bytes = ""
    if input_type == "file":
      uf = request.files.get("file")
      if uf and uf.filename:
        rawf = uf.read()
        if action == "encrypt":
          msg_arg = rawf
        else:
          # ciphertext input is text here (comma-separated numbers)
          msg_arg = rawf.decode("utf-8", errors="replace")
      else:
        msg_arg = b"" if action == "encrypt" else ""
    else:
      message = request.form.get("message", "")
      if action == "encrypt":
        msg_arg = message.encode("utf-8")
      else:
        msg_arg = message

    if parse_error:
      text_out = ""
      raw_out = None
      rsa_steps = []
      rsa_keys = None
      rsa_error = parse_error
      elapsed_ns = None
    else:
      start_ns = time.perf_counter_ns()
      out = rsa(
        msg_arg,
        action,
        n_str=n_f,
        e_str=e_f,
        d_str=d_f,
        p_str=p_f,
        q_str=q_f,
        phi_str=phi_f,
        regenerate=regenerate,
      )
      text_out = out["text"]
      raw_out = out.get("raw_out")
      rsa_steps = out["steps"]
      rsa_keys = out["keys"]
      rsa_error = out["error"]
      end_ns = time.perf_counter_ns()
      elapsed_ns = end_ns - start_ns

    if rsa_error:
      # do not show timing when the operation failed
      answer = None
      show_textbox = True
      elapsed_ns = None
      benchmark_input_size = None
    elif regenerate:
      # key generation is metadata only, no output payload to show
      answer = None
      show_textbox = True
      elapsed_ns = None
      benchmark_input_size = None
    else:
      # only successful encrypt/decrypt runs are benchmarked
      benchmark_input_size = _input_size_bytes(msg_arg)
      _log_benchmark("rsa", action, input_type, benchmark_input_size, elapsed_ns)
      if action == "encrypt":
        fn = export_name + ".txt" if not export_name.endswith(".txt") else export_name
        b_dl = text_out.encode("utf-8")
        o = _apply_output_mode(output_mode, text_out, download_bytes=b_dl, default_filename=fn)
        answer = o["answer"]
        show_textbox = o["show_textbox"]
        download_data = o["download_data"]
        download_filename = o["download_filename"]
      else:
        fn = export_name if re.search(r"\.[a-z0-9]+$", export_name, re.I) else export_name + ".bin"
        b_dl = raw_out if raw_out is not None else text_out.encode("utf-8", errors="replace")
        o = _apply_output_mode(output_mode, text_out, download_bytes=b_dl, default_filename=fn)
        answer = o["answer"]
        show_textbox = o["show_textbox"]
        download_data = o["download_data"]
        download_filename = o["download_filename"]

  return render_template(
    "rsa.html",
    current="rsa",
    message=message,
    action=action,
    input_type=input_type,
    answer=answer,
    elapsed_time=elapsed_ns,
    benchmark_algorithm="rsa",
    benchmark_action=action,
    benchmark_input_type=input_type,
    benchmark_input_size=benchmark_input_size,
    rsa_steps=rsa_steps,
    rsa_keys=rsa_keys,
    rsa_error=rsa_error,
    p_input=p_input,
    q_input=q_input,
    show_textbox=show_textbox,
    download_data=download_data,
    download_filename=download_filename,
  )


@app.route("/des", methods=["GET", "POST"])
def des_page():
  message, key1, key2, key3, action = "", "", "", "", "encrypt"
  input_type = "message"
  answer = None
  elapsed_ns = None
  benchmark_input_size = None
  download_data = None
  filename = ""
  show_textbox = True
  download_filename = None

  if request.method == "POST":
    input_type = request.form.get("input_type", "message")
    key1 = request.form.get("key1", "")
    key2 = request.form.get("key2", "")
    key3 = request.form.get("key3", "")
    action = request.form.get("action", "")
    output_mode = request.form.get("output_mode", "textbox")
    export_name = _safe_export_name(request.form.get("export_name", ""), "3des_output")

    kf = read_upload_text(request.files.get("key_file"))
    if kf:
      triple = des_module.parse_triple_des_keys_from_file(kf)
      if triple:
        key1, key2, key3 = triple

    file_bytes = None
    uploaded_file = None
    msg = None
    err = None

    if input_type == "file":
      uploaded_file = request.files.get("file")
      if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
      else:
        err = "No file uploaded."
    else:
      message = request.form.get("message", "")
      if action == "encrypt":
        msg = message.encode()
      else:
        try:
          # textarea decrypt mode expects hex-encoded ciphertext
          msg = bytes.fromhex(message.replace(" ", "").replace("\n", ""))
        except ValueError:
          err = "Ciphertext must be valid hexadecimal."

    if err is None:
      start_ns = time.perf_counter_ns()
      try:
        data_in = file_bytes if file_bytes is not None else msg
        if data_in is None:
          raw = None
          answer = "ERROR: No message or file provided."
        else:
          raw = des3(data_in, key1, key2, key3, action)
          if isinstance(raw, str):
            answer = raw
          else:
            answer = raw
      except Exception:
        raw = None
        answer = "ERROR: Invalid input"
      end_ns = time.perf_counter_ns()
      elapsed_ns = end_ns - start_ns

      bad = isinstance(answer, str) and (
        answer.startswith("ERROR") or "Improper" in answer
      )
      if bad:
        # invalid decrypt/parse paths should not report timing
        elapsed_ns = None
        benchmark_input_size = None
        show_textbox = True
      elif isinstance(answer, bytes):
        benchmark_input_size = _input_size_bytes(data_in)
        _log_benchmark("des", action, input_type, benchmark_input_size, elapsed_ns)
        if action == "encrypt":
          # show hex in ui but download raw bytes to preserve exact data
          text_for_box = answer.hex()
          default_fn = (
            (uploaded_file.filename + ".enc")
            if uploaded_file and uploaded_file.filename
            else export_name + ".bin"
          )
        else:
          text_for_box = answer.decode("utf-8", errors="replace")
          default_fn = (
            uploaded_file.filename.rsplit(".", 1)[0] + ".dec"
            if uploaded_file and uploaded_file.filename and "." in uploaded_file.filename
            else export_name + ".dec"
          )
        o = _apply_output_mode(
          output_mode,
          text_for_box,
          download_bytes=answer,
          default_filename=_safe_export_name(request.form.get("export_name", "") or default_fn, default_fn),
        )
        answer = o["answer"]
        show_textbox = o["show_textbox"]
        download_data = o["download_data"]
        download_filename = o["download_filename"]
      else:
        benchmark_input_size = _input_size_bytes(data_in)
        _log_benchmark("des", action, input_type, benchmark_input_size, elapsed_ns)
        text_ans = str(answer)
        dl_bytes = None
        if isinstance(raw, bytes):
          dl_bytes = raw
        elif action == "encrypt":
          try:
            dl_bytes = bytes.fromhex(text_ans.replace(" ", "").replace("\n", ""))
          except ValueError:
            dl_bytes = text_ans.encode("utf-8")
        else:
          dl_bytes = text_ans.encode("utf-8")
        default_fn = (export_name + ".hex.txt") if action == "encrypt" else (export_name + ".txt")
        o = _apply_output_mode(
          output_mode,
          text_ans,
          download_bytes=dl_bytes,
          default_filename=_safe_export_name(request.form.get("export_name", "") or default_fn, default_fn),
        )
        answer = o["answer"]
        show_textbox = o["show_textbox"]
        download_data = o["download_data"]
        download_filename = o["download_filename"]

    if err:
      answer = f"ERROR: {err}"
      elapsed_ns = None
      benchmark_input_size = None

  return render_template(
    "des.html",
    current="des",
    message=message,
    key1=key1,
    key2=key2,
    key3=key3,
    action=action,
    answer=answer,
    elapsed_time=elapsed_ns,
    benchmark_algorithm="des",
    benchmark_action=action,
    benchmark_input_type=input_type,
    benchmark_input_size=benchmark_input_size,
    input_type=input_type,
    download_data=download_data,
    filename=filename,
    show_textbox=show_textbox,
    download_filename=download_filename,
  )


@app.route("/aes", methods=["GET", "POST"])
def aes_page():
  message = ""
  key_hex = ""
  key_bits = 128
  action = "encrypt"
  answer = None
  elapsed_ns = None
  benchmark_input_size = None
  input_type = "message"
  download_data = None
  filename = ""
  show_textbox = True
  download_filename = None

  if request.method == "POST":
    input_type = request.form.get("input_type", "message")
    kf_aes = read_upload_text(request.files.get("key_file"))
    key_hex = merge_key_field(request.form.get("key", ""), kf_aes)
    try:
      key_bits = int(request.form.get("key_bits", "128"))
    except ValueError:
      key_bits = 128
    action = request.form.get("action", "encrypt")
    output_mode = request.form.get("output_mode", "textbox")
    export_name = _safe_export_name(request.form.get("export_name", ""), "aes_output")

    file_bytes = None
    uploaded_file = None
    msg = None
    err = None

    if input_type == "file":
      uploaded_file = request.files.get("file")
      if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
      else:
        err = "No file uploaded."
    else:
      message = request.form.get("message", "")
      if action == "encrypt":
        msg = message.encode("utf-8")
      else:
        try:
          # allow users to paste spaced or multiline hex
          hex_clean = message.replace(" ", "").replace("\n", "")
          msg = bytes.fromhex(hex_clean)
        except ValueError:
          err = "Ciphertext must be valid hexadecimal."

    if err is None:
      start_ns = time.perf_counter_ns()
      try:
        data_in = file_bytes if file_bytes is not None else msg
        if data_in is None:
          answer = "ERROR: No message or file provided."
        else:
          out = aes_cipher(data_in, key_hex, key_bits, action)
          if action == "encrypt":
            text_for_box = out.hex()
            dl = out
            default_fn = (
              (uploaded_file.filename + ".aes") if uploaded_file and uploaded_file.filename else export_name + ".bin"
            )
          else:
            text_for_box = out.decode("utf-8", errors="replace")
            dl = out
            default_fn = export_name + ".dec" if not re.search(r"\.[a-z0-9]+$", export_name, re.I) else export_name
          o = _apply_output_mode(
            output_mode,
            text_for_box,
            download_bytes=dl,
            default_filename=_safe_export_name(request.form.get("export_name", "") or default_fn, default_fn),
          )
          answer = o["answer"]
          show_textbox = o["show_textbox"]
          download_data = o["download_data"]
          download_filename = o["download_filename"]
      except ValueError as exc:
        answer = f"ERROR: {exc}"
        show_textbox = True
      except Exception:
        answer = "ERROR: Invalid input or decryption failed."
        show_textbox = True
      end_ns = time.perf_counter_ns()
      elapsed_ns = end_ns - start_ns
      if not (isinstance(answer, str) and answer.startswith("ERROR")):
        benchmark_input_size = _input_size_bytes(data_in)
        _log_benchmark("aes", action, input_type, benchmark_input_size, elapsed_ns)
      else:
        # keep timing hidden on aes validation/decrypt failures
        elapsed_ns = None
        benchmark_input_size = None
    else:
      answer = f"ERROR: {err}"
      elapsed_ns = None
      benchmark_input_size = None

  return render_template(
    "aes.html",
    current="aes",
    message=message,
    key_hex=key_hex,
    key_bits=key_bits,
    action=action,
    answer=answer,
    elapsed_time=elapsed_ns,
    benchmark_algorithm="aes",
    benchmark_action=action,
    benchmark_input_type=input_type,
    benchmark_input_size=benchmark_input_size,
    input_type=input_type,
    download_data=download_data,
    filename=filename,
    show_textbox=show_textbox,
    download_filename=download_filename,
  )


if __name__ == "__main__":
  port = int(os.environ.get("PORT", "5001"))
  app.run(debug=True, host="0.0.0.0", port=port)
