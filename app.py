from flask import Flask, request, render_template
import os
import time
import base64
from algorithms import vigenere, des3, aes, rsa

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home_page():
  return render_template("home.html", current="home")

@app.route("/vigenere", methods=["GET", "POST"])
def vigenere_page():
  message, key, action, answer, elapsed_ns, vigenere_steps = "", "", "encrypt", None, None, None

  if request.method == "POST":
    message = request.form.get("message", "")
    key = request.form.get("key", "")
    action = request.form.get("action", "")
    start_ns = time.perf_counter_ns()
    out = vigenere(message, key, action)
    answer = out["text"]
    vigenere_steps = out["steps"]
    end_ns = time.perf_counter_ns()
    elapsed_ns = end_ns - start_ns

  return render_template(
    "vigenere.html",
    current="vigenere",
    message=message,
    key=key,
    action=action,
    answer=answer,
    elapsed_time=elapsed_ns,
    vigenere_steps=vigenere_steps,
  )

@app.route("/rsa", methods=["GET", "POST"])
def rsa_page():
  message = ""
  action = "encrypt"
  answer = None
  elapsed_ns = None
  rsa_steps = None
  rsa_keys = None
  rsa_error = None

  if request.method == "POST":
    message = request.form.get("message", "")
    action = request.form.get("action", "encrypt")
    regenerate = bool(request.form.get("generate"))
    start_ns = time.perf_counter_ns()
    out = rsa(
      message,
      action,
      n_str=request.form.get("n", ""),
      e_str=request.form.get("e", ""),
      d_str=request.form.get("d", ""),
      p_str=request.form.get("p", ""),
      q_str=request.form.get("q", ""),
      phi_str=request.form.get("phi", ""),
      regenerate=regenerate,
    )
    answer = out["text"]
    rsa_steps = out["steps"]
    rsa_keys = out["keys"]
    rsa_error = out["error"]
    end_ns = time.perf_counter_ns()
    elapsed_ns = end_ns - start_ns

  return render_template(
    "rsa.html",
    current="rsa",
    message=message,
    action=action,
    answer=answer,
    elapsed_time=elapsed_ns,
    rsa_steps=rsa_steps,
    rsa_keys=rsa_keys,
    rsa_error=rsa_error,
  )

@app.route("/des", methods=["GET", "POST"])
def des_page():
  message, key1, key2, key3, action, answer, elapsed_ns = "", "", "", "", "encrypt", None, None
  input_type = "message"
  download_data = None
  filename = ""

  if request.method == "POST":
    input_type = request.form.get("input_type", "message")
    file_bytes = None
    key1 = request.form.get("key1", "")
    key2 = request.form.get("key2", "")
    key3 = request.form.get("key3", "")
    action = request.form.get("action", "")
    if input_type == "file":
      uploaded_file = request.files.get("file")
      if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
    else:
      message = request.form.get("message", "")
      if action == "encrypt":
        msg = message.encode()
      else:
        try:
          msg = bytes.fromhex(message)
        except:
          pass
        


    start_ns = time.perf_counter_ns()
    try:
      answer = des3(file_bytes if file_bytes is not None else msg, key1, key2, key3, action)
    except:
      answer = "ERROR: Invalid Input"
    end_ns = time.perf_counter_ns()
    elapsed_ns = end_ns - start_ns

    # Prepare download data if answer is bytes
    if input_type == "file":
      download_data = base64.b64encode(answer).decode('utf-8')
      filename = uploaded_file.filename
    elif action == "encrypt":
      answer = answer.hex()
    elif isinstance(answer, bytes):
      answer = answer.decode('utf-8')

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
    input_type=input_type,
    download_data=download_data,
    filename=filename
  )

@app.route("/aes", methods=["GET", "POST"])
def aes_page():
  return render_template("aes.html", current="aes")

if __name__ == "__main__":
  port = int(os.environ.get("PORT", "5001"))
  app.run(debug=True, host="0.0.0.0", port=port)