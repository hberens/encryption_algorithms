from flask import Flask, request, render_template
import os
import time
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
  return render_template("rsa.html", current="rsa")

@app.route("/des", methods=["GET", "POST"])
def des_page():
  message, key1, key2, key3, action, answer, elapsed_ns = "", "", "", "", "encrypt", None, None

  if request.method == "POST":
    message = request.form.get("message", "")
    key1 = request.form.get("key1", "")
    key2 = request.form.get("key2", "")
    key3 = request.form.get("key3", "")
    action = request.form.get("action", "")
    start_ns = time.perf_counter_ns()
    answer = des3(message, key1, key2, key3, action)
    end_ns = time.perf_counter_ns()
    elapsed_ns = end_ns - start_ns

  return render_template("des.html", current="des", message=message, key1=key1, key2=key2, key3=key3, action=action, answer=answer, elapsed_time=elapsed_ns)

@app.route("/aes", methods=["GET", "POST"])
def aes_page():
  return render_template("aes.html", current="aes")

if __name__ == "__main__":
  port = int(os.environ.get("PORT", "5001"))
  app.run(debug=True, host="0.0.0.0", port=port)