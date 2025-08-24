from flask import Flask, render_template, request
from vigenere import vigenere_encrypt, vigenere_decrypt, auto_vigenere_decrypt

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    guessed_key = None
    if request.method == "POST":
        action = request.form.get("action")
        text = request.form.get("text")
        keyword = request.form.get("keyword", "")

        if action == "encrypt":
            result = vigenere_encrypt(text, keyword)
        elif action == "decrypt":
            result = vigenere_decrypt(text, keyword)
        elif action == "auto":
            result, guessed_key = auto_vigenere_decrypt(text)

    return render_template("index.html", result=result, guessed_key=guessed_key)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
