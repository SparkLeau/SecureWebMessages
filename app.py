from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import random
import string

app = Flask(__name__)
socketio = SocketIO(app)

users = {}

# Fonction de génération de clé aléatoire
def generate_random_key(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

# Chiffrement Vigenère
def vigenere_encrypt(text, key):
    alphabet = string.ascii_letters + string.digits + string.punctuation + " "
    encrypted = ""
    key = key * (len(text) // len(key)) + key[:len(text) % len(key)]

    for i in range(len(text)):
        char = text[i]
        key_char = key[i]
        if char in alphabet:
            new_index = (alphabet.index(char) + alphabet.index(key_char)) % len(alphabet)
            encrypted += alphabet[new_index]
        else:
            encrypted += char
    return encrypted

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on("connect")
def handle_connect():
    username = f"User_{random.randint(1000, 9999)}"
    gender = random.choice(["girl", "boy"])
    avatar_url = f"https://avatar.iran.liara.run/public/{gender}?username={username}"

    users[request.sid] = {
        "username": username,
        "avatar": avatar_url
    }

    emit("user_joined", {
        "username": username,
        "avatar": avatar_url
    }, broadcast=True)

    emit("set_username", {"username": username})

@socketio.on("disconnect")
def handle_disconnect():
    user = users.pop(request.sid, None)
    if user:
        emit("user_left", {
            "username": user["username"]
        }, broadcast=True)

@socketio.on("send_message")
def handle_message(data):
    user = users.get(request.sid)
    if user:
        key = generate_random_key()
        encrypted_message = vigenere_encrypt(data["message"], key)

        # Envoi du message chiffré et de la clé aux clients
        emit("new_message", {
            "username": user["username"],
            "avatar": user["avatar"],
            "message": encrypted_message,
            "key": key  
        }, broadcast=True)

@socketio.on("update_username")
def handle_update_username(data):
    old_username = users[request.sid]["username"]
    new_username = data["username"]
    users[request.sid]["username"] = new_username

    emit("username_updated", {
        "old_username": old_username,
        "new_username": new_username
    }, broadcast=True)

if __name__ == "__main__":
    socketio.run(app)
