from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import random
import base64
import string

app = Flask(__name__)
socketio = SocketIO(app)

users = {}

def generate_aes_key():
    return os.urandom(32)

def generate_iv():
    return os.urandom(16)  # AES requires a 16-byte IV for CBC mode

def aes_encrypt(text, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - len(text) % 16
    text = text + chr(pad_len) * pad_len

    encrypted = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

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
        key = generate_aes_key()
        iv = generate_iv()
        encrypted_message = aes_encrypt(data["message"], key, iv)

        emit("new_message", {
            "username": user["username"],
            "avatar": user["avatar"],
            "message": encrypted_message,
            "key": base64.b64encode(key).decode(),
            "iv": base64.b64encode(iv).decode()
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
