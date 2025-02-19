import socket
import os
from dotenv import load_dotenv
from threading import Thread
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import string
import random

load_dotenv()
HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT"))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

users = {}

def vigenere_cipher(text, key):
    alphabet = string.ascii_letters
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    result = ""
    
    for i, char in enumerate(text):
        if char in alphabet:
            shift = alphabet.index(key[i])
            new_index = (alphabet.index(char) + shift) % len(alphabet)
            result += alphabet[new_index]
        else:
            result += char

    return result

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on("connect")
def handle_connect():
    username = f"User_{random.randint(1000,9999)}"
    gender = random.choice(["girl","boy"])
    avatar_url = f" https://avatar.iran.liara.run/public/{gender}?username={username}"

    users[request.sid] = { "username":username,"avatar":avatar_url}

    emit("user_joined", {"username":username,"avatar":avatar_url},broadcast=True)

    emit("set_username", {"username":username})

@socketio.on("disconnect")
def handle_disconnect():
    user = users.pop(request.sid, None)
    if user:
      emit("user_left", {"username":user["username"]},broadcast=True)

@socketio.on("send_message")
def handle_message(data):
    user = users.get(request.sid)
    if user:
        emit("new_message", {
            "username":user["username"],
            "avatar":user["avatar"],
            "message":data["message"]
        }, broadcast=True)

@socketio.on("update_username")
def handle_update_username(data):
    old_username = users[request.sid]["username"]
    new_username = data["username"]
    users[request.sid]["username"] = new_username

    emit("username_updated", {
        "old_username":old_username,
        "new_username":new_username
    }, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, HOST, PORT)
