from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import random
import string

app = Flask(__name__)
socketio = SocketIO(app)

users = {}

def generate_random_shift():
    return random.randint(1, 25)

def caesar_encrypt(text, shift):
    alphabet = string.ascii_letters + string.digits + string.punctuation + " "
    encrypted = ""

    for char in text:
        if char in alphabet:
            new_index = (alphabet.index(char) + shift) % len(alphabet)
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
        # Chiffrement César

@socketio.on("send_message")
def handle_message(data):
    user = users.get(request.sid)
    if user:
        shift = random.randint(1, 25)
        encrypted_message = caesar_encrypt(data["message"], shift)

        emit("new_message", {
            "username": user["username"],
            "avatar": user["avatar"],
            "message": encrypted_message,
            "key": shift
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
