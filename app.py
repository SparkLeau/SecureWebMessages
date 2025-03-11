from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import random

app = Flask(__name__)
socketio = SocketIO(app)

users = {}

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
        "avatar": avatar_url,
        "public_key": None
    }

    emit("user_joined", {
        "username": username,
        "avatar": avatar_url
    }, broadcast=True)

    emit("set_username", {"username": username})

    # Send the public keys of all connected users to the new user
    for sid, user in users.items():
        if user["public_key"]:
            emit("public_key", {"username": user["username"], "publicKey": user["public_key"]}, room=request.sid)

@socketio.on("disconnect")
def handle_disconnect():
    user = users.pop(request.sid, None)
    if user:
        emit("user_left", {
            "username": user["username"]
        }, broadcast=True)

@socketio.on("public_key")
def handle_public_key(data):
    if "publicKey" in data:
        if request.sid in users:
            users[request.sid]["public_key"] = data["publicKey"]
            emit("public_key", {"username": users[request.sid]["username"], "publicKey": data["publicKey"]}, broadcast=True)
    else:
        print("publicKey not found in data")

@socketio.on("request_public_key")
def handle_request_public_key():
    if request.sid in users and users[request.sid]["public_key"]:
        emit("public_key", {"username": users[request.sid]["username"], "publicKey": users[request.sid]["public_key"]})

@socketio.on("send_message")
def handle_message(data):
    sender = users.get(request.sid)
    if sender:
        for sid, user in users.items():
            if user["username"] in data["keys"]:
                emit("new_message", {
                    "username": sender["username"],
                    "avatar": sender["avatar"],
                    "message": data["message"],  # Already encrypted on the client side
                    "key": data["keys"][user["username"]],  # Send the corresponding encrypted key
                    "iv": data["iv"]  # Send the IV directly
                }, room=sid)

@socketio.on("update_username")
def handle_update_username(data):
    old_username = users[request.sid]["username"]
    new_username = data["username"]
    users[request.sid]["username"] = new_username

    emit("username_updated", {
        "old_username": old_username,
        "new_username": new_username
    }, broadcast=True)

    # Send the updated public key to all users
    if users[request.sid]["public_key"]:
        emit("public_key", {"username": new_username, "publicKey": users[request.sid]["public_key"]}, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, ssl_context=('cert.pem','key.pem')) 
