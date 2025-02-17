import socket
import os
from dotenv import load_dotenv
from threading import Thread

load_dotenv()
HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT"))

def send(client):
    while True:
        msg = input("Serveur → ")
        msg = msg.encode("utf-8")
        client.send(msg)

def reception(client):
    while True:
        requete_client = client.recv(500)
        requete_client = requete_client.decode("utf-8")
        print(f"Client: {requete_client}")
        if not requete_client:
            print("CLOSE")
            break

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

envoi = Thread(target=send, args=[client_socket])
recp = Thread(target=reception, args=[client_socket])

envoi.start()
recp.start()

