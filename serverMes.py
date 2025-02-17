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

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("En attente de connexion...")
client, ip = server_socket.accept()
print(f"Le client d'IP {ip} s'est connecté.")

envoi = Thread(target=send, args=[client])
recep = Thread(target=reception, args=[client])

envoi.start()
recep.start()

recep.join()

client.close()
server_socket.close()
