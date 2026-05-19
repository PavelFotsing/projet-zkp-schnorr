import socket
import random

from crypto import verification
from params import G, P, Q

HOST = '127.0.0.1'
PORT = 5000

def demarrer_serveur():
    # Dictionnaire pour stocker les clés publiques des clients
    # (en vrai, ce serait une base de données)
    base_clients = {}

    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind((HOST, PORT))
    serveur.listen()
    print(f"Serveur démarré sur {HOST}:{PORT}")

    #On va traiter un client à la fois

    connexion, addr = serveur.accept()
    print(f"Client connecté: {addr}")

    # Etape 1: Recevoir la clé publique (inscription)
    
    y_str = connexion.recv(1024).decode()
    y = int(y_str)
    client_id = addr[1] # utiliser le port comme identifiant
    base_clients[client_id] = y
    print(f"Clé publique reçue : y = {y} ")

    # Boucle d'authentification (plusieurs fois possible)

    while True:
        # Etape 2: recevoir t
        t_str = connexion.recv(1024).decode()
        if not t_str:
            break
        t = int(t_str)
        print(f"Reçu t = {t}")

        # Etape 3: Générer c aléatoire
        c = random.randrange(1, Q)
        print(f"Généré c = {c}")
        connexion.send(str(c).encode())

        # Etappe 4: Recevoir s
        s_str = connexion.recv(1024).decode()
        s = int(s_str)
        print(f"Reçu s = {s}")

        # Etape 5: Vérifier

        if verification(t, s, y, c):
            print("✅ Authentification réussie")
            connexion.send(b"OK")
        else: 
            print("❌ Authentification échouée")
            connexion.send(b"FAIL")

    connexion.close()
    serveur.close()
        
if __name__=="__main__":
    demarrer_serveur()