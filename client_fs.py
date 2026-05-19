import socket
import random
import time
from crypto_fs import generer_cle, engagement, reponse, hash_to_c
from params import P, Q, G

HOST = '127.0.0.1'
PORT = 6000

def demarrer_client_fs():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("CLIENT FIAT-SHAMIR (non interactif)")
    print(f"Connecté au serveur {HOST}:{PORT}")
    
    # Inscription : générer et envoyer la clé publique
    x, y = generer_cle()
    print(f"\n[INSCRIPTION]")
    print(f"   Clé privée : x = {x}")
    print(f"   Clé publique : y = {y}")
    client.send(str(y).encode())
    
    # Authentification (plusieurs fois)
    for i in range(3):
        print(f"\n[AUTHENTIFICATION {i+1}]")
        
        # Étape 1 : Choisir r, calculer t
        r = random.randrange(1, Q)
        t = engagement(r)
        print(f"   r = {r}")
        print(f"   t = {t}")
        
        # Étape 2 : Calculer c = H(t, y, timestamp)
        timestamp = time.time()
        c = hash_to_c(t, y, timestamp)
        print(f"   timestamp = {timestamp}")
        print(f"   c = H(t, y, timestamp) = {c}")
        
        # Étape 3 : Calculer s
        s = reponse(r, x, c)
        print(f"   s = {s}")
        
        # Étape 4 : Envoyer (t, s, timestamp) en un seul message
        message = f"{t},{s},{timestamp}"
        client.send(message.encode())
        print(f"   Message envoyé : ({t}, {s}, {timestamp})")
        
        # Étape 5 : Recevoir le résultat
        resultat = client.recv(1024).decode()
        print(f"   Résultat : {resultat}")
    
    client.close()
    print("\nClient fermé")

if __name__ == "__main__":
    demarrer_client_fs()