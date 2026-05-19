import socket
import random
from crypto import generer_cle, engagement, reponse
from params import P, Q, G

HOST = '127.0.0.1'
PORT = 5000

def demarrer_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("Connecté au serveur")
    
    # Phase 1 : Inscription (envoyer la clé publique)
    x, y = generer_cle()
    print(f"Clé privée : x = {x}")
    print(f"Clé publique : y = {y}")
    client.send(str(y).encode())
    print("Clé publique envoyée")
    
    # Phase 2 : Authentification
    for i in range(3):
        print(f"\n--- Authentification {i+1} ---")
        
        # Étape 1 : Choisir r, calculer t
        r = random.randrange(1, Q)
        t = engagement(r)
        print(f"r = {r}, t = {t}")
        client.send(str(t).encode())
        
        # Étape 2 : Recevoir c
        c_str = client.recv(1024).decode()
        c = int(c_str)
        print(f"c reçu = {c}")
        
        # Étape 3 : Calculer s (corrigé : avant le print)
        s = reponse(r, x, c)
        print(f"s = {s}")  # maintenant s existe !
        client.send(str(s).encode())
        
        # Étape 4 : Recevoir le résultat
        resultat = client.recv(1024).decode()
        print(f"Résultat : {resultat}")
    
    client.close()

if __name__ == "__main__":
    demarrer_client()