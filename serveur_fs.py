import socket
import time
from crypto_fs import verification
from params import G, P, Q

HOST = '127.0.0.1'
PORT = 6000  # Port différent pour ne pas confluer

def demarrer_serveur_fs():
    base_clients = {}
    
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind((HOST, PORT))
    serveur.listen()
    print(f"SERVEUR FIAT-SHAMIR (non interactif)")
    print(f"Serveur démarré sur {HOST}:{PORT}")
    
    connexion, addr = serveur.accept()
    print(f"Client connecté: {addr}")
    
    # Inscription : recevoir la clé publique
    y_str = connexion.recv(1024).decode()
    y = int(y_str)
    base_clients[addr[1]] = y
    print(f"Clé publique reçue : y = {y}")
    
    while True:
        # Recevoir le message unique (t, s, timestamp)
        data = connexion.recv(1024).decode()
        if not data:
            break
        
        # Format: "t,s,timestamp"
        parts = data.split(',')
        t = int(parts[0])
        s = int(parts[1])
        timestamp = float(parts[2])
        
        print(f"\nMessage reçu:")
        print(f"   t = {t}")
        print(f"   s = {s}")
        print(f"   timestamp = {timestamp}")
        
        # Vérification
        if verification(t, s, y, timestamp):
            print("   ✅ Authentification réussie")
            connexion.send(b"OK")
        else:
            print("   ❌ Authentification échouée")
            connexion.send(b"FAIL")
    
    connexion.close()
    serveur.close()

if __name__ == "__main__":
    demarrer_serveur_fs()