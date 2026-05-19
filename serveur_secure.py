import socket
import time
from crypto_fs import verification
from params import G, P, Q

HOST = '127.0.0.1'
PORT = 7000  # Port différent pour ne pas confluer

def demarrer_serveur_secure():
    base_clients = {}
    timestamps_vus = set()  # Stocke les timestamps déjà utilisés
    
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind((HOST, PORT))
    serveur.listen()
    print(f"SERVEUR SÉCURISÉ (avec contre-mesure anti-rejeu)")
    print(f"Serveur démarré sur {HOST}:{PORT}")
    
    connexion, addr = serveur.accept()
    print(f"Client connecté: {addr}")
    
    # Inscription : recevoir la clé publique
    y_str = connexion.recv(1024).decode()
    y = int(y_str)
    base_clients[addr[1]] = y
    print(f"Clé publique reçue : y = {y}")
    
    while True:
        data = connexion.recv(1024).decode()
        if not data:
            break
        
        parts = data.split(',')
        t = int(parts[0])
        s = int(parts[1])
        timestamp = float(parts[2])
        
        print(f"\nMessage reçu: t={t}, s={s}, timestamp={timestamp}")
        
        # CONTRE-MESURE 1 : Vérifier l'unicité du timestamp
        if timestamp in timestamps_vus:
            print("   ❌ REJET : Timestamp déjà utilisé (rejeu détecté)")
            connexion.send(b"REJET - Rejeu")
            continue
        
        # CONTRE-MESURE 2 : Vérifier la fraîcheur (60 secondes max)
        age = abs(time.time() - timestamp)
        if age > 60:
            print(f"   ❌ REJET : Timestamp trop vieux ({age:.0f} secondes)")
            connexion.send(b"REJET - Timestamp expire")
            continue
        
        # Vérification cryptographique standard
        if verification(t, s, y, timestamp):
            print("   ✅ Authentification réussie")
            timestamps_vus.add(timestamp)  # On mémorise
            connexion.send(b"OK")
        else:
            print("   ❌ Authentification échouée")
            connexion.send(b"FAIL")
    
    connexion.close()
    serveur.close()

if __name__ == "__main__":
    demarrer_serveur_secure()