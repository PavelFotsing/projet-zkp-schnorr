import socket
import time

HOST = '127.0.0.1'
PORT = 6000

def pirate():
    print("=" *60)
    print("🏴‍☠️  PIRATE - Attaque par rejeu")
    print("=" * 60)

    t_capture =  4   
    s_capture =  3    
    timestamp_capture = 1777552379.3923736

   
    print(f"\n[CAPTURE] Valeurs interceptées :")
    print(f"   t = {t_capture}")
    print(f"   s = {s_capture}")
    print(f"   timestamp = {timestamp_capture}")

    print(f"\n[REJEU] Tentative de rejeu...")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("Connecté au serveur")

    # Envoi d'une clé publique (peu importe laquelle)
    client.send(b"18")
    time.sleep(0.1)
    print("   Clé publique envoyée")

    # Rejeu du message capturé
    message = f"{t_capture},{s_capture},{timestamp_capture}"
    client.send(message.encode())
    print(f"   Message rejoué : ({t_capture}, {s_capture}, {timestamp_capture})")
    

    # Réception du résultat
    resultat = client.recv(1024).decode()
    print(f"\n[RÉSULTAT] {resultat}")
    

    if resultat == "OK":
        print("\n⚠️  ATTAQUE RÉUSSIE !")
        print("   Le serveur a accepté le rejeu.")
        print("   Cause : absence de vérification du timestamp.")
    else:
        print("\n✅ ATTAQUE ÉCHOUÉE")
        print("   Le serveur a détecté le rejeu.")
    client.close()

if __name__ == "__main__":
   pirate()