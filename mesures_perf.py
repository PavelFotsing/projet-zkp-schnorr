import time
import random
import hashlib
from params import P, Q, G
from crypto import generer_cle, engagement, reponse, verification

def mesure_generation_cles(nb_tests=1000):
    """Mesure le temps de génération des clés"""
    temps_total = 0
    for _ in range(nb_tests):
        debut = time.perf_counter()
        x, y = generer_cle()
        fin = time.perf_counter()
        temps_total += (fin - debut) * 1000  # conversion en millisecondes
    return temps_total / nb_tests

def mesure_engagement(nb_tests=1000):
    """Mesure le temps de calcul de t = g^r"""
    temps_total = 0
    for _ in range(nb_tests):
        r = random.randrange(1, Q)
        debut = time.perf_counter()
        t = engagement(r)
        fin = time.perf_counter()
        temps_total += (fin - debut) * 1000
    return temps_total / nb_tests

def mesure_reponse(nb_tests=1000):
    """Mesure le temps de calcul de s = (r + x*c) mod Q"""
    x = random.randrange(1, Q)
    c = random.randrange(1, Q)
    temps_total = 0
    for _ in range(nb_tests):
        r = random.randrange(1, Q)
        debut = time.perf_counter()
        s = reponse(r, x, c)
        fin = time.perf_counter()
        temps_total += (fin - debut) * 1000
    return temps_total / nb_tests

def mesure_hash(nb_tests=1000):
    """Mesure le temps de hash SHA-256 (pour Fiat-Shamir)"""
    temps_total = 0
    for _ in range(nb_tests):
        t = random.randrange(1, P)
        y = random.randrange(1, P)
        timestamp = time.time()
        donnees = f"{t}{y}{timestamp}"
        debut = time.perf_counter()
        h = hashlib.sha256(donnees.encode()).hexdigest()
        c = int(h, 16) % Q
        fin = time.perf_counter()
        temps_total += (fin - debut) * 1000
    return temps_total / nb_tests

def mesure_verification(nb_tests=1000):
    """Mesure le temps de vérification g^s == t * y^c"""
    temps_total = 0
    for _ in range(nb_tests):
        # Génération de valeurs valides pour le test
        x = random.randrange(1, Q)
        y = pow(G, x, P)
        r = random.randrange(1, Q)
        t = pow(G, r, P)
        c = random.randrange(1, Q)
        s = (r + x * c) % Q
        
        debut = time.perf_counter()
        gauche = pow(G, s, P)
        droite = (t * pow(y, c, P)) % P
        ok = (gauche == droite)
        fin = time.perf_counter()
        temps_total += (fin - debut) * 1000
    return temps_total / nb_tests

def afficher_resultats():
    print("=" * 60)
    print("MESURES DE PERFORMANCE - Protocole de Schnorr")
    print("=" * 60)
    print(f"\nParamètres :")
    print(f"   p = {P} (bits : {P.bit_length()})")
    print(f"   q = {Q} (bits : {Q.bit_length()})")
    print(f"   g = {G}")
    print(f"\nMesures sur 1000 échantillons (temps en millisecondes) :")
    print("-" * 60)
    
    # Mesures
    temps_gen = mesure_generation_cles()
    temps_eng = mesure_engagement()
    temps_hash = mesure_hash()
    temps_rep = mesure_reponse()
    temps_verif = mesure_verification()
    
    # Affichage
    print(f"\n[CÔTÉ CLIENT]")
    print(f"   Génération des clés (x, y) : {temps_gen:.4f} ms")
    print(f"   Engagement (t = g^r)        : {temps_eng:.4f} ms")
    print(f"   Hash SHA-256 (Fiat-Shamir)  : {temps_hash:.4f} ms")
    print(f"   Réponse (s = r + x*c)       : {temps_rep:.4f} ms")
    print(f"   TOTAL client                : {temps_gen + temps_eng + temps_hash + temps_rep:.4f} ms")
    
    print(f"\n[CÔTÉ SERVEUR]")
    print(f"   Vérification (g^s ?= t·y^c) : {temps_verif:.4f} ms")
    
    print(f"\n[COMPARAISON]")
    print(f"   Version interactive (2 aller-retours) : {temps_eng + temps_rep + temps_verif:.4f} ms + RTT*2")
    print(f"   Version non interactive (1 aller-retour) : {temps_eng + temps_hash + temps_rep + temps_verif:.4f} ms + RTT")
    
    print("\n" + "=" * 60)
    print("Note : RTT = Round Trip Time (latence réseau)")
    print("       Les temps sont donnés à titre indicatif")
    print("       avec des paramètres de test (p=23, petits nombres)")
    print("=" * 60)

if __name__ == "__main__":
    afficher_resultats()