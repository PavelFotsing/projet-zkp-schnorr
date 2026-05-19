import random
import hashlib
from params import P, G, Q

def generer_cle():
    x = random.randrange(1, Q)
    y = pow (G, x, P)
    return x, y

def engagement(r):
    return pow(G,r,P)

def reponse(r,x,c):
    return (r+x*c)%Q

def hash_to_c(t, y, timestamp):
    donnees = f"{t}{y}{timestamp}"
    h = hashlib.sha256(donnees.encode()).hexdigest()
    return int(h, 16) % Q

def verification (t, s, y, timestamp):
    """vérification avec Fiat-shamir"""
    c = hash_to_c(t, y, timestamp)
    gauche = pow(G, s, P)
    droite = (t*pow(y, c, P))%P
    return gauche == droite
