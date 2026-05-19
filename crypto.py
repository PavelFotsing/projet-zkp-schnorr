import random
from params import P, G, Q

def generer_cle():
    """Génère une paire de clés (x,y)"""
    x=random.randrange(1, Q)  # x est entre 1 et Q-1
    y= pow (G, x, P)           # y= G^x mod P
    return x, y

def engagement(r):
    """Calcule t=G^r mod P"""
    t= pow (G,r,P)
    return t

def reponse (r,x,c):
    s=(r+x*c) % Q
    return s

def verification(t,s,y,c):
    """Vérification de G^s==t*y^c mod P"""
    gauche = pow(G,s,P)
    droite = (t*pow(y,c,P)) % P
    return gauche == droite 

