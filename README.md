# 🔐 Authentification sans mot de passe par protocole ZKP (Schnorr)

> Implémentation du protocole de Schnorr (Zero-Knowledge Proof) pour l'authentification sécurisée sans transmission de secret.

**Université de Yaoundé I — Département d'Informatique**  
**Année académique 2025–2026**

---

## 👥 Auteurs

| Nom | Matricule |
|-----|-----------|
| FOTSING KENGNE Diane Iris | 17T2631 |
| KOUGOUM FOTSING Pavel | 21T2887 |

---

## 📌 Description du projet

Ce projet implémente le **protocole de Schnorr**, une preuve à connaissance nulle (Zero-Knowledge Proof), permettant à un client de prouver qu'il connaît un secret **sans jamais le révéler** sur le réseau.

Trois versions sont proposées :

| Version | Port | Type | Anti-rejeu |
|---------|------|------|------------|
| Interactive | 5000 | 3 messages (t → c → s) | ❌ N/A |
| Fiat-Shamir vulnérable | 6000 | 1 message (t, s, timestamp) | ❌ Non |
| Fiat-Shamir sécurisée | 7000 | 1 message (t, s, timestamp) | ✅ Oui |

---

## 🧠 Principe mathématique

**Paramètres publics :** `(p, q, g)` avec clé privée `x` et clé publique `y = g^x mod p`

Le protocole en 4 étapes :

```
Client                          Serveur
  |  ── 1. t = g^r mod p ──▶  |
  |  ◀── 2. c (aléatoire) ──  |
  |  ── 3. s = (r + x·c) mod q ──▶  |
  |  ◀── 4. OK / FAIL ──       |
```

**Vérification :** `g^s ≡ t · y^c (mod p)`  
**Correctness :** `t · y^c = g^r · (g^x)^c = g^(r+xc) = g^s` ✓

---

## 📁 Structure du projet

```
Projet_ZKP/
├── interface.py          # Interface graphique Tkinter (3 onglets)
├── params.py             # Paramètres publics (p, q, g)
├── crypto.py             # Cryptographie version interactive
├── crypto_fs.py          # Cryptographie version Fiat-Shamir
├── serveur_auth.py       # Serveur interactif (port 5000)
├── client_auth.py        # Client interactif
├── serveur_fs.py         # Serveur Fiat-Shamir vulnérable (port 6000)
├── client_fs.py          # Client Fiat-Shamir
├── serveur_secure.py     # Serveur sécurisé anti-rejeu (port 7000)
├── pirate_rejeu.py       # Simulation d'attaque par rejeu
├── mesures_perf.py       # Mesures de performance
└── README.md
```

---

## ⚙️ Installation

*Prérequis :* Python 3.11+

```bash
# Cloner le dépôt
git clone https://github.com/TON-USERNAME/projet-zkp-schnorr.git
cd projet-zkp-schnorr

# Installer les dépendances
pip install pycryptodome
```

> `tkinter` est inclus par défaut avec Python. Si absent : `sudo apt install python3-tk`

---

##  Utilisation

### Interface graphique (recommandée)

```bash
python3 interface.py
```

L'interface propose 3 onglets :
- **Onglet 1** — Protocole interactif (port 5000)
- **Onglet 2** — Fiat-Shamir vulnérable + démonstration d'attaque (port 6000)
- **Onglet 3** — Version sécurisée anti-rejeu (port 7000)

### En ligne de commande

```bash
# Version interactive
python3 serveur_auth.py        # Terminal 1
python3 client_auth.py         # Terminal 2

# Version Fiat-Shamir sécurisée
python3 serveur_secure.py      # Terminal 1
python3 client_secure.py       # Terminal 2

# Simuler une attaque par rejeu
python3 pirate_rejeu.py

# Mesurer les performances
python3 mesures_perf.py
```

---

## 🛡️ Sécurité

### Résistance à l'interception passive
Seules les valeurs `t`, `c` et `s` circulent sur le réseau. La clé privée `x` **n'apparaît jamais**, garantissant la propriété de connaissance nulle.

### Résistance au rejeu (version sécurisée)
Le serveur applique deux vérifications :
1. **Timestamp déjà vu** → rejet immédiat
2. **Timestamp expiré** (> 60 secondes) → rejet immédiat

```python
if timestamp in timestamps_vus:
    return "REJET - Rejeu"
if abs(time.time() - timestamp) > 60:
    return "REJET - Timestamp expiré"
timestamps_vus.add(timestamp)
```

---

## 📊 Performances

Mesures effectuées sur **1 000 échantillons** :

| Opération | Côté | Temps moyen |
|-----------|------|-------------|
| Génération des clés | Client | 0.0023 ms |
| Engagement `t = g^r` | Client | 0.0018 ms |
| Hash SHA-256 | Client | 0.0150 ms |
| Réponse `s = r + x·c` | Client | 0.0004 ms |
| Vérification | Serveur | 0.0025 ms |
| **Total client** | | **0.0195 ms** |

> La charge cryptographique est négligeable. Le goulot d'étranglement est la **latence réseau**.

---

## 📚 Références

- Schnorr, C.P. (1989). *Efficient Identification and Signatures for Smart Cards*. CRYPTO 1989.
- Fiat, A., Shamir, A. (1986). *How to Prove Yourself*. CRYPTO 1986.
- Goldwasser, S., Micali, S., Rackoff, C. (1985). *The Knowledge Complexity of Interactive Proof Systems*. STOC 1985.

---

## 📄 Licence

Projet académique — Université de Yaoundé I, 2025–2026. Usage éducatif uniquement.
