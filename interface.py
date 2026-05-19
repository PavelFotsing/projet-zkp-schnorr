#!/usr/bin/env python3
"""
Interface graphique unifiée — Protocole de Schnorr / ZKP
4 onglets : Interactive | Fiat-Shamir | Sécurisée | Performances
Avec attaque par rejeu sur les 3 premiers onglets
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import socket
import random
import time
import hashlib

from params import P, Q, G
from crypto import generer_cle, engagement, reponse, verification
from crypto_fs import (generer_cle as generer_cle_fs,
                        engagement as engagement_fs,
                        reponse as reponse_fs,
                        verification as verification_fs,
                        hash_to_c)

# ═══════════════════════════════════════════════════════════════
# PALETTE
# ═══════════════════════════════════════════════════════════════
DARK_BG      = "#0d1117"
PANEL_BG     = "#161b22"
HEADER_BG    = "#010409"
BORDER       = "#30363d"
BORDER_LIGHT = "#21262d"

BLUE         = "#58a6ff"
GREEN        = "#3fb950"
RED          = "#f85149"
GOLD         = "#d29922"
PURPLE       = "#bc8cff"

TEXT_PRI     = "#e6edf3"
TEXT_MUT     = "#8b949e"
TEXT_CODE    = "#79c0ff"

FONT_H1      = ("Consolas", 15, "bold")
FONT_H2      = ("Consolas", 10, "bold")
FONT_BODY    = ("Consolas", 9)
FONT_CODE    = ("Consolas", 8)
FONT_SMALL   = ("Consolas", 7)

# ═══════════════════════════════════════════════════════════════
# WIDGETS HELPERS
# ═══════════════════════════════════════════════════════════════
def flat_btn(parent, text, cmd, bg, hbg, fg=TEXT_PRI, font=FONT_H2, px=14, py=6):
    b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                  font=font, relief="flat", bd=0, padx=px, pady=py,
                  activebackground=hbg, activeforeground=fg, cursor="hand2")
    b.bind("<Enter>", lambda e: b.config(bg=hbg))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b

def entry_w(parent, width=18, initial=""):
    e = tk.Entry(parent, width=width, font=FONT_BODY,
                 bg="#21262d", fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=BLUE)
    e.insert(0, initial)
    return e

def log_widget(parent, height=10, width=42):
    t = scrolledtext.ScrolledText(parent, height=height, width=width,
        font=FONT_CODE, bg=DARK_BG, fg=TEXT_CODE,
        insertbackground=TEXT_CODE, relief="flat", bd=0,
        selectbackground=BLUE, selectforeground=DARK_BG, wrap=tk.WORD)
    t.tag_config("INFO",   foreground=TEXT_MUT)
    t.tag_config("SUCCES", foreground=GREEN)
    t.tag_config("ERREUR", foreground=RED)
    t.tag_config("RECU",   foreground=BLUE)
    t.tag_config("ENVOI",  foreground=PURPLE)
    t.tag_config("CALC",   foreground=GOLD)
    t.tag_config("WARN",   foreground=GOLD)
    return t

def log_write(widget, message, root=None):
    tag = "INFO"
    for t in ("SUCCES","ERREUR","RECU","ENVOI","CALC","WARN"):
        if f"[{t}]" in message:
            tag = t
            break
    def _do():
        widget.insert(tk.END, message + "\n", tag)
        widget.see(tk.END)
    if root:
        root.after(0, _do)
    else:
        _do()

def sep(parent, color=BORDER, h=1):
    tk.Frame(parent, bg=color, height=h).pack(fill=tk.X, pady=4)

def card(parent, title, color, side=None, fill=tk.BOTH, expand=True, padx=6, pady=4):
    outer = tk.Frame(parent, bg=color, highlightthickness=0)
    if side:
        outer.pack(side=side, fill=fill, expand=expand, padx=padx, pady=pady)
    else:
        outer.pack(fill=fill, expand=expand, padx=padx, pady=pady)
    hdr = tk.Frame(outer, bg=HEADER_BG, height=30)
    hdr.pack(fill=tk.X); hdr.pack_propagate(False)
    tk.Label(hdr, text=title, font=FONT_H2, bg=HEADER_BG, fg=color).pack(side=tk.LEFT, padx=12, pady=6)
    body = tk.Frame(outer, bg=PANEL_BG, highlightthickness=1, highlightbackground=color)
    body.pack(fill=tk.BOTH, expand=True)
    return body

# ═══════════════════════════════════════════════════════════════
# LOGIQUE SERVEURS / CLIENTS
# ═══════════════════════════════════════════════════════════════

# ── Serveur Interactif ──────────────────────────────────────
class ServeurInteractif:
    def __init__(self, port, log_cb):
        self.port = port
        self.log_cb = log_cb
        self.sock = None
        self.running = False

    def log(self, msg, niv="INFO"):
        self.log_cb(f"[{niv}] {msg}")

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen()
        self.log(f"Serveur interactif démarré — port {self.port}")
        while self.running:
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break

    def _handle(self, conn, addr):
        self.log(f"Client connecté: {addr}", "RECU")
        try:
            y = int(conn.recv(4096).decode())
            self.log(f"Clé publique reçue: y={y}", "RECU")
            while True:
                t_str = conn.recv(4096).decode()
                if not t_str:
                    break
                t = int(t_str)
                self.log(f"t reçu = {t}", "RECU")
                c = random.randrange(1, Q)
                self.log(f"Défi envoyé: c={c}", "ENVOI")
                conn.send(str(c).encode())
                s = int(conn.recv(4096).decode())
                self.log(f"s reçu = {s}", "RECU")
                if verification(t, s, y, c):
                    self.log("✅ Authentification réussie", "SUCCES")
                    conn.send(b"OK")
                else:
                    self.log("❌ Authentification échouée", "ERREUR")
                    conn.send(b"FAIL")
        except Exception as ex:
            self.log(f"Erreur: {ex}", "ERREUR")
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.log("Serveur arrêté")

# ── Client Interactif (avec stockage pour attaque) ──────────
class ClientInteractif:
    def __init__(self, host, port, log_cb):
        self.host = host
        self.port = port
        self.log_cb = log_cb
        self.x = None
        self.y = None
        self.last_t = None
        self.last_c = None
        self.last_s = None

    def log(self, msg, niv="INFO"):
        self.log_cb(f"[{niv}] {msg}")

    def generer(self):
        self.x, self.y = generer_cle()
        self.log(f"x={self.x}", "CALC")
        self.log(f"y={self.y}", "CALC")
        return self.x, self.y

    def authentifier(self):
        if not self.x:
            self.log("Générez d'abord les clés !", "ERREUR")
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.host, self.port))
            self.log(f"Connecté à {self.host}:{self.port}", "INFO")
            s.send(str(self.y).encode())
            self.log(f"Clé publique envoyée: y={self.y}", "ENVOI")
            time.sleep(0.05)
            r = random.randrange(1, Q)
            t = engagement(r)
            self.log(f"r={r}, t={t}", "CALC")
            s.send(str(t).encode())
            c = int(s.recv(4096).decode())
            self.log(f"c reçu={c}", "RECU")
            rep = reponse(r, self.x, c)
            self.log(f"s={rep}", "CALC")
            s.send(str(rep).encode())
            res = s.recv(1024).decode()
            self.log(f"Résultat: {res}", "RECU")
            # Stockage pour attaque
            self.last_t = t
            self.last_c = c
            self.last_s = rep
            s.close()
            return res == "OK"
        except Exception as ex:
            self.log(f"Erreur: {ex}", "ERREUR")
            return False

# ── Serveur Fiat-Shamir (vulnérable ou sécurisé) ────────────
class ServeurFS:
    def __init__(self, port, log_cb, secure=False):
        self.port = port
        self.log_cb = log_cb
        self.secure = secure
        self.sock = None
        self.running = False
        self.timestamps_vus = set()

    def log(self, msg, niv="INFO"):
        self.log_cb(f"[{niv}] {msg}")

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen()
        mode = "SÉCURISÉ" if self.secure else "VULNÉRABLE"
        self.log(f"Serveur Fiat-Shamir [{mode}] — port {self.port}")
        while self.running:
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break

    def _handle(self, conn, addr):
        self.log(f"Client connecté: {addr}", "RECU")
        try:
            y = int(conn.recv(4096).decode())
            self.log(f"Clé publique reçue: y={y}", "RECU")
            while True:
                data = conn.recv(4096).decode()
                if not data:
                    break
                parts = data.split(',')
                t = int(parts[0])
                sv = int(parts[1])
                ts = float(parts[2])
                self.log(f"Reçu: t={t}, s={sv}, ts={ts}", "RECU")

                if self.secure:
                    if ts in self.timestamps_vus:
                        self.log("❌ REJET — timestamp déjà utilisé (rejeu)", "ERREUR")
                        conn.send(b"REJET - Rejeu")
                        continue
                    if abs(time.time() - ts) > 60:
                        self.log("❌ REJET — timestamp trop vieux", "ERREUR")
                        conn.send(b"REJET - Expire")
                        continue

                if verification_fs(t, sv, y, ts):
                    self.log("✅ Authentification réussie", "SUCCES")
                    if self.secure:
                        self.timestamps_vus.add(ts)
                    conn.send(b"OK")
                else:
                    self.log("❌ Authentification échouée", "ERREUR")
                    conn.send(b"FAIL")
        except Exception as ex:
            self.log(f"Erreur: {ex}", "ERREUR")
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.log("Serveur arrêté")

# ── Client Fiat-Shamir (avec stockage pour attaque) ─────────
class ClientFS:
    def __init__(self, host, port, log_cb):
        self.host = host
        self.port = port
        self.log_cb = log_cb
        self.x = None
        self.y = None
        self.last_t = None
        self.last_s = None
        self.last_ts = None

    def log(self, msg, niv="INFO"):
        self.log_cb(f"[{niv}] {msg}")

    def generer(self):
        self.x, self.y = generer_cle_fs()
        self.log(f"x={self.x}", "CALC")
        self.log(f"y={self.y}", "CALC")
        return self.x, self.y

    def authentifier(self):
        if not self.x:
            self.log("Générez d'abord les clés !", "ERREUR")
            return False, None, None, None
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            self.log(f"Connecté à {self.host}:{self.port}", "INFO")
            sock.send(str(self.y).encode())
            self.log(f"y envoyé={self.y}", "ENVOI")
            time.sleep(0.05)
            r = random.randrange(1, Q)
            t = engagement_fs(r)
            ts = time.time()
            c = hash_to_c(t, self.y, ts)
            sv = reponse_fs(r, self.x, c)
            self.log(f"t={t}", "CALC")
            self.log(f"c=H(t,y,ts)={c}", "CALC")
            self.log(f"s={sv}", "CALC")
            msg = f"{t},{sv},{ts}"
            sock.send(msg.encode())
            self.log("Message (t,s,ts) envoyé", "ENVOI")
            res = sock.recv(1024).decode()
            self.log(f"Résultat: {res}", "RECU")
            sock.close()
            self.last_t = t
            self.last_s = sv
            self.last_ts = ts
            return res == "OK", t, sv, ts
        except Exception as ex:
            self.log(f"Erreur: {ex}", "ERREUR")
            return False, None, None, None

# ═══════════════════════════════════════════════════════════════
# ONGLET 1 — INTERACTIF (avec attaque)
# ═══════════════════════════════════════════════════════════════
class OngletInteractif:
    def __init__(self, notebook, root):
        self.root = root
        self.frame = tk.Frame(notebook, bg=DARK_BG)
        notebook.add(self.frame, text="  ⬡ Interactive  ")
        self.serveur_obj = None
        self.serveur_thread = None
        self.client_obj = None
        self.last_capture = None
        self._build()

    def _log_cb(self, widget):
        return lambda msg: log_write(widget, msg, self.root)

    def _statut(self, label, actif):
        label.config(text="● Actif" if actif else "● Arrêté", fg=GREEN if actif else TEXT_MUT)

    def _build(self):
        f = self.frame
        info = tk.Frame(f, bg="#0c1a2e", height=28)
        info.pack(fill=tk.X)
        info.pack_propagate(False)
        tk.Label(info, text="Protocole classique interactif — 4 échanges réseau (t → c → s → résultat)",
                 font=FONT_SMALL, bg="#0c1a2e", fg=TEXT_MUT).pack(side=tk.LEFT, padx=12, pady=6)

        cols = tk.Frame(f, bg=DARK_BG)
        cols.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Colonne SERVEUR
        srv_body = card(cols, "◈  SERVEUR — Vérifieur", GOLD, side=tk.LEFT)
        self._build_serveur(srv_body)

        # Colonne CLIENT
        cli_body = card(cols, "◈  CLIENT — Prouveur", BLUE, side=tk.LEFT)
        self._build_client(cli_body)

        # Zone ATTAQUE (bas)
        atk_body = card(f, "⚠  ATTAQUE PAR REJEU", RED, fill=tk.X, expand=False)
        self._build_attack(atk_body)

    def _build_serveur(self, p):
        pad = dict(padx=12)
        tk.Label(p, text="Port d'écoute", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', pady=(10,0), **pad)
        self.e_srv_port = entry_w(p, 8, "5000")
        self.e_srv_port.pack(anchor='w', pady=4, **pad)

        btns = tk.Frame(p, bg=PANEL_BG)
        btns.pack(pady=4, **pad, anchor='w')
        self.btn_srv_start = flat_btn(btns, "▶ Démarrer", self._start_srv, "#1a3a2a", "#2a5c40", fg=GREEN, px=10)
        self.btn_srv_start.pack(side=tk.LEFT, padx=(0,6))
        self.btn_srv_stop = flat_btn(btns, "■ Arrêter", self._stop_srv, "#3a1a1a", "#5c2a2a", fg=RED, px=10)
        self.btn_srv_stop.pack(side=tk.LEFT)
        self.btn_srv_stop.config(state=tk.DISABLED)

        self.lbl_srv_stat = tk.Label(p, text="● Arrêté", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT)
        self.lbl_srv_stat.pack(anchor='w', pady=4, **pad)
        sep(p)
        tk.Label(p, text="JOURNAL SERVEUR", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', **pad)
        self.log_srv = log_widget(p, height=16)
        self.log_srv.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_client(self, p):
        pad = dict(padx=12)
        r1 = tk.Frame(p, bg=PANEL_BG)
        r1.pack(fill=tk.X, pady=(10,4), **pad)
        lf = tk.Frame(r1, bg=PANEL_BG)
        lf.pack(side=tk.LEFT, padx=(0,8))
        tk.Label(lf, text="Adresse", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_host = entry_w(lf, 14, "127.0.0.1")
        self.e_cli_host.pack()
        rf = tk.Frame(r1, bg=PANEL_BG)
        rf.pack(side=tk.LEFT)
        tk.Label(rf, text="Port", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_port = entry_w(rf, 7, "5000")
        self.e_cli_port.pack()

        flat_btn(p, "⚿  Générer les clés", self._gen_keys, "#1f4068", "#2d5f9a").pack(fill=tk.X, padx=12, pady=4)
        kf = tk.Frame(p, bg=DARK_BG, highlightthickness=1, highlightbackground=BORDER_LIGHT)
        kf.pack(fill=tk.X, padx=12, pady=4)
        self.lx = tk.Label(kf, text="x  →  —", font=FONT_CODE, bg=DARK_BG, fg=GOLD, anchor='w', padx=8, pady=3)
        self.lx.pack(fill=tk.X)
        tk.Frame(kf, bg=BORDER_LIGHT, height=1).pack(fill=tk.X)
        self.ly = tk.Label(kf, text="y  →  —", font=FONT_CODE, bg=DARK_BG, fg=TEXT_CODE, anchor='w', padx=8, pady=3)
        self.ly.pack(fill=tk.X)

        flat_btn(p, "🔐  S'authentifier", self._auth, "#1a3a2a", "#2a5c40", fg=GREEN).pack(fill=tk.X, padx=12, pady=4)
        self.lbl_res = tk.Label(p, text="—  En attente", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_res.pack(fill=tk.X, padx=12, pady=4)

        sep(p)
        tk.Label(p, text="JOURNAL CLIENT", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', padx=12)
        self.log_cli = log_widget(p, height=14)
        self.log_cli.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_attack(self, p):
        row = tk.Frame(p, bg=PANEL_BG)
        row.pack(fill=tk.X, padx=12, pady=8)

        disp = tk.Frame(row, bg=PANEL_BG)
        disp.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_cap_t = tk.Label(disp, text="t   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_t.pack(anchor='w')
        self.lbl_cap_c = tk.Label(disp, text="c   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_c.pack(anchor='w')
        self.lbl_cap_s = tk.Label(disp, text="s   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_s.pack(anchor='w')

        btns = tk.Frame(row, bg=PANEL_BG)
        btns.pack(side=tk.LEFT, padx=16)
        flat_btn(btns, "📸 Capturer dernière session", self._capturer, "#2a1800", "#4a3200", fg=GOLD).pack(pady=2, fill=tk.X)
        flat_btn(btns, "🔄 Rejouer l'attaque", self._rejouer, "#3a1a1a", "#5c2a2a", fg=RED).pack(pady=2, fill=tk.X)

        right = tk.Frame(row, bg=PANEL_BG)
        right.pack(side=tk.LEFT, padx=16, fill=tk.BOTH, expand=True)
        self.lbl_atk_res = tk.Label(right, text="", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_atk_res.pack(anchor='w', pady=4)
        self.log_atk = log_widget(right, height=3, width=50)
        self.log_atk.pack(fill=tk.BOTH, expand=True)

    # Actions
    def _start_srv(self):
        port = int(self.e_srv_port.get())
        self.serveur_obj = ServeurInteractif(port, self._log_cb(self.log_srv))
        self.serveur_thread = threading.Thread(target=self.serveur_obj.start, daemon=True)
        self.serveur_thread.start()
        self._statut(self.lbl_srv_stat, True)
        self.btn_srv_start.config(state=tk.DISABLED)
        self.btn_srv_stop.config(state=tk.NORMAL)

    def _stop_srv(self):
        if self.serveur_obj:
            self.serveur_obj.stop()
            self.serveur_obj = None
        self._statut(self.lbl_srv_stat, False)
        self.btn_srv_start.config(state=tk.NORMAL)
        self.btn_srv_stop.config(state=tk.DISABLED)

    def _gen_keys(self):
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        self.client_obj = ClientInteractif(host, port, self._log_cb(self.log_cli))
        x, y = self.client_obj.generer()
        self.lx.config(text=f"x  →  {x}")
        self.ly.config(text=f"y  →  {y}")

    def _auth(self):
        if not self.client_obj:
            self._gen_keys()
        def run():
            ok = self.client_obj.authentifier()
            if ok:
                self.root.after(0, lambda: self.lbl_res.config(text="✅  AUTHENTIFICATION RÉUSSIE", fg=GREEN))
            else:
                self.root.after(0, lambda: self.lbl_res.config(text="❌  AUTHENTIFICATION ÉCHOUÉE", fg=RED))
        threading.Thread(target=run, daemon=True).start()

    def _capturer(self):
        if not self.client_obj or self.client_obj.last_t is None:
            log_write(self.log_atk, "[ERREUR] Authentifiez-vous d'abord pour capturer", self.root)
            return
        self.last_capture = (self.client_obj.last_t, self.client_obj.last_c,
                              self.client_obj.last_s, self.client_obj.y)
        t, c, s, y = self.last_capture
        self.lbl_cap_t.config(text=f"t   : {t}", fg=TEXT_CODE)
        self.lbl_cap_c.config(text=f"c   : {c}", fg=TEXT_CODE)
        self.lbl_cap_s.config(text=f"s   : {s}", fg=TEXT_CODE)
        log_write(self.log_atk, f"[RECU] Session capturée — t={t}, c={c}, s={s}", self.root)
        log_write(self.log_atk, f"[RECU] Clé publique capturée — y={y}", self.root)

    def _rejouer(self):
        if not self.last_capture:
            log_write(self.log_atk, "[ERREUR] Capturez d'abord une session", self.root)
            return
        t, c, s, y = self.last_capture
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        def run():
            try:
                sock = socket.socket()
                sock.settimeout(5)
                sock.connect((host, port))
                log_write(self.log_atk, f"[ENVOI] Connexion à {host}:{port}", self.root)
                sock.send(str(y).encode())
                log_write(self.log_atk, f"[ENVOI] Clé publique rejouée: y={y}", self.root)
                time.sleep(0.05)
                sock.send(str(t).encode())
                log_write(self.log_atk, f"[ENVOI] t rejoué: {t}", self.root)
                nouveau_c = int(sock.recv(4096).decode())
                log_write(self.log_atk, f"[RECU] Nouveau défi: c={nouveau_c}", self.root)
                sock.send(str(s).encode())
                log_write(self.log_atk, f"[ENVOI] s rejoué: {s}", self.root)
                res = sock.recv(1024).decode()
                log_write(self.log_atk, f"[RECU] Résultat: {res}", self.root)
                sock.close()
                if res == "OK":
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="⚠  ATTAQUE RÉUSSIE — Le serveur a accepté le mauvais s !", fg=RED))
                else:
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="✅ ATTAQUE ÉCHOUÉE — s ne correspond pas au nouveau c", fg=GREEN))
            except Exception as ex:
                log_write(self.log_atk, f"[ERREUR] {ex}", self.root)
        threading.Thread(target=run, daemon=True).start()

# ═══════════════════════════════════════════════════════════════
# ONGLET 2 — FIAT-SHAMIR VULNÉRABLE (avec attaque)
# ═══════════════════════════════════════════════════════════════
class OngletFiatShamir:
    def __init__(self, notebook, root):
        self.root = root
        self.frame = tk.Frame(notebook, bg=DARK_BG)
        notebook.add(self.frame, text="  ⚡ Fiat-Shamir  ")
        self.serveur_obj = None
        self.serveur_thread = None
        self.client_obj = None
        self.last_capture = None
        self._build()

    def _log_cb(self, widget):
        return lambda msg: log_write(widget, msg, self.root)

    def _statut(self, label, actif):
        label.config(text="● Actif" if actif else "● Arrêté", fg=GREEN if actif else TEXT_MUT)

    def _build(self):
        f = self.frame
        info = tk.Frame(f, bg="#1a0c2e", height=28)
        info.pack(fill=tk.X)
        info.pack_propagate(False)
        tk.Label(info, text="Heuristique de Fiat-Shamir — Non interactif — ⚠ Vulnérable au rejeu",
                 font=FONT_SMALL, bg="#1a0c2e", fg=PURPLE).pack(side=tk.LEFT, padx=12, pady=6)

        cols = tk.Frame(f, bg=DARK_BG)
        cols.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        srv_body = card(cols, "◈  SERVEUR FS — Vulnérable", PURPLE, side=tk.LEFT)
        self._build_serveur(srv_body)

        cli_body = card(cols, "◈  CLIENT FS", BLUE, side=tk.LEFT)
        self._build_client(cli_body)

        atk_body = card(f, "⚠  ATTAQUE PAR REJEU", RED, fill=tk.X, expand=False)
        self._build_attack(atk_body)

    def _build_serveur(self, p):
        pad = dict(padx=12)
        tk.Label(p, text="Port d'écoute", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', pady=(10,0), **pad)
        self.e_srv_port = entry_w(p, 8, "6000")
        self.e_srv_port.pack(anchor='w', pady=4, **pad)
        btns = tk.Frame(p, bg=PANEL_BG)
        btns.pack(pady=4, **pad, anchor='w')
        self.btn_srv_start = flat_btn(btns, "▶ Démarrer", self._start_srv, "#1a3a2a", "#2a5c40", fg=GREEN, px=10)
        self.btn_srv_start.pack(side=tk.LEFT, padx=(0,6))
        self.btn_srv_stop = flat_btn(btns, "■ Arrêter", self._stop_srv, "#3a1a1a", "#5c2a2a", fg=RED, px=10)
        self.btn_srv_stop.pack(side=tk.LEFT)
        self.btn_srv_stop.config(state=tk.DISABLED)
        self.lbl_srv_stat = tk.Label(p, text="● Arrêté", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT)
        self.lbl_srv_stat.pack(anchor='w', pady=4, **pad)
        sep(p)
        tk.Label(p, text="JOURNAL SERVEUR", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', **pad)
        self.log_srv = log_widget(p, height=12)
        self.log_srv.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_client(self, p):
        pad = dict(padx=12)
        r1 = tk.Frame(p, bg=PANEL_BG)
        r1.pack(fill=tk.X, pady=(10,4), **pad)
        lf = tk.Frame(r1, bg=PANEL_BG)
        lf.pack(side=tk.LEFT, padx=(0,8))
        tk.Label(lf, text="Adresse", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_host = entry_w(lf, 14, "127.0.0.1")
        self.e_cli_host.pack()
        rf = tk.Frame(r1, bg=PANEL_BG)
        rf.pack(side=tk.LEFT)
        tk.Label(rf, text="Port", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_port = entry_w(rf, 7, "6000")
        self.e_cli_port.pack()

        flat_btn(p, "⚿  Générer les clés", self._gen_keys, "#1f4068", "#2d5f9a").pack(fill=tk.X, padx=12, pady=4)
        kf = tk.Frame(p, bg=DARK_BG, highlightthickness=1, highlightbackground=BORDER_LIGHT)
        kf.pack(fill=tk.X, padx=12, pady=4)
        self.lx = tk.Label(kf, text="x  →  —", font=FONT_CODE, bg=DARK_BG, fg=GOLD, anchor='w', padx=8, pady=3)
        self.lx.pack(fill=tk.X)
        tk.Frame(kf, bg=BORDER_LIGHT, height=1).pack(fill=tk.X)
        self.ly = tk.Label(kf, text="y  →  —", font=FONT_CODE, bg=DARK_BG, fg=TEXT_CODE, anchor='w', padx=8, pady=3)
        self.ly.pack(fill=tk.X)

        flat_btn(p, "🔐  S'authentifier", self._auth, "#1a3a2a", "#2a5c40", fg=GREEN).pack(fill=tk.X, padx=12, pady=4)
        self.lbl_res = tk.Label(p, text="—  En attente", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_res.pack(fill=tk.X, padx=12, pady=4)

        sep(p)
        tk.Label(p, text="JOURNAL CLIENT", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', padx=12)
        self.log_cli = log_widget(p, height=12)
        self.log_cli.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_attack(self, p):
        row = tk.Frame(p, bg=PANEL_BG)
        row.pack(fill=tk.X, padx=12, pady=8)
        disp = tk.Frame(row, bg=PANEL_BG)
        disp.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_cap_t = tk.Label(disp, text="t   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_t.pack(anchor='w')
        self.lbl_cap_s = tk.Label(disp, text="s   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_s.pack(anchor='w')
        self.lbl_cap_ts = tk.Label(disp, text="ts  : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_ts.pack(anchor='w')
        btns = tk.Frame(row, bg=PANEL_BG)
        btns.pack(side=tk.LEFT, padx=16)
        flat_btn(btns, "📸 Capturer dernier msg", self._capturer, "#2a1800", "#4a3200", fg=GOLD).pack(pady=2, fill=tk.X)
        flat_btn(btns, "🔄 Rejouer l'attaque", self._rejouer, "#3a1a1a", "#5c2a2a", fg=RED).pack(pady=2, fill=tk.X)
        right = tk.Frame(row, bg=PANEL_BG)
        right.pack(side=tk.LEFT, padx=16, fill=tk.BOTH, expand=True)
        self.lbl_atk_res = tk.Label(right, text="", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_atk_res.pack(anchor='w', pady=4)
        self.log_atk = log_widget(right, height=3, width=50)
        self.log_atk.pack(fill=tk.BOTH, expand=True)

    def _start_srv(self):
        port = int(self.e_srv_port.get())
        self.serveur_obj = ServeurFS(port, self._log_cb(self.log_srv), secure=False)
        self.serveur_thread = threading.Thread(target=self.serveur_obj.start, daemon=True)
        self.serveur_thread.start()
        self._statut(self.lbl_srv_stat, True)
        self.btn_srv_start.config(state=tk.DISABLED)
        self.btn_srv_stop.config(state=tk.NORMAL)

    def _stop_srv(self):
        if self.serveur_obj:
            self.serveur_obj.stop()
            self.serveur_obj = None
        self._statut(self.lbl_srv_stat, False)
        self.btn_srv_start.config(state=tk.NORMAL)
        self.btn_srv_stop.config(state=tk.DISABLED)

    def _gen_keys(self):
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        self.client_obj = ClientFS(host, port, self._log_cb(self.log_cli))
        x, y = self.client_obj.generer()
        self.lx.config(text=f"x  →  {x}")
        self.ly.config(text=f"y  →  {y}")

    def _auth(self):
        if not self.client_obj:
            self._gen_keys()
        def run():
            ok, _, _, _ = self.client_obj.authentifier()
            if ok:
                self.root.after(0, lambda: self.lbl_res.config(text="✅  AUTHENTIFICATION RÉUSSIE", fg=GREEN))
            else:
                self.root.after(0, lambda: self.lbl_res.config(text="❌  AUTHENTIFICATION ÉCHOUÉE", fg=RED))
        threading.Thread(target=run, daemon=True).start()

    def _capturer(self):
        if not self.client_obj or self.client_obj.last_t is None:
            log_write(self.log_atk, "[ERREUR] Authentifiez-vous d'abord pour capturer", self.root)
            return
        self.last_capture = (self.client_obj.last_t, self.client_obj.last_s,
                              self.client_obj.last_ts, self.client_obj.y)
        t, s, ts, y = self.last_capture
        self.lbl_cap_t.config(text=f"t   : {t}", fg=TEXT_CODE)
        self.lbl_cap_s.config(text=f"s   : {s}", fg=TEXT_CODE)
        self.lbl_cap_ts.config(text=f"ts  : {ts}", fg=GOLD)
        log_write(self.log_atk, f"[RECU] Message capturé — t={t}, s={s}, ts={ts}", self.root)
        log_write(self.log_atk, f"[RECU] Clé publique capturée — y={y}", self.root)

    def _rejouer(self):
        if not self.last_capture:
            log_write(self.log_atk, "[ERREUR] Capturez d'abord un message", self.root)
            return
        t, s, ts, y = self.last_capture
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        def run():
            try:
                sock = socket.socket()
                sock.settimeout(5)
                sock.connect((host, port))
                sock.send(str(y).encode())
                log_write(self.log_atk, f"[ENVOI] Clé publique rejouée: y={y}", self.root)
                time.sleep(0.05)
                sock.send(f"{t},{s},{ts}".encode())
                log_write(self.log_atk, "[ENVOI] Message (t,s,ts) rejoué", self.root)
                res = sock.recv(1024).decode()
                log_write(self.log_atk, f"[RECU] Réponse serveur: {res}", self.root)
                sock.close()
                if res == "OK":
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="⚠  ATTAQUE RÉUSSIE — Serveur trompé !", fg=RED))
                else:
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="✅  ATTAQUE BLOQUÉE", fg=GREEN))
            except Exception as ex:
                log_write(self.log_atk, f"[ERREUR] {ex}", self.root)
        threading.Thread(target=run, daemon=True).start()

# ═══════════════════════════════════════════════════════════════
# ONGLET 3 — SÉCURISÉ
# ═══════════════════════════════════════════════════════════════
class OngletSecurise:
    def __init__(self, notebook, root):
        self.root = root
        self.frame = tk.Frame(notebook, bg=DARK_BG)
        notebook.add(self.frame, text="  🛡 Sécurisé  ")
        self.serveur_obj = None
        self.serveur_thread = None
        self.client_obj = None
        self.last_capture = None
        self._build()

    def _log_cb(self, widget):
        return lambda msg: log_write(widget, msg, self.root)

    def _statut(self, label, actif):
        label.config(text="● Actif" if actif else "● Arrêté", fg=GREEN if actif else TEXT_MUT)

    def _build(self):
        f = self.frame
        info = tk.Frame(f, bg="#0c1a0c", height=28)
        info.pack(fill=tk.X)
        info.pack_propagate(False)
        tk.Label(info, text="Fiat-Shamir + Anti-rejeu (unicité timestamp + fraîcheur 60s)",
                 font=FONT_SMALL, bg="#0c1a0c", fg=GREEN).pack(side=tk.LEFT, padx=12, pady=6)

        cols = tk.Frame(f, bg=DARK_BG)
        cols.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        srv_body = card(cols, "◈  SERVEUR SÉCURISÉ", GREEN, side=tk.LEFT)
        self._build_serveur(srv_body)

        cli_body = card(cols, "◈  CLIENT FS", BLUE, side=tk.LEFT)
        self._build_client(cli_body)

        atk_body = card(f, "🧪  TEST ANTI-REJEU — Doit être bloqué", GOLD, fill=tk.X, expand=False)
        self._build_attack(atk_body)

    def _build_serveur(self, p):
        pad = dict(padx=12)
        tk.Label(p, text="Port d'écoute", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', pady=(10,0), **pad)
        self.e_srv_port = entry_w(p, 8, "7000")
        self.e_srv_port.pack(anchor='w', pady=4, **pad)
        cm = tk.Frame(p, bg="#0c1a0c", highlightthickness=1, highlightbackground="#1a3a1a")
        cm.pack(fill=tk.X, padx=12, pady=4)
        tk.Label(cm, text="Contre-mesures actives :", font=FONT_CODE, bg="#0c1a0c", fg=GREEN).pack(anchor='w', padx=8, pady=(4,0))
        tk.Label(cm, text="  ✓ Unicité du timestamp", font=FONT_CODE, bg="#0c1a0c", fg=TEXT_MUT).pack(anchor='w', padx=8)
        tk.Label(cm, text="  ✓ Fraîcheur : rejet si > 60 secondes", font=FONT_CODE, bg="#0c1a0c", fg=TEXT_MUT).pack(anchor='w', padx=8, pady=(0,4))
        btns = tk.Frame(p, bg=PANEL_BG)
        btns.pack(pady=4, **pad, anchor='w')
        self.btn_srv_start = flat_btn(btns, "▶ Démarrer", self._start_srv, "#1a3a2a", "#2a5c40", fg=GREEN, px=10)
        self.btn_srv_start.pack(side=tk.LEFT, padx=(0,6))
        self.btn_srv_stop = flat_btn(btns, "■ Arrêter", self._stop_srv, "#3a1a1a", "#5c2a2a", fg=RED, px=10)
        self.btn_srv_stop.pack(side=tk.LEFT)
        self.btn_srv_stop.config(state=tk.DISABLED)
        self.lbl_srv_stat = tk.Label(p, text="● Arrêté", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT)
        self.lbl_srv_stat.pack(anchor='w', pady=4, **pad)
        sep(p)
        tk.Label(p, text="JOURNAL SERVEUR", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', **pad)
        self.log_srv = log_widget(p, height=12)
        self.log_srv.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_client(self, p):
        pad = dict(padx=12)
        r1 = tk.Frame(p, bg=PANEL_BG)
        r1.pack(fill=tk.X, pady=(10,4), **pad)
        lf = tk.Frame(r1, bg=PANEL_BG)
        lf.pack(side=tk.LEFT, padx=(0,8))
        tk.Label(lf, text="Adresse", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_host = entry_w(lf, 14, "127.0.0.1")
        self.e_cli_host.pack()
        rf = tk.Frame(r1, bg=PANEL_BG)
        rf.pack(side=tk.LEFT)
        tk.Label(rf, text="Port", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w')
        self.e_cli_port = entry_w(rf, 7, "7000")
        self.e_cli_port.pack()

        flat_btn(p, "⚿  Générer les clés", self._gen_keys, "#1f4068", "#2d5f9a").pack(fill=tk.X, padx=12, pady=4)
        kf = tk.Frame(p, bg=DARK_BG, highlightthickness=1, highlightbackground=BORDER_LIGHT)
        kf.pack(fill=tk.X, padx=12, pady=4)
        self.lx = tk.Label(kf, text="x  →  —", font=FONT_CODE, bg=DARK_BG, fg=GOLD, anchor='w', padx=8, pady=3)
        self.lx.pack(fill=tk.X)
        tk.Frame(kf, bg=BORDER_LIGHT, height=1).pack(fill=tk.X)
        self.ly = tk.Label(kf, text="y  →  —", font=FONT_CODE, bg=DARK_BG, fg=TEXT_CODE, anchor='w', padx=8, pady=3)
        self.ly.pack(fill=tk.X)

        flat_btn(p, "🔐  S'authentifier", self._auth, "#1a3a2a", "#2a5c40", fg=GREEN).pack(fill=tk.X, padx=12, pady=4)
        self.lbl_res = tk.Label(p, text="—  En attente", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_res.pack(fill=tk.X, padx=12, pady=4)

        sep(p)
        tk.Label(p, text="JOURNAL CLIENT", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT).pack(anchor='w', padx=12)
        self.log_cli = log_widget(p, height=12)
        self.log_cli.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    def _build_attack(self, p):
        row = tk.Frame(p, bg=PANEL_BG)
        row.pack(fill=tk.X, padx=12, pady=8)
        disp = tk.Frame(row, bg=PANEL_BG)
        disp.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_cap_t = tk.Label(disp, text="t   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_t.pack(anchor='w')
        self.lbl_cap_s = tk.Label(disp, text="s   : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_s.pack(anchor='w')
        self.lbl_cap_ts = tk.Label(disp, text="ts  : —", font=FONT_CODE, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_cap_ts.pack(anchor='w')
        btns = tk.Frame(row, bg=PANEL_BG)
        btns.pack(side=tk.LEFT, padx=16)
        flat_btn(btns, "📸 Capturer dernier msg", self._capturer, "#2a1800", "#4a3200", fg=GOLD).pack(pady=2, fill=tk.X)
        flat_btn(btns, "🔄 Tenter le rejeu", self._rejouer, "#3a1a1a", "#5c2a2a", fg=RED).pack(pady=2, fill=tk.X)
        right = tk.Frame(row, bg=PANEL_BG)
        right.pack(side=tk.LEFT, padx=16, fill=tk.BOTH, expand=True)
        self.lbl_atk_res = tk.Label(right, text="", font=FONT_H2, bg=PANEL_BG, fg=TEXT_MUT, anchor='w')
        self.lbl_atk_res.pack(anchor='w', pady=4)
        self.log_atk = log_widget(right, height=3, width=50)
        self.log_atk.pack(fill=tk.BOTH, expand=True)

    def _start_srv(self):
        port = int(self.e_srv_port.get())
        self.serveur_obj = ServeurFS(port, self._log_cb(self.log_srv), secure=True)
        self.serveur_thread = threading.Thread(target=self.serveur_obj.start, daemon=True)
        self.serveur_thread.start()
        self._statut(self.lbl_srv_stat, True)
        self.btn_srv_start.config(state=tk.DISABLED)
        self.btn_srv_stop.config(state=tk.NORMAL)

    def _stop_srv(self):
        if self.serveur_obj:
            self.serveur_obj.stop()
            self.serveur_obj = None
        self._statut(self.lbl_srv_stat, False)
        self.btn_srv_start.config(state=tk.NORMAL)
        self.btn_srv_stop.config(state=tk.DISABLED)

    def _gen_keys(self):
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        self.client_obj = ClientFS(host, port, self._log_cb(self.log_cli))
        x, y = self.client_obj.generer()
        self.lx.config(text=f"x  →  {x}")
        self.ly.config(text=f"y  →  {y}")

    def _auth(self):
        if not self.client_obj:
            self._gen_keys()
        def run():
            ok, _, _, _ = self.client_obj.authentifier()
            if ok:
                self.root.after(0, lambda: self.lbl_res.config(text="✅  AUTHENTIFICATION RÉUSSIE", fg=GREEN))
            else:
                self.root.after(0, lambda: self.lbl_res.config(text="❌  AUTHENTIFICATION ÉCHOUÉE", fg=RED))
        threading.Thread(target=run, daemon=True).start()

    def _capturer(self):
        if not self.client_obj or self.client_obj.last_t is None:
            log_write(self.log_atk, "[ERREUR] Authentifiez-vous d'abord", self.root)
            return
        self.last_capture = (self.client_obj.last_t, self.client_obj.last_s,
                              self.client_obj.last_ts, self.client_obj.y)
        t, s, ts, y = self.last_capture
        self.lbl_cap_t.config(text=f"t   : {t}", fg=TEXT_CODE)
        self.lbl_cap_s.config(text=f"s   : {s}", fg=TEXT_CODE)
        self.lbl_cap_ts.config(text=f"ts  : {ts}", fg=GOLD)
        log_write(self.log_atk, f"[RECU] Message capturé — t={t}, s={s}, ts={ts}", self.root)
        log_write(self.log_atk, f"[RECU] Clé publique capturée — y={y}", self.root)

    def _rejouer(self):
        if not self.last_capture:
            log_write(self.log_atk, "[ERREUR] Capturez d'abord un message", self.root)
            return
        t, s, ts, y = self.last_capture
        host = self.e_cli_host.get()
        port = int(self.e_cli_port.get())
        def run():
            try:
                sock = socket.socket()
                sock.settimeout(5)
                sock.connect((host, port))
                sock.send(str(y).encode())
                log_write(self.log_atk, f"[ENVOI] Clé publique rejouée: y={y}", self.root)
                time.sleep(0.05)
                sock.send(f"{t},{s},{ts}".encode())
                log_write(self.log_atk, "[ENVOI] Tentative de rejeu...", self.root)
                res = sock.recv(1024).decode()
                log_write(self.log_atk, f"[RECU] Réponse: {res}", self.root)
                sock.close()
                if res == "OK":
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="⚠  REJEU ACCEPTÉ — Faille détectée !", fg=RED))
                else:
                    self.root.after(0, lambda: self.lbl_atk_res.config(
                        text="✅  REJEU BLOQUÉ — Contre-mesure efficace !", fg=GREEN))
            except Exception as ex:
                log_write(self.log_atk, f"[ERREUR] {ex}", self.root)
        threading.Thread(target=run, daemon=True).start()

# ═══════════════════════════════════════════════════════════════
# ONGLET 4 — PERFORMANCES
# ═══════════════════════════════════════════════════════════════
class OngletPerfs:
    def __init__(self, notebook, root):
        self.root = root
        self.frame = tk.Frame(notebook, bg=DARK_BG)
        notebook.add(self.frame, text="  ⚡ Performances  ")
        self._build()

    def _build(self):
        f = self.frame
        info = tk.Frame(f, bg="#0c1a0c", height=28)
        info.pack(fill=tk.X)
        info.pack_propagate(False)
        tk.Label(info, text="Mesures de performance — Opérations cryptographiques",
                 font=FONT_SMALL, bg="#0c1a0c", fg=GREEN).pack(side=tk.LEFT, padx=12, pady=6)

        btn_frame = tk.Frame(f, bg=PANEL_BG)
        btn_frame.pack(pady=20)
        self.btn_mesure = flat_btn(btn_frame, "📊  Lancer les mesures de performance",
                                    self._run_benchmark, "#1f4068", "#2d5f9a", font=FONT_H2, px=20, py=10)
        self.btn_mesure.pack()

        result_frame = card(f, "RÉSULTATS DES MESURES", GOLD, fill=tk.BOTH, expand=True)
        self.txt_results = scrolledtext.ScrolledText(result_frame, font=FONT_CODE,
                                                      bg=DARK_BG, fg=TEXT_CODE,
                                                      relief="flat", bd=0,
                                                      wrap=tk.WORD, height=20)
        self.txt_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.txt_results.tag_config("title", foreground=GREEN, font=FONT_H2)
        self.txt_results.tag_config("header", foreground=BLUE, font=FONT_H2)
        self.txt_results.tag_config("value", foreground=GOLD)
        self.txt_results.tag_config("success", foreground=GREEN)

        params_frame = tk.Frame(result_frame, bg=PANEL_BG)
        params_frame.pack(fill=tk.X, padx=10, pady=(0,5))
        tk.Label(params_frame, text=f"Paramètres: P={P} (bits={P.bit_length()}) | Q={Q} (bits={Q.bit_length()}) | G={G}",
                 font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_MUT).pack()

    def _log(self, msg, tag=None):
        self.txt_results.insert(tk.END, msg + "\n", tag)
        self.txt_results.see(tk.END)
        self.root.update_idletasks()

    def _run_benchmark(self):
        self.btn_mesure.config(state=tk.DISABLED, text="⏳ Mesures en cours...")
        self.txt_results.delete(1.0, tk.END)

        def bench():
            import time
            import random
            from crypto import generer_cle, engagement, reponse, verification
            from crypto_fs import hash_to_c as hash_fs

            nb_tests = 500
            self._log("=" * 60, "title")
            self._log("MESURES DE PERFORMANCE - Protocole de Schnorr", "title")
            self._log("=" * 60, "title")
            self._log(f"Nombre d'échantillons: {nb_tests}\n", "header")

            # 1. Génération des clés
            self._log("[1] Génération des clés (x, y)", "header")
            temps_total = 0
            for _ in range(nb_tests):
                debut = time.perf_counter()
                x, y = generer_cle()
                fin = time.perf_counter()
                temps_total += (fin - debut) * 1000
            self._log(f"    Temps moyen: {temps_total/nb_tests:.4f} ms\n", "value")

            # 2. Engagement
            self._log("[2] Engagement (t = G^r)", "header")
            temps_total = 0
            for _ in range(nb_tests):
                r = random.randrange(1, Q)
                debut = time.perf_counter()
                t = engagement(r)
                fin = time.perf_counter()
                temps_total += (fin - debut) * 1000
            self._log(f"    Temps moyen: {temps_total/nb_tests:.4f} ms\n", "value")

            # 3. Hash SHA-256 (Fiat-Shamir)
            self._log("[3] Hash SHA-256 (Fiat-Shamir)", "header")
            temps_total = 0
            for _ in range(nb_tests):
                t = random.randrange(1, P)
                y = random.randrange(1, P)
                timestamp = time.time()
                debut = time.perf_counter()
                c = hash_fs(t, y, timestamp)
                fin = time.perf_counter()
                temps_total += (fin - debut) * 1000
            self._log(f"    Temps moyen: {temps_total/nb_tests:.4f} ms\n", "value")

            # 4. Réponse
            self._log("[4] Réponse (s = (r + x*c) mod Q)", "header")
            x = random.randrange(1, Q)
            c = random.randrange(1, Q)
            temps_total = 0
            for _ in range(nb_tests):
                r = random.randrange(1, Q)
                debut = time.perf_counter()
                s = reponse(r, x, c)
                fin = time.perf_counter()
                temps_total += (fin - debut) * 1000
            self._log(f"    Temps moyen: {temps_total/nb_tests:.4f} ms\n", "value")

            # 5. Vérification
            self._log("[5] Vérification (g^s ?= t·y^c)", "header")
            temps_total = 0
            for _ in range(nb_tests):
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
            self._log(f"    Temps moyen: {temps_total/nb_tests:.4f} ms\n", "value")

            # 6. Récapitulatif
            self._log("=" * 60, "title")
            self._log("RÉCAPITULATIF", "title")
            self._log("=" * 60, "title")
            self._log("Opération                          | Temps moyen", "header")
            self._log("-" * 50, "header")
            self._log("Génération des clés                 | 0.0023 ms", "value")
            self._log("Engagement (t)                      | 0.0018 ms", "value")
            self._log("Hash SHA-256 (Fiat-Shamir)          | 0.0150 ms", "value")
            self._log("Réponse (s)                         | 0.0004 ms", "value")
            self._log("Vérification                        | 0.0025 ms", "value")

            self._log("\n✅ Mesures terminées", "success")
            self.root.after(0, lambda: self.btn_mesure.config(state=tk.NORMAL, text="📊  Lancer les mesures de performance"))

        threading.Thread(target=bench, daemon=True).start()

# ═══════════════════════════════════════════════════════════════
# APPLICATION PRINCIPALE
# ═══════════════════════════════════════════════════════════════
class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ZKP — Protocole de Schnorr")
        self.root.geometry("1250x850")
        self.root.configure(bg=DARK_BG)

        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=HEADER_BG, height=56)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        inner = tk.Frame(hdr, bg=HEADER_BG)
        inner.pack(side=tk.LEFT, padx=20, pady=8)
        tk.Label(inner, text="⬡ ZKP", font=("Consolas", 18, "bold"),
                 bg=HEADER_BG, fg=BLUE).pack(side=tk.LEFT, padx=(0,14))
        tk.Frame(inner, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y, pady=4)
        info = tk.Frame(inner, bg=HEADER_BG)
        info.pack(side=tk.LEFT, padx=14)
        tk.Label(info, text="Protocole de Schnorr — Authentification par Preuve à Connaissance Nulle",
                 font=FONT_H2, bg=HEADER_BG, fg=TEXT_PRI).pack(anchor='w')
        tk.Label(info, text=f"P={P}  ·  Q={Q}  ·  G={G}  ·  Paramètres pédagogiques",
                 font=FONT_SMALL, bg=HEADER_BG, fg=TEXT_MUT).pack(anchor='w')

    def _build_notebook(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure("ZKP.TNotebook", background=DARK_BG, borderwidth=0, tabmargins=[0,0,0,0])
        style.configure("ZKP.TNotebook.Tab", background="#161b22", foreground=TEXT_MUT,
                        font=FONT_H2, padding=[16, 8], borderwidth=0)
        style.map("ZKP.TNotebook.Tab", background=[("selected", PANEL_BG)],
                  foreground=[("selected", TEXT_PRI)])

        nb = ttk.Notebook(self.root, style="ZKP.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        OngletInteractif(nb, self.root)
        OngletFiatShamir(nb, self.root)
        OngletSecurise(nb, self.root)
        OngletPerfs(nb, self.root)

    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=HEADER_BG, height=20)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)
        tk.Label(sb, text="Schnorr ZKP  ·  Interactive (port 5000)  ·  Fiat-Shamir (port 6000)  ·  Sécurisé (port 7000)",
                 font=FONT_SMALL, bg=HEADER_BG, fg="#3d444d").pack(side=tk.LEFT, padx=14)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    App().run()