#!/usr/bin/env python3
# ============================================================================
# cryptohunt.py - resolution assistee de challenges crypto CTF
# By 12ak_H4ck
#
# [!] Usage LEGAL uniquement : CTF / labs / cibles explicitement autorisees.
#
# Ce que cet outil fait VRAIMENT :
#   - Decode en cascade tout encodage reversible (base64/64url/32/16/85/58/45/62,
#     hex, binaire, URL, morse, decimal ASCII, entites HTML, echappements
#     unicode, NATO, a1z26, bacon, rot13/47, atbash, gzip/zlib/bz2).
#   - ENCODE aussi (mode -e) : applique une ou plusieurs methodes en chaine
#     (ex: -e base64,hex). Voir --list.
#   - Casse les chiffrements CLASSIQUES : Cesar, Affine, Rail fence, XOR (simple/
#     repete/crib), Vigenere (chi-carre + dico), SUBSTITUTION monoalphabetique
#     (hill-climbing + n-grammes) - avec choix du meilleur candidat par score et
#     filtre anti-faux-flag (fini les 'pwn{rq:tyx|}' coincidants).
#   - JWT : decode header/payload, detecte alg:none, bruteforce le secret HS256.
#   - Identifie le type d'encodage (-I, facon Magic) et le type de hash (hashcat).
#   - RSA : petit e sans padding, Fermat, Pollard p-1 & rho (offline), common
#     modulus, Wiener, Hastad broadcast, multi-prime, d/phi fournis, FactorDB.
#
# Ce que cet outil NE fait PAS et ne pretend PAS faire :
#   - Casser un chiffrement moderne correctement implemente (AES/RSA fort).
#     Aucun outil au monde ne le fait sans la cle -> garantie mathematique,
#     pas une limite de cet outil. Dans ce cas, l'outil te le dit clairement
#     au lieu d'essayer indefiniment.
# ============================================================================

import argparse
import base64
import binascii
import itertools
import json
import math
import os
import re
import string
import sys
import time
import urllib.request
import urllib.error
from collections import Counter

# ----------------------------------------------------------------------
# Couleurs / affichage
# ----------------------------------------------------------------------
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; GR = "\033[90m"; BD = "\033[1m"; X = "\033[0m"

def out(s=""):
    print(s)

BANNER = f"""{C.CY}{C.BD}
   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║
  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
{C.X}     cascade de decodage/cassage assistee - CTF crypto
     By 12ak_H4ck
{C.GR}     [!] Usage LEGAL uniquement : CTF / labs / cibles explicitement autorisees.{C.X}
"""

# ----------------------------------------------------------------------
# Detection de flag - condition d'arret universelle
# ----------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(
    r"(?:flag|ctf|htb|thm|pico(?:ctf)?|hackthebox|tryhackme|key|pwn)\{[^{}]{3,200}\}",
    re.I
)

def intro():
    """Affiche le banner de facon animee (ligne par ligne + spinner)."""
    try:
        tty = sys.stdout.isatty()
    except Exception:
        tty = False
    if not tty:
        out(BANNER)
        return
    for ln in BANNER.split("\n"):
        out(ln)
        try:
            time.sleep(0.035)
        except Exception:
            pass
    try:
        for _ in range(2):
            for ch in "|/-\\":
                sys.stdout.write(f"\r     {C.Y}initialisation {ch}{C.X}")
                sys.stdout.flush()
                time.sleep(0.03)
        sys.stdout.write("\r" + " " * 40 + "\r")
    except Exception:
        pass

def find_flag(text, pattern):
    if not text:
        return None
    m = pattern.search(text)
    return m.group(0) if m else None

def _clean_flag(f):
    """Un VRAI flag a un contenu propre (alphanumerique + _ - . !). Un match
    coincidant sur un mauvais decalage/cle contient des symboles bizarres
    (rq:tyx| ...) -> permet de rejeter les faux positifs des bruteforces."""
    if not f or '{' not in f:
        return False
    inside = f[f.find('{') + 1:f.rfind('}')]
    if not inside:
        return False
    good = sum(1 for c in inside if c.isalnum() or c in "_-.! ")
    return good / len(inside) >= 0.8

# ----------------------------------------------------------------------
# Scoring frequentiel (anglais) - sert a Cesar / XOR / Vigenere
# ----------------------------------------------------------------------
_ENG_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
    'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4,
    'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0,
    'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.1, 'z': 0.07
}

_WEIRD_CHARS = set('\\^`~<>|@#$%&*+=[]')

def english_score(s):
    """Plus le score est haut, plus s ressemble a du texte anglais/latin
    valide. Combine frequence des lettres + ratio d'imprimables + presence
    d'espaces + penalite forte pour les caracteres rares en texte reel
    (\\ ^ [ ] etc.) qui trahissent un mauvais candidat meme quand la seule
    frequence des lettres presentes semblait correcte."""
    if not s:
        return -1e9
    printable = sum(1 for c in s if c in string.printable)
    if len(s) == 0:
        return -1e9
    printable_ratio = printable / len(s)
    if printable_ratio < 0.85:
        return -1e9  # quasi certainement pas du texte -> elimine direct
    weird = sum(1 for c in s if c in _WEIRD_CHARS or (ord(c) < 32 and c not in '\t\n'))
    weird_ratio = weird / len(s)
    letters = [c.lower() for c in s if c.isalpha()]
    letter_ratio = len(letters) / len(s)
    if not letters:
        # Un candidat SANS AUCUNE lettre (que chiffres/ponctuation) n'est
        # quasiment jamais le bon flag/texte clair -> forte penalite, pas
        # un score neutre. Bug reel constate : ce cas scorait parfois
        # plus haut qu'un vrai candidat en lettres scrambled.
        return -50.0 + printable_ratio * 2
    freq = Counter(letters)
    n = len(letters)
    score = 0.0
    # IMPORTANT : on balaie les 26 lettres de l'alphabet, pas seulement
    # celles presentes dans le candidat. Sinon l'ABSENCE de lettres tres
    # frequentes (e, t, a...) n'est jamais penalisee, ce qui biaise le
    # score et fait choisir un mauvais decalage/cle.
    for ch in string.ascii_lowercase:
        expected = _ENG_FREQ.get(ch, 0.02) / 100.0
        observed = freq.get(ch, 0) / n
        score -= abs(expected - observed)
    space_bonus = 2.0 if ' ' in s else 0.0
    # 'score' accumule deja -somme_des_ecarts (negatif = mauvais match).
    # PAS de moins supplementaire ici : score*10 -> proche de 0 pour un bon
    # match, tres negatif pour un mauvais -> polarite correcte. Un ancien
    # '-score*10' inversait tout : le charabia scorait plus haut que du
    # vrai anglais (bug reel constate en testant explicitement les deux).
    return (score * 10 + space_bonus + printable_ratio * 3
            + letter_ratio * 4 - weird_ratio * 25)

# ----------------------------------------------------------------------
# COUCHE 1 - Encodages reversibles (pas de cle) - cascade recursive
# ----------------------------------------------------------------------
def _is_printable_result(b):
    try:
        s = b.decode('utf-8')
    except Exception:
        return None
    ratio = sum(1 for c in s if c in string.printable) / max(len(s), 1)
    return s if ratio > 0.85 else None

def try_base64(s):
    s2 = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]{8,}", s2):
        return None
    try:
        pad = s2 + "=" * (-len(s2.replace('\n', '').replace(' ', '')) % 4)
        raw = base64.b64decode(pad, validate=False)
        return _is_printable_result(raw)
    except Exception:
        return None

def try_base32(s):
    s2 = s.strip().upper()
    if not re.fullmatch(r"[A-Z2-7=\s]{8,}", s2):
        return None
    try:
        raw = base64.b32decode(s2, casefold=True)
        return _is_printable_result(raw)
    except Exception:
        return None

def try_base85(s):
    s2 = s.strip()
    try:
        raw = base64.b85decode(s2)
        return _is_printable_result(raw)
    except Exception:
        return None

def try_hex(s):
    s2 = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s2) < 8 or len(s2) % 2 != 0:
        return None
    try:
        raw = binascii.unhexlify(s2)
        return _is_printable_result(raw)
    except Exception:
        return None

def try_binary(s):
    bits = re.sub(r"[^01]", "", s)
    if len(bits) < 16 or len(bits) % 8 != 0:
        return None
    try:
        raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        return _is_printable_result(raw)
    except Exception:
        return None

def try_url(s):
    # Exige au moins 2 sequences %XX credibles - un seul '%' isole peut
    # etre un octet de ciphertext coincidant (ex: XOR), pas un vrai
    # encodage URL. Evite de corrompre des donnees binaires brutes.
    matches = re.findall(r"%[0-9a-fA-F]{2}", s)
    if len(matches) < 2:
        return None
    try:
        from urllib.parse import unquote
        r = unquote(s)
        return r if r != s else None
    except Exception:
        return None

MORSE_MAP = {
    '.-':'a', '-...':'b', '-.-.':'c', '-..':'d', '.':'e', '..-.':'f',
    '--.':'g', '....':'h', '..':'i', '.---':'j', '-.-':'k', '.-..':'l',
    '--':'m', '-.':'n', '---':'o', '.--.':'p', '--.-':'q', '.-.':'r',
    '...':'s', '-':'t', '..-':'u', '...-':'v', '.--':'w', '-..-':'x',
    '-.--':'y', '--..':'z', '-----':'0', '.----':'1', '..---':'2',
    '...--':'3', '....-':'4', '.....':'5', '-....':'6', '--...':'7',
    '---..':'8', '----.':'9'
}

def try_morse(s):
    if not re.search(r"[.-]{2,}", s):
        return None
    # '/' (ou double espace) = separateur de MOTS -> espace dans la sortie
    s2 = re.sub(r"\s*/\s*|\s{2,}", " / ", s.strip())
    tokens = re.split(r"\s+", s2)
    if not all(re.fullmatch(r"[.-]+", t) for t in tokens if t and t != "/"):
        return None
    out_chars = [' ' if t == "/" else MORSE_MAP.get(t, '?') for t in tokens if t]
    real = [c for c in out_chars if c != ' ']
    if not real or real.count('?') / len(real) > 0.3:
        return None
    return ''.join(out_chars)

def try_rot13(s):
    r = s.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))
    if r == s:
        return None
    # N'accepte que si le resultat ressemble VRAIMENT a du texte (score > 0) ET
    # ameliore la vraisemblance - sinon rot13 se declenche a tort sur du hex/
    # base32/garbage qui contient par hasard des lettres, corrompant la suite.
    if english_score(r) > 0 and english_score(r) > english_score(s) + 1.0:
        return r
    return None

# ----------------------------------------------------------------------
# Encodages/transforms supplementaires (base58, base64url, compression,
# atbash, rot47, a1z26, bacon)
# ----------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b):
    n = int.from_bytes(b, 'big')
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    pad = len(b) - len(b.lstrip(b'\x00'))
    return "1" * pad + (s or "1")

def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    pad = len(s) - len(s.lstrip('1'))
    return b'\x00' * pad + full

def try_base58(s):
    s2 = s.strip()
    if len(s2) < 8 or any(c not in _B58 for c in s2):
        return None
    try:
        return _is_printable_result(b58decode(s2))
    except Exception:
        return None

def try_base64url(s):
    s2 = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9\-_=]{8,}", s2) or ('-' not in s2 and '_' not in s2):
        return None
    try:
        pad = s2 + "=" * (-len(s2.replace('=', '')) % 4)
        return _is_printable_result(base64.urlsafe_b64decode(pad))
    except Exception:
        return None

def try_compress(s):
    """gzip / zlib / bz2 sur les octets bruts (detection par magic bytes)."""
    import gzip, zlib, bz2
    raw = s.encode('latin-1', errors='ignore')
    for magic, fn in ((b"\x1f\x8b", gzip.decompress), (b"BZh", bz2.decompress),
                      (b"\x78\x9c", zlib.decompress), (b"\x78\x01", zlib.decompress),
                      (b"\x78\xda", zlib.decompress)):
        if raw[:len(magic)] == magic:
            try:
                return _is_printable_result(fn(raw))
            except Exception:
                pass
    return None

def atbash(s):
    def m(c):
        if c.islower(): return chr(219 - ord(c))   # a+z = 97+122
        if c.isupper(): return chr(155 - ord(c))   # A+Z = 65+90
        return c
    return ''.join(m(c) for c in s)

def try_atbash(s):
    r = atbash(s)
    # ne se declenche QUE si le resultat ressemble VRAIMENT a du texte (score > 0)
    # -> evite de corrompre du ciphertext/garbage dans la cascade
    if r != s and english_score(r) > 0 and english_score(r) > english_score(s) + 1.0:
        return r
    return None

def rot47(s):
    return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)

def try_rot47(s):
    r = rot47(s)
    if r != s and english_score(r) > 0 and english_score(r) > english_score(s) + 1.0:
        return r
    return None

def try_a1z26(s):
    # "8 5 12 12 15" ou "8-5-12" -> 'hello'. Exige des separateurs (sinon
    # confusion avec du binaire/decimal brut).
    if not re.search(r"[\s\-,._]", s) or not re.fullmatch(r"[\d\s\-,._]+", s.strip()):
        return None
    nums = re.findall(r"\d{1,2}", s)
    if len(nums) < 3 or not all(1 <= int(n) <= 26 for n in nums):
        return None
    return ''.join(chr(96 + int(n)) for n in nums)

_BACON = {}
for _i in range(26):
    _BACON[format(_i, '05b').replace('0', 'A').replace('1', 'B')] = chr(97 + _i)

def try_bacon(s):
    t = re.sub(r"[^A-Ba-b01]", "", s)
    if len(t) < 25 or len(t) % 5 != 0:
        return None
    t = t.upper().replace('0', 'A').replace('1', 'B')
    letters = [_BACON.get(t[i:i+5], '?') for i in range(0, len(t), 5)]
    if letters.count('?') / max(len(letters), 1) > 0.2:
        return None
    return ''.join(letters)

# --- lot 2 : ASCII decimal, entites HTML, unicode escapes, base45, base62, NATO
def try_decimal(s):
    """'104 101 108 108 111' -> 'hello'. Exige des separateurs."""
    if not re.fullmatch(r"[\d\s,;]+", s.strip()) or not re.search(r"[\s,;]", s.strip()):
        return None
    nums = re.findall(r"\d{1,3}", s)
    if len(nums) < 3 or not all(9 <= int(n) <= 126 for n in nums):
        return None
    try:
        return _is_printable_result(bytes(int(n) for n in nums))
    except Exception:
        return None

def try_html_entities(s):
    if not re.search(r"&#x?[0-9a-fA-F]+;|&[a-zA-Z]{2,10};", s):
        return None
    import html as _html
    r = _html.unescape(s)
    return r if r != s else None

def try_unicode_escape(s):
    if not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", s):
        return None
    try:
        r = s.encode('latin-1', 'ignore').decode('unicode_escape')
        return r if r and r != s else None
    except Exception:
        return None

_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def b45encode(b):
    res = ""
    for i in range(0, len(b), 2):
        ch = b[i:i+2]
        if len(ch) == 2:
            n = ch[0] * 256 + ch[1]
            res += _B45[n % 45] + _B45[(n // 45) % 45] + _B45[n // 2025]
        else:
            res += _B45[ch[0] % 45] + _B45[ch[0] // 45]
    return res

def b45decode(s):
    out = bytearray()
    for i in range(0, len(s), 3):
        ch = s[i:i+3]
        n = sum(_B45.index(c) * (45 ** j) for j, c in enumerate(ch))
        out += n.to_bytes(2 if len(ch) == 3 else 1, 'big')
    return bytes(out)

def try_base45(s):
    s2 = s.strip().upper()
    if len(s2) < 4 or len(s2) % 3 == 1 or any(c not in _B45 for c in s2):
        return None
    try:
        return _is_printable_result(b45decode(s2))
    except Exception:
        return None

_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase

def b62encode(b):
    n = int.from_bytes(b, 'big')
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = _B62[r] + s
    return s or "0"

def b62decode(s):
    n = 0
    for c in s:
        n = n * 62 + _B62.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''

_NATO = {"alfa": "a", "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d",
         "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i",
         "juliett": "j", "juliet": "j", "kilo": "k", "lima": "l", "mike": "m",
         "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r",
         "sierra": "s", "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w",
         "xray": "x", "yankee": "y", "zulu": "z"}

def try_nato(s):
    words = re.findall(r"[a-z]+", s.lower())
    if len(words) < 3 or not all(w in _NATO for w in words):
        return None
    return ''.join(_NATO[w] for w in words)

ENCODINGS = [
    ("base64", try_base64), ("base64url", try_base64url), ("base32", try_base32),
    ("base85", try_base85), ("base58", try_base58), ("base45", try_base45),
    ("hex", try_hex), ("binaire", try_binary), ("compression", try_compress),
    ("url", try_url), ("html", try_html_entities), ("unicode", try_unicode_escape),
    ("decimal", try_decimal), ("morse", try_morse), ("nato", try_nato),
    ("a1z26", try_a1z26), ("bacon", try_bacon),
    ("rot13", try_rot13), ("rot47", try_rot47), ("atbash", try_atbash),
]

# ----------------------------------------------------------------------
# MODE ENCODAGE - le script encode AUSSI (pas seulement decoder)
# ----------------------------------------------------------------------
def _b(s):
    return s.encode('utf-8')

MORSE_REV = {v: k for k, v in MORSE_MAP.items()}

def enc_morse(s):
    return ' '.join('/' if c == ' ' else MORSE_REV.get(c, '?') for c in s.lower())

def enc_a1z26(s):
    return '-'.join(str(ord(c) - 96) for c in s.lower() if c.isalpha())

def enc_bacon(s):
    inv = {v: k for k, v in _BACON.items()}
    return ' '.join(inv.get(c, '?????') for c in s.lower() if c.isalpha())

def enc_rot13(s):
    return s.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))

ENCODERS = {
    "base64":    lambda s: base64.b64encode(_b(s)).decode(),
    "base64url": lambda s: base64.urlsafe_b64encode(_b(s)).decode(),
    "base32":    lambda s: base64.b32encode(_b(s)).decode(),
    "base16":    lambda s: base64.b16encode(_b(s)).decode(),
    "hex":       lambda s: _b(s).hex(),
    "base85":    lambda s: base64.b85encode(_b(s)).decode(),
    "base58":    lambda s: b58encode(_b(s)),
    "binary":    lambda s: ' '.join(format(b, '08b') for b in _b(s)),
    "url":       lambda s: __import__('urllib.parse', fromlist=['quote']).quote(s, safe=''),
    "morse":     enc_morse,
    "rot13":     enc_rot13,
    "rot47":     rot47,
    "atbash":    atbash,
    "a1z26":     enc_a1z26,
    "bacon":     enc_bacon,
    "base45":    lambda s: b45encode(_b(s)),
    "base62":    lambda s: b62encode(_b(s)),
    "decimal":   lambda s: ' '.join(str(b) for b in _b(s)),
    "html":      lambda s: ''.join(f"&#{ord(c)};" for c in s),
    "unicode":   lambda s: ''.join(f"\\u{ord(c):04x}" for c in s),
    "nato":      lambda s: ' '.join({v: k for k, v in _NATO.items() if len(k) > 3}.get(c, c)
                                    for c in s.lower()),
    "reverse":   lambda s: s[::-1],
}

def do_encode(text, chain):
    """Encode le texte en appliquant une CHAINE de methodes (ex: base64,hex)."""
    cur = text
    steps = []
    for m in chain:
        m = m.strip().lower()
        if m not in ENCODERS:
            out(f"{C.R}[!] methode d'encodage inconnue : {m}{C.X}")
            out(f"{C.GR}    dispo : {', '.join(ENCODERS)}{C.X}")
            return
        cur = ENCODERS[m](cur)
        steps.append(m)
        out(f"  {C.G}[+] {m}{C.X} -> {cur[:80]!r}{'...' if len(cur) > 80 else ''}")
    out(f"\n{C.CY}{C.BD}[RESULTAT] ({' -> '.join(steps)}){C.X}")
    out(cur)

def cascade_decode(text, flag_re, max_depth=8, verbose=True):
    """Decode en boucle jusqu'a trouver un flag ou ne plus progresser.
    Retourne (flag_trouve|None, historique_des_etapes)."""
    seen = {text}
    current = text
    history = [("entree", current)]
    for depth in range(max_depth):
        f = find_flag(current, flag_re)
        if f:
            return f, history
        progressed = False
        for name, fn in ENCODINGS:
            try:
                res = fn(current)
            except Exception:
                res = None
            if res and res.strip() and res not in seen and res != current:
                seen.add(res)
                history.append((name, res))
                if verbose:
                    out(f"  {C.G}[+] decode {name}{C.X} -> {res[:80]!r}")
                current = res
                progressed = True
                break
        if not progressed:
            break
    f = find_flag(current, flag_re)
    return f, history

# ----------------------------------------------------------------------
# COUCHE 2 - Cesar (bruteforce 25 rotations + scoring)
# ----------------------------------------------------------------------
def caesar_shift(s, k):
    out_chars = []
    for c in s:
        if c.isupper():
            out_chars.append(chr((ord(c) - 65 - k) % 26 + 65))
        elif c.islower():
            out_chars.append(chr((ord(c) - 97 - k) % 26 + 97))
        else:
            out_chars.append(c)
    return ''.join(out_chars)

def caesar_crack(s, flag_re):
    results = [(k, caesar_shift(s, k), 0) for k in range(26)]
    flag, key, cand = _best_flag_or_score([(k, c) for k, c, _ in results], flag_re)
    if flag:
        return flag, key, cand, results
    results = sorted(((k, c, english_score(c)) for k, c, _ in results), key=lambda x: -x[2])
    return None, results[0][0], results[0][1], results

# ----------------------------------------------------------------------
# COUCHE 3 - XOR (cle simple 1 octet, et cle repetee via Kasiski)
# ----------------------------------------------------------------------
def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def xor_single_byte_crack(data, flag_re):
    scored = []
    for k in range(256):
        try:
            s = xor_bytes(data, bytes([k])).decode('utf-8')
        except Exception:
            continue
        scored.append((k, s, text_fitness(s)))
    if not scored:
        return None, None, None
    # flag PROPRE prioritaire (evite 'pwn{rq:tyx|}' coincidant) ; sinon meilleur score
    hits = [x for x in scored if _clean_flag(find_flag(x[1], flag_re))]
    if hits:
        k, s, _ = max(hits, key=lambda x: x[2])
        return find_flag(s, flag_re), k, s
    k, s, _ = max(scored, key=lambda x: x[2])
    return None, k, s

def hamming_distance(a, b):
    return bin(int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).count('1')

def guess_xor_keylength(data, max_len=20):
    """Distance de Hamming normalisee entre blocs successifs -> la vraie
    longueur de cle minimise generalement la distance normalisee, mais sur
    du ciphertext court ce signal est bruite et un MULTIPLE de la vraie
    longueur peut sortir en tete -> on teste aussi les diviseurs des
    meilleurs candidats (meme correctif que pour Vigenere)."""
    scored = []
    for klen in range(2, min(max_len, len(data) // 4) + 1):
        chunks = [data[i:i+klen] for i in range(0, len(data) - klen, klen)][:8]
        if len(chunks) < 2:
            continue
        dists = []
        for a, b in itertools.combinations(chunks, 2):
            if len(a) == len(b):
                dists.append(hamming_distance(a, b) / klen)
        if dists:
            scored.append((klen, sum(dists) / len(dists)))
    scored.sort(key=lambda x: x[1])
    top = [k for k, _ in scored[:5]]
    candidates = []
    for k in top:
        candidates.append(k)
        candidates.extend(_divisors(k))
    seen = set()
    ordered = []
    for k in candidates:
        if k >= 2 and k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered[:8]

def xor_repeating_key_crack(data, flag_re):
    for klen in guess_xor_keylength(data):
        key = bytearray()
        for col in range(klen):
            column = data[col::klen]
            _, best_byte, _ = xor_single_byte_crack(column, flag_re)
            key.append(best_byte or 0)
        cand = xor_bytes(data, bytes(key))
        try:
            s = cand.decode('utf-8')
        except Exception:
            continue
        f = find_flag(s, flag_re)
        if f:
            return f, bytes(key), s
        if english_score(s) > 5:
            return None, bytes(key), s
    return None, None, None

CRIB_WORDS = ["flag{", "FLAG{", "ctf{", "CTF{", "htb{", "HTB{", "thm{", "THM{", "pico{"]

def cribs_from_regex(pattern_src):
    """Derive un crib du format de flag custom (ex: 'CTF\\{...}' -> 'CTF{')
    pour que le crib dragging marche aussi avec un --flag-regex maison."""
    m = re.match(r"\^?\(?:?([A-Za-z0-9_]{1,20})\\?\{", pattern_src or "")
    if not m:
        return []
    p = m.group(1)
    return [f"{p}{{", f"{p.lower()}{{", f"{p.upper()}{{"]

def xor_crib_crack(data, flag_re, cribs=None):
    """Casse XOR a cle repetee par 'crib dragging' : on connait un fragment
    de clair tres probable (prefixe de flag CTF standard), donc on XOR ce
    fragment contre le ciphertext a chaque position pour retrouver des
    octets de la cle directement. BEAUCOUP plus fiable que l'analyse
    frequentielle seule quand le ciphertext est court (technique standard
    en CTF, plus fiable que la pure statistique)."""
    for crib in dict.fromkeys((cribs or []) + CRIB_WORDS):
        crib_b = crib.encode()
        if len(crib_b) > len(data):
            continue
        for offset in range(0, len(data) - len(crib_b) + 1):
            frag = data[offset:offset + len(crib_b)]
            key_frag = xor_bytes(frag, crib_b)
            # le crib doit lui-meme couvrir au moins une pleine periode de
            # cle pour qu'on puisse reconstruire la cle entiere -> on
            # teste toutes les longueurs de cle <= longueur du crib
            for klen in range(1, len(crib_b) + 1):
                key = bytes(key_frag[i % klen] for i in range(klen))
                # verifie la coherence : le crib doit etre periodique de
                # periode klen dans key_frag, sinon cette klen est fausse
                if all(key_frag[i] == key[i % klen] for i in range(len(key_frag))):
                    cand = xor_bytes(data, key)
                    try:
                        s = cand.decode('utf-8')
                    except Exception:
                        continue
                    f = find_flag(s, flag_re)
                    # Garde-fou : une cle CTF legitime est quasi toujours
                    # une chaine IMPRIMABLE (l'auteur du challenge la tape
                    # au clavier - 'ctf', 'secret123', etc.). Le faux
                    # positif constate produisait une cle faite de
                    # caracteres de controle purs (b'\x13\x02\x0c\x00\x1f')
                    # -> filtre bien plus robuste qu'un seuil de score
                    # arbitraire, qui finit toujours par matcher par hasard
                    # sur assez de combinaisons offset x crib x longueur.
                    key_printable = sum(1 for b in key if 32 <= b < 127) / len(key)
                    if f and key_printable >= 0.8 and english_score(s) > -2.0:
                        return f, key, s
    return None, None, None

# ----------------------------------------------------------------------
# COUCHE 4 - Vigenere (indice de coincidence + frequentiel par colonne)
# ----------------------------------------------------------------------
def index_of_coincidence(s):
    letters = [c.lower() for c in s if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0
    freq = Counter(letters)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def _divisors(n):
    return [d for d in range(2, n + 1) if n % d == 0]

def vigenere_guess_keylength(s, max_len=20):
    """L'indice de coincidence seul est bruite sur du ciphertext court : un
    MULTIPLE de la vraie longueur de cle affiche souvent un IC tout aussi
    bon (voire meilleur par variance d'echantillonnage). On teste donc
    aussi les DIVISEURS des meilleurs candidats, technique standard en
    cryptanalyse Vigenere pour compenser ce biais."""
    clean = [c.lower() for c in s if c.isalpha()]
    scored = []
    for klen in range(1, max_len + 1):
        cols = [''.join(clean[i::klen]) for i in range(klen)]
        avg_ic = sum(index_of_coincidence(c) for c in cols) / klen
        scored.append((klen, avg_ic))
    scored.sort(key=lambda x: -x[1])
    top = [k for k, ic in scored[:5]]
    candidates = []
    for k in top:
        candidates.append(k)
        candidates.extend(_divisors(k))
    seen = set()
    ordered = []
    for k in candidates:
        if k >= 1 and k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered[:8]

def _chi2_shift(col):
    """Meilleur decalage d'une colonne par CHI-CARRE vs frequences anglaises
    (methode standard Vigenere, bien plus fiable que english_score par colonne)."""
    n = len(col)
    if n == 0:
        return 0
    best_k, best_chi = 0, 1e18
    for k in range(26):
        cnt = Counter(chr((ord(c) - 97 - k) % 26 + 97) for c in col)
        chi = 0.0
        for ch in string.ascii_lowercase:
            expected = _ENG_FREQ.get(ch, 0.02) / 100.0 * n
            if expected > 0:
                chi += (cnt.get(ch, 0) - expected) ** 2 / expected
        if chi < best_chi:
            best_chi, best_k = chi, k
    return best_k

def _vig_decrypt(s, key):
    ks = [ord(k) - 97 for k in key.lower() if k.isalpha()]
    if not ks:
        return s
    res, ki = [], 0
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            res.append(chr((ord(c) - base - ks[ki % len(ks)]) % 26 + base))
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

# cles Vigenere tres frequentes en CTF (les auteurs tapent souvent un mot)
VIG_KEYS = ["key", "secret", "password", "flag", "cipher", "vigenere", "crypto",
            "hidden", "cake", "lemon", "attack", "kryptos", "cryptography",
            "admin", "letmein", "ctf", "hacker", "secretkey", "supersecret"]

def vigenere_crack(s, flag_re, max_len=20):
    clean = ''.join(c.lower() for c in s if c.isalpha())
    if len(clean) < 4:
        return None, None, None
    cands = []
    # 1) dictionnaire de cles courantes
    for key in VIG_KEYS:
        cands.append((key, _vig_decrypt(s, key)))
    # 2) TOUTES les longueurs 1..max, chi-carre par colonne
    for klen in range(1, min(max_len, len(clean)) + 1):
        shifts = [_chi2_shift(clean[col::klen]) for col in range(klen)]
        key = ''.join(chr(97 + k) for k in shifts)
        cands.append((key, _vig_decrypt(s, key)))
    # meilleur candidat (flag prioritaire, sinon meilleur score anglais)
    return _best_flag_or_score(cands, flag_re)

# ----------------------------------------------------------------------
# COUCHE 4bis - Affine (bruteforce a*x+b) + Rail fence (transposition)
# ----------------------------------------------------------------------
# mots/trigrammes anglais tres frequents -> discriminent le VRAI clair du
# charabia (la frequence de lettres seule ne suffit pas : une cle Vigenere trop
# longue sur-ajuste chaque colonne et 'tte ghicu brewr' score comme 'the quick').
_COMMON = [" the ", " and ", " for ", " that ", " with ", " this ", " you ",
           " are ", " was ", " have ", " from ", " flag ", "the", "and", "ing",
           "ion", "ent", "tio", "tha", "ere", "ate", "her", "hat", "his", "for",
           "flag", "ctf", "key"]

def word_fitness(text):
    t = " " + text.lower() + " "
    return sum(t.count(w) for w in _COMMON)

def text_fitness(s):
    """Score combine : frequence de lettres + presence de vrais mots anglais."""
    return english_score(s) + 8.0 * word_fitness(s)

def _best_flag_or_score(cands, flag_re):
    """cands = [(key, dec)]. Parmi les candidats qui matchent un flag, garde
    celui au MEILLEUR score (evite un 'ctf{garbage}' coincidant) ; sinon renvoie
    le meilleur score global. Utilise text_fitness (lettres + mots reels)."""
    scored = [(k, d, text_fitness(d)) for k, d in cands]
    hits = [(k, d, sc) for k, d, sc in scored if _clean_flag(find_flag(d, flag_re))]
    if hits:
        k, d, _ = max(hits, key=lambda x: x[2])
        return find_flag(d, flag_re), k, d
    if not scored:
        return None, None, ""
    k, d, _ = max(scored, key=lambda x: x[2])
    return None, k, d

def affine_crack(s, flag_re):
    cands = []
    for a in [x for x in range(1, 26) if math.gcd(x, 26) == 1]:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            dec = ''.join(
                chr(a_inv * ((ord(c) - 65) - b) % 26 + 65) if c.isupper() else
                chr(a_inv * ((ord(c) - 97) - b) % 26 + 97) if c.islower() else c
                for c in s)
            cands.append(((a, b), dec))
    return _best_flag_or_score(cands, flag_re)

def railfence_decode(s, rails):
    if rails < 2 or rails >= len(s):
        return s
    pattern, r, d = [], 0, 1
    for _ in s:
        pattern.append(r)
        d = 1 if r == 0 else -1 if r == rails - 1 else d
        r += d
    order = sorted(range(len(s)), key=lambda i: pattern[i])
    res = [None] * len(s)
    for k, i in enumerate(order):
        res[i] = s[k]
    return ''.join(res)

def railfence_crack(s, flag_re, max_rails=12):
    cands = [(r, railfence_decode(s, r))
             for r in range(2, min(max_rails, len(s) - 1) + 1)]
    return _best_flag_or_score(cands, flag_re)

# ----------------------------------------------------------------------
# COUCHE 4ter - Substitution monoalphabetique (hill-climbing + n-grammes)
# ----------------------------------------------------------------------
_CORPUS = ((
    "the quick brown fox jumps over the lazy dog while the cryptographer smiles "
    "softly and thinks about the secret message hidden in plain sight for anyone "
    "who knows where to look because information wants to be free and knowledge is "
    "power in the hands of those who understand how these systems really work under "
    "the surface where the true meaning of every word and letter matters more than "
    "you would expect from such a simple looking string of characters that seems "
    "random at first but reveals its structure once you apply the right technique "
    "and a little patience together with careful analysis of the frequencies and "
    "patterns that appear again and again throughout the english language which is "
    "full of common words like the and that with have this from they will have been "
    "when there their what about which would other into time could people than only "
    "over also back after use two how our work first well way even new want because "
    "any these give day most people should never underestimate the value of reading "
    "carefully and thinking clearly before making an important decision that could "
    "change everything they have worked so hard to build over many long years of "
    "effort and sacrifice for their family and friends who always believed in them "
    "no matter what happened along the difficult road that led them to this moment "
    "where they finally understand that the journey itself was the real reward all "
    "along and that success is measured not by what you have but by who you become "
    "as you learn to face your fears and overcome the many obstacles life throws at "
    "you every single day without warning or mercy but with endless opportunity to "
    "grow stronger wiser and kinder than you were the day before when you first "
    "started this incredible adventure that we call being alive and human on this "
    "small blue planet spinning quietly through the vast and silent darkness of space"
) * 2)

def _build_ngrams(text, N):
    t = re.sub(r'[^a-z]', '', text.lower())
    cnt = Counter(t[i:i + N] for i in range(len(t) - N + 1))
    total = sum(cnt.values()) or 1
    logp = {g: math.log10(c / total) for g, c in cnt.items()}
    return logp, math.log10(0.01 / total)

_QUAD_LOGP, _QUAD_FLOOR = _build_ngrams(_CORPUS, 4)
_TRI_LOGP, _TRI_FLOOR = _build_ngrams(_CORPUS, 3)
_BI_LOGP, _BI_FLOOR = _build_ngrams(_CORPUS, 2)

def _ngram_fitness(text):
    t = re.sub(r'[^a-z]', '', text.lower())
    if len(t) < 4:
        return -1e9
    # quadgrammes (fort) + trigrammes + bigrammes (lisse le paysage pour le hill-climb)
    s4 = sum(_QUAD_LOGP.get(t[i:i + 4], _QUAD_FLOOR) for i in range(len(t) - 3))
    s3 = sum(_TRI_LOGP.get(t[i:i + 3], _TRI_FLOOR) for i in range(len(t) - 2))
    s2 = sum(_BI_LOGP.get(t[i:i + 2], _BI_FLOOR) for i in range(len(t) - 1))
    return s4 + 0.5 * s3 + 0.2 * s2

def substitution_crack(s, flag_re, restarts=25, iters=2600):
    """Casse une substitution monoalphabetique par hill-climbing : part d'une
    cle aleatoire, echange 2 lettres tant que le score n-grammes s'ameliore ;
    plusieurs restarts pour eviter les optima locaux."""
    import random
    L = string.ascii_lowercase
    fit_src = s[:800]                          # cap pour la vitesse

    def apply(key, text):
        return text.translate(str.maketrans(L + L.upper(), key + key.upper()))

    best = None
    for _ in range(restarts):
        key = list(L)
        random.shuffle(key)
        cur_key = ''.join(key)
        cur_sc = _ngram_fitness(apply(cur_key, fit_src))
        it, improved = 0, True
        while improved and it < iters:
            improved = False
            for a in range(26):
                for b in range(a + 1, 26):
                    k = list(cur_key)
                    k[a], k[b] = k[b], k[a]
                    nk = ''.join(k)
                    sc = _ngram_fitness(apply(nk, fit_src))
                    if sc > cur_sc:
                        cur_key, cur_sc, improved = nk, sc, True
                    it += 1
                if it >= iters:
                    break
        dec = apply(cur_key, s)
        if best is None or cur_sc > best[2]:
            best = (cur_key, dec, cur_sc)
        if find_flag(dec, flag_re):
            return find_flag(dec, flag_re), cur_key, dec
    if best:
        return find_flag(best[1], flag_re), best[0], best[1]
    return None, None, None

# ----------------------------------------------------------------------
# COUCHE 5 - Identification de hash
# ----------------------------------------------------------------------
HASH_PATTERNS = [
    (r"^\$2[aby]\$\d+\$.{53}$", "bcrypt", "3200"),
    (r"^\$6\$", "sha512crypt", "1800"),
    (r"^\$5\$", "sha256crypt", "7400"),
    (r"^\$1\$", "md5crypt", "500"),
    (r"^\$y\$|\$7\$", "yescrypt", "None (non supporte par hashcat)"),
    (r"^[a-fA-F0-9]{32}$", "MD5 / NTLM (ambigu, verifier contexte)", "0 (MD5) / 1000 (NTLM)"),
    (r"^[a-fA-F0-9]{40}$", "SHA1", "100"),
    (r"^[a-fA-F0-9]{56}$", "SHA224", "1300"),
    (r"^[a-fA-F0-9]{64}$", "SHA256", "1400"),
    (r"^[a-fA-F0-9]{96}$", "SHA384", "10800"),
    (r"^[a-fA-F0-9]{128}$", "SHA512", "1700"),
    (r"^[a-fA-F0-9]{32}:[A-F0-9]{32}$", "NTLMv1/NetNTLM", "5500"),
    (r"^\$krb5", "Kerberos ticket (TGS/AS-REP)", "13100 / 18200"),
]

def identify_hash(s):
    s = s.strip()
    matches = []
    for pattern, name, mode in HASH_PATTERNS:
        if re.match(pattern, s):
            matches.append((name, mode))
    return matches

# ----------------------------------------------------------------------
# IDENTIFICATION du type d'encodage (facon 'magic' CyberChef)
# ----------------------------------------------------------------------
def identify_encoding(text):
    """Devine le(s) type(s) probable(s). Retourne [(nom, confiance, apercu)]."""
    t = text.strip()
    # (nom, fonction de decode, confiance) - confiance haute = format tres specifique
    checks = [
        ("morse", try_morse, 96), ("compression (gzip/zlib/bz2)", try_compress, 96),
        ("NATO phonetique", try_nato, 95), ("binaire", try_binary, 92),
        ("entites HTML", try_html_entities, 90), ("echappements unicode", try_unicode_escape, 90),
        ("URL-encode", try_url, 88), ("ASCII decimal", try_decimal, 86),
        ("base45", try_base45, 84), ("base32", try_base32, 84), ("bacon", try_bacon, 84),
        ("base64url", try_base64url, 80), ("a1z26", try_a1z26, 78),
        ("hex", try_hex, 76), ("base64", try_base64, 70), ("base58", try_base58, 66),
        ("base85", try_base85, 58),
    ]
    hits = []
    for name, fn, conf in checks:
        try:
            res = fn(t)
        except Exception:
            res = None
        if res:
            hits.append((name, conf, res[:60]))
    for name, mode in identify_hash(t):
        hits.append((f"HASH : {name}", 88, f"hashcat -m {mode}"))
    if extract_rsa_params(t).get('n'):
        hits.append(("parametres RSA (n/e/c)", 90, "-> attaques RSA auto"))
    # rot13/atbash/cesar : detectables seulement par amelioration de score
    if re.fullmatch(r"[A-Za-z\s.,!?'\"{}_-]+", t) and len(t) > 6:
        hits.append(("texte alpha : possible Cesar/Affine/Vigenere/substitution/rot13/atbash",
                     40, "-> essaie le decodage complet"))
    hits.sort(key=lambda x: -x[1])
    return hits

# ----------------------------------------------------------------------
# JWT : decode header/payload + alg:none + bruteforce du secret HS*
# ----------------------------------------------------------------------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
JWT_SECRETS = ["secret", "password", "123456", "key", "jwt", "admin", "changeme",
               "your-256-bit-secret", "supersecret", "s3cr3t", "secretkey",
               "private", "flag", "test", "token", "pass", "qwerty", "letmein",
               "root", "12345678", "P@ssw0rd", "1234567890"]

def _b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _load_wordlist(limit=50000):
    for path in ("/usr/share/wordlists/rockyou.txt",
                 "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"):
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    return [l.rstrip("\n") for _, l in zip(range(limit), f)]
            except Exception:
                pass
    return []

def jwt_analyze(token):
    import hmac, hashlib
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_dec(parts[0]))
        payload = json.loads(_b64url_dec(parts[1]))
    except Exception:
        return None
    alg = str(header.get("alg", "")).upper()
    info = {"header": header, "payload": payload, "alg": header.get("alg"),
            "none_forgery": None, "secret": None}
    if alg == "NONE":
        info["none_forgery"] = f"{parts[0]}.{parts[1]}."
    if alg.startswith("HS") and len(parts) == 3:
        hfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        secrets = list(dict.fromkeys(JWT_SECRETS + _load_wordlist()))
        for sec in secrets:
            sig = base64.urlsafe_b64encode(
                hmac.new(sec.encode(), signing_input, hfn).digest()).rstrip(b"=").decode()
            if sig == parts[2]:
                info["secret"] = sec
                break
    return info

# ----------------------------------------------------------------------
# COUCHE 6 - RSA faible (detection auto n/e/c + attaques courantes)
# ----------------------------------------------------------------------
def _toint(v):
    return int(v, 16) if v.lower().startswith('0x') else int(v)

def extract_rsa_params(text):
    params = {}
    for key in ('n', 'e', 'c', 'p', 'q', 'd', 'phi'):
        m = re.search(rf"\b{key}\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)", text)
        if m:
            params[key] = _toint(m.group(1))
    # variantes numerotees : e1/e2, c1/c2/c3, n1/n2/n3 (common modulus + Hastad)
    for key in ('e', 'c', 'n'):
        for idx in ('1', '2', '3', '4'):
            m = re.search(rf"\b{key}{idx}\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)", text)
            if m:
                params[f"{key}{idx}"] = _toint(m.group(1))
    return params

def _looks_plaintext(pt):
    """Un vrai clair RSA est quasi toujours imprimable (l'auteur tape un flag)."""
    if not pt:
        return False
    printable = sum(1 for c in pt if c in string.printable)
    return printable / max(len(pt), 1) >= 0.85

def iroot(n, k):
    """Racine k-ieme entiere de n (pour l'attaque exposant petit sans padding)."""
    if n < 0:
        return None
    lo, hi = 0, 1
    while hi ** k <= n:
        hi *= 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo

def rsa_small_e_attack(n, e, c):
    """Si c = m^e mod n mais que m^e < n (pas de wraparound, message court /
    pas de padding), alors m = racine e-ieme entiere de c. Classique CTF."""
    if e > 11:
        return None
    root = iroot(c, e)
    if root ** e == c:
        try:
            nbytes = (root.bit_length() + 7) // 8
            raw = root.to_bytes(nbytes, 'big')
            return raw.decode('utf-8', errors='ignore')
        except Exception:
            return str(root)
    return None

def fermat_factor(n, max_iter=200000):
    """Factorisation de Fermat : marche quand p et q sont proches
    (|p-q| petit) -> tres frequent dans les CTF crypto mal generes."""
    a = math.isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == n and p > 1 and q > 1:
                return p, q
        a += 1
    return None

def pollard_pm1(n, B=200000):
    """Pollard p-1 : factorise si p-1 est 'lisse' (petits facteurs). Offline."""
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 256 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d, n // d
    d = math.gcd(a - 1, n)
    return (d, n // d) if 1 < d < n else None

def pollard_rho(n, max_tries=6):
    """Pollard rho (Brent) : trouve un petit facteur rapidement. Offline."""
    import random
    if n % 2 == 0:
        return 2, n // 2
    for _ in range(max_tries):
        x = random.randrange(2, n - 1)
        y, c, d = x, random.randrange(1, n - 1), 1
        cnt = 0
        while d == 1 and cnt < 1 << 20:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            cnt += 1
        if 1 < d < n:
            return d, n // d
    return None

def factor_n(n):
    """Tente de factoriser n localement : Fermat -> Pollard p-1 -> Pollard rho."""
    for fn in (lambda: fermat_factor(n, 100000),
               lambda: pollard_pm1(n),
               lambda: pollard_rho(n)):
        try:
            r = fn()
        except Exception:
            r = None
        if r and r[0] * r[1] == n and r[0] > 1 and r[1] > 1:
            return r
    return None

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y

def rsa_common_modulus_solve(n, e1, c1, e2, c2):
    """Meme modulus n, 2 exposants e1/e2 premiers entre eux -> m = c1^a * c2^b
    mod n (Bezout). Erreur de generation classique en CTF."""
    g, a, b = _egcd(e1, e2)
    if g != 1:
        return None
    m1 = pow(c1, a, n) if a >= 0 else pow(pow(c1, -1, n), -a, n)
    m2 = pow(c2, b, n) if b >= 0 else pow(pow(c2, -1, n), -b, n)
    m = (m1 * m2) % n
    try:
        raw = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return str(m)

def _m_to_text(m):
    try:
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')
    except Exception:
        return str(m)

def rsa_decrypt_with_d(n, d, c):
    """d (ou phi) connu -> dechiffrement direct m = c^d mod n."""
    return _m_to_text(pow(c, d, n))

def rsa_multiprime(primes, e, c):
    """n = produit de PLUSIEURS premiers (FactorDB en donne parfois >2) ->
    phi = produit des (pi-1), d = e^-1 mod phi, m = c^d mod n."""
    n = 1
    phi = 1
    for p in primes:
        n *= p
        phi *= (p - 1)
    try:
        d = pow(e, -1, phi)
        return _m_to_text(pow(c, d, n))
    except Exception:
        return None

def rsa_hastad(pairs, e):
    """Hastad broadcast : meme message m chiffre avec le MEME petit e vers
    >= e destinataires (n_i, c_i) distincts -> CRT puis racine e-ieme entiere.
    Classique quand e=3 et 3 (n,c) donnes."""
    if len(pairs) < e:
        return None
    N = 1
    for n, _ in pairs:
        N *= n
    total = 0
    for n, c in pairs:
        Ni = N // n
        try:
            total += c * Ni * pow(Ni, -1, n)
        except Exception:
            return None
    x = total % N
    m = iroot(x, e)
    if m is not None and m ** e == x:
        return _m_to_text(m)
    return None

def rsa_wiener(n, e, c):
    """Attaque de Wiener : recupere d quand d est PETIT (d < n^0.25), via les
    reduites de la fraction continue de e/n. Frequent en CTF (e enorme)."""
    def cont_frac(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b
    def convergents(cf):
        num0, den0, num1, den1 = 0, 1, 1, 0
        for q in cf:
            num0, num1 = num1, q * num1 + num0
            den0, den1 = den1, q * den1 + den0
            yield num1, den1
    for k, d in convergents(cont_frac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # resout x^2 - (n - phi + 1) x + n = 0 -> racines p,q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        r = math.isqrt(disc)
        if r * r != disc:
            continue
        if c is None:
            return None
        try:
            m = pow(c, d, n)
            raw = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            return raw.decode('utf-8', errors='ignore')
        except Exception:
            return None
    return None

def factordb_lookup(n, timeout=8):
    """Interroge FactorDB (base publique de nombres factorises) - beaucoup
    de challenges CTF reutilisent des n deja factorises par la communaute.
    Retourne None si injoignable (offline) -> ne bloque jamais le script."""
    try:
        url = f"http://factordb.com/api?query={n}"
        req = urllib.request.Request(url, headers={"User-Agent": "cryptohunt/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        factors = data.get("factors", [])
        primes = []
        for f, mult in factors:
            primes.extend([int(f)] * mult)
        return primes if len(primes) >= 2 else None
    except Exception:
        return None

def rsa_solve(params, flag_re, use_factordb=True):
    findings = []
    n, e, c = params.get('n'), params.get('e'), params.get('c')
    p, q = params.get('p'), params.get('q')

    if p and q and n is None:
        n = p * q

    if not n:
        return findings

    d_in, phi_in = params.get('d'), params.get('phi')
    primes = None
    if p and q:
        findings.append(("p/q deja fournis", p, q))
    elif not (d_in or phi_in):
        f = factor_n(n)                       # Fermat -> Pollard p-1 -> Pollard rho (offline)
        if f:
            p, q = f
            findings.append(("factorise localement (Fermat/Pollard p-1/rho)", p, q))
        elif use_factordb:
            primes = factordb_lookup(n)
            if primes and len(primes) == 2:
                p, q = primes
                findings.append(("FactorDB (deja connu publiquement)", p, q))
            elif primes and len(primes) > 2:
                findings.append((f"FactorDB : n multi-prime ({len(primes)} facteurs)",
                                 primes[0], "..."))

    result = {"n": n, "e": e, "c": c, "p": p, "q": q, "flag": None,
              "plaintext": None, "method": None, "notes": findings}

    def _accept(pt, method):
        """N'accepte un clair QUE s'il contient un flag OU est imprimable.
        Fix du bug : avant, l'outil affichait du charabia comme 'dechiffre'."""
        if not pt:
            return False
        f = find_flag(pt, flag_re)
        if f:
            result["plaintext"], result["method"], result["flag"] = pt, method, f
            return True
        if _looks_plaintext(pt):
            result["plaintext"], result["method"] = pt, method
            return True
        return False

    # 0) d ou phi DONNE directement -> dechiffrement immediat
    if c and d_in and not result["plaintext"]:
        _accept(rsa_decrypt_with_d(n, d_in, c), "d fourni -> dechiffrement direct")
    if c and e and phi_in and not result["plaintext"]:
        try:
            _accept(rsa_decrypt_with_d(n, pow(e, -1, phi_in), c),
                    "phi fourni -> d = e^-1 mod phi -> dechiffrement")
        except Exception:
            pass

    # 0bis) n multi-prime (>2 facteurs) -> phi = produit des (pi-1)
    if c and e and primes and len(primes) > 2 and not result["plaintext"]:
        _accept(rsa_multiprime(primes, e, c),
                f"n multi-prime ({len(primes)} facteurs) -> phi = prod(pi-1)")

    # 1) exposant petit sans padding (racine e-ieme)
    if e and c and not (p and q) and not result["plaintext"]:
        _accept(rsa_small_e_attack(n, e, c),
                f"exposant petit (e={e}) sans padding, racine {e}-ieme entiere")

    # 2) factorisation connue -> dechiffrement direct
    if p and q and e and c and not result["plaintext"]:
        try:
            d = pow(e, -1, (p - 1) * (q - 1))
            m = pow(c, d, n)
            pt = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')
            _accept(pt, "factorisation de n -> calcul de d -> dechiffrement direct")
        except Exception:
            pass

    # 3) Wiener (d petit) en secours si toujours rien et e grand
    if e and c and not result["plaintext"] and e > 65537:
        _accept(rsa_wiener(n, e, c), "attaque de Wiener (exposant prive d trop petit)")

    return [result]

def get_raw_bytes(s):
    """Pour l'analyse XOR/binaire : contrairement a la cascade d'encodages
    (qui exige un resultat lisible a chaque etape), le resultat d'un XOR/
    chiffrement N'A PAS a etre imprimable. On tente donc un decodage
    hex/base64 SANS filtre de printabilite, pour recuperer les vrais
    octets du ciphertext plutot que les caracteres ASCII de sa
    representation textuelle."""
    s2 = s.strip()
    compact = re.sub(r"\s", "", s2)
    hexonly = re.sub(r"[^0-9a-fA-F]", "", s2)
    if len(hexonly) >= 8 and len(hexonly) % 2 == 0 and len(hexonly) == len(compact):
        try:
            return binascii.unhexlify(hexonly)
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", compact):
        try:
            pad = compact + "=" * (-len(compact) % 4)
            return base64.b64decode(pad, validate=False)
        except Exception:
            pass
    try:
        return s.encode('latin-1')
    except Exception:
        return s.encode('utf-8', errors='ignore')

# ----------------------------------------------------------------------
# ORCHESTRATION
# ----------------------------------------------------------------------
def run(args):
    flag_re = re.compile(args.flag_regex) if args.flag_regex else DEFAULT_FLAG_RE

    if args.input:
        with open(args.input, 'r', errors='ignore') as f:
            text = f.read().strip()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read().strip()

    if not text:
        out(f"{C.Y}[!] Entree vide.{C.X}")
        return

    out(f"{C.GR}[i] Entree ({len(text)} car.) : {text[:100]!r}{'...' if len(text) > 100 else ''}{C.X}\n")

    # --- IDENTIFICATION du type d'encodage (non cassant : juste informatif) ---
    ident = identify_encoding(text)
    if ident:
        out(f"{C.B}{C.BD}== Type(s) d'encodage probable(s) =={C.X}")
        for name, conf, preview in ident[:6]:
            bar = "#" * (conf // 10)
            out(f"  {C.B}{conf:3d}% {C.GR}{bar:<10}{C.X} {C.CY}{name}{C.X}"
                + (f"  {C.GR}-> {preview!r}{C.X}" if preview else ""))
        out("")

    # --- JWT (structure distinctive : eyJ....eyJ....sig) ---
    jm = JWT_RE.search(text)
    if jm:
        info = jwt_analyze(jm.group(0))
        if info:
            out(f"{C.M}{C.BD}== Detection : JSON Web Token (JWT) =={C.X}")
            out(f"  {C.CY}header  : {info['header']}{C.X}")
            out(f"  {C.CY}payload : {info['payload']}{C.X}")
            if info["none_forgery"]:
                out(f"  {C.R}{C.BD}[!] alg=none -> forge un token SANS signature :{C.X}")
                out(f"  {C.G}    {info['none_forgery']}{C.X}")
            if info["secret"]:
                out(f"  {C.G}{C.BD}[+] secret HS trouve : '{info['secret']}'{C.X}"
                    f"  {C.GR}-> tu peux forger n'importe quel token{C.X}")
                fl = find_flag(json.dumps(info["payload"]) + info["secret"], flag_re)
                if fl:
                    out(f"  {C.G}{C.BD}[FLAG] {fl}{C.X}")
            elif str(info.get("alg", "")).upper().startswith("HS"):
                out(f"  {C.Y}[i] secret HS non trouve (dico + rockyou si present). "
                    f"Essaie une wordlist plus grande.{C.X}")
            fl = find_flag(json.dumps(info["payload"]), flag_re)
            if fl:
                out(f"  {C.G}{C.BD}[FLAG] {fl}{C.X}")
                return
            out("")

    # --- Detection hash directe (rapide, avant la cascade) ---
    hash_matches = identify_hash(text)
    if hash_matches:
        out(f"{C.M}{C.BD}== Detection : ceci ressemble a un HASH =={C.X}")
        for name, mode in hash_matches:
            out(f"  {C.M}[?] {name}{C.X}  -> hashcat -m {mode} hash.txt wordlist.txt")
        out(f"{C.GR}  [i] Pas de cassage de hash automatique ici (necessite wordlist/temps) "
            f"- commande prete ci-dessus.{C.X}\n")

    # --- Detection RSA directe ---
    rsa_params = extract_rsa_params(text)
    # Hastad broadcast : meme petit e, plusieurs (n_i, c_i) -> CRT + racine e-ieme
    e_bcast = rsa_params.get('e') or rsa_params.get('e1')
    bpairs = [(rsa_params[f"n{i}"], rsa_params[f"c{i}"]) for i in ('1', '2', '3', '4')
              if f"n{i}" in rsa_params and f"c{i}" in rsa_params]
    if e_bcast and 2 <= e_bcast <= 11 and len(bpairs) >= e_bcast:
        out(f"{C.M}{C.BD}== Detection : RSA Hastad broadcast (e={e_bcast}, {len(bpairs)} messages) =={C.X}")
        pt = rsa_hastad(bpairs, e_bcast)
        if pt and (find_flag(pt, flag_re) or _looks_plaintext(pt)):
            fl = find_flag(pt, flag_re)
            out(f"  {C.G}{C.BD}[FLAG] {fl}{C.X}  (Hastad)" if fl else
                f"  {C.G}[+] dechiffre (Hastad) -> {pt[:200]!r}{C.X}")
            return
        out(f"  {C.Y}[i] Hastad tente mais pas de clair exploitable.{C.X}\n")
    # common modulus : meme n, e1/e2 + c1/c2 -> attaque de Bezout (branchee !)
    if 'n' in rsa_params and {'e1', 'e2', 'c1', 'c2'} <= set(rsa_params):
        out(f"{C.M}{C.BD}== Detection : RSA common modulus (e1/e2 + c1/c2) =={C.X}")
        pt = rsa_common_modulus_solve(rsa_params['n'], rsa_params['e1'],
                                      rsa_params['c1'], rsa_params['e2'], rsa_params['c2'])
        if pt and (find_flag(pt, flag_re) or _looks_plaintext(pt)):
            fl = find_flag(pt, flag_re)
            if fl:
                out(f"  {C.G}{C.BD}[FLAG] {fl}{C.X}  (common modulus)")
            else:
                out(f"  {C.G}[+] dechiffre (common modulus) -> {pt[:200]!r}{C.X}")
            return
        out(f"  {C.Y}[i] common modulus tente mais pas de clair exploitable.{C.X}\n")
    if 'n' in rsa_params or ('p' in rsa_params and 'q' in rsa_params):
        out(f"{C.M}{C.BD}== Detection : parametres RSA trouves =={C.X}")
        out(f"  {C.GR}parametres extraits : {rsa_params}{C.X}")
        results = rsa_solve(rsa_params, flag_re, use_factordb=not args.no_online)
        for r in results:
            if r["flag"]:
                out(f"  {C.G}{C.BD}[FLAG] {r['flag']}{C.X}")
                out(f"  {C.GR}methode : {r['method']}{C.X}")
                return
            elif r["plaintext"]:
                out(f"  {C.G}[+] dechiffre via : {r['method']}{C.X}")
                out(f"  {C.G}    -> {r['plaintext'][:200]!r}{C.X}")
            elif r["notes"]:
                for note, p, q in r["notes"]:
                    out(f"  {C.Y}[i] {note} : p={p}{C.X}")
                    out(f"  {C.Y}                 q={q}{C.X}")
            else:
                out(f"  {C.Y}[!] n non factorisable automatiquement (premiers trop grands/eloignes) "
                    f"-> essaie RsaCtfTool (Wiener, Boneh-Durfee, etc.) :{C.X}")
                out(f"  {C.CY}    certipy... non, ici : python3 RsaCtfTool.py -n {rsa_params.get('n','<n>')} "
                    f"-e {rsa_params.get('e','<e>')} --uncipher {rsa_params.get('c','<c>')}{C.X}")
        out("")

    # --- Cascade d'encodages (toujours tentee, c'est le plus courant) ---
    out(f"{C.CY}{C.BD}== Cascade de decodage (encodages reversibles) =={C.X}")
    flag, history = cascade_decode(text, flag_re, max_depth=args.max_depth)
    if flag:
        out(f"\n{C.G}{C.BD}[FLAG] {flag}{C.X}")
        out(f"{C.GR}chemin : {' -> '.join(h[0] for h in history)}{C.X}")
        return
    final = history[-1][1]
    if len(history) > 1:
        out(f"{C.GR}  [i] Aucun flag direct, mais {len(history)-1} couche(s) d'encodage retiree(s).{C.X}")
        out(f"{C.GR}      Resultat final : {final[:150]!r}{C.X}\n")
    else:
        out(f"{C.GR}  [i] Aucun encodage reversible detecte, l'entree reste telle quelle.{C.X}\n")

    working_text = final

    # --- Cesar ---
    out(f"{C.CY}{C.BD}== Cesar (bruteforce 25 rotations) =={C.X}")
    flag, key, cand, _ = caesar_crack(working_text, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (rotation={key})")
        return
    out(f"  {C.GR}meilleur candidat (rotation={key}, score max) : {cand[:100]!r}{C.X}\n")

    # --- Affine (a*x+b) ---
    out(f"{C.CY}{C.BD}== Affine (bruteforce a*x+b) =={C.X}")
    flag, key, cand = affine_crack(working_text, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (a,b={key})")
        return
    if key:
        out(f"  {C.GR}meilleur candidat (a,b={key}) : {cand[:100]!r}{C.X}\n")

    # --- Rail fence (transposition) ---
    out(f"{C.CY}{C.BD}== Rail fence (transposition, 2-12 rails) =={C.X}")
    flag, key, cand = railfence_crack(working_text, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (rails={key})")
        return
    if key:
        out(f"  {C.GR}meilleur candidat (rails={key}) : {cand[:100]!r}{C.X}\n")

    # --- XOR (simple puis cle repetee) : on repart de l'ENTREE D'ORIGINE (hex/
    #     base64 du ciphertext), PAS du working_text sur-decode par la cascade
    #     (rot47/atbash peuvent l'avoir corrompu). ---
    raw_bytes = get_raw_bytes(text)

    out(f"{C.CY}{C.BD}== XOR cle simple (1 octet, bruteforce 256) =={C.X}")
    flag, key, cand = xor_single_byte_crack(raw_bytes, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (cle=0x{key:02x})")
        return
    if key is not None:
        out(f"  {C.GR}meilleur candidat (cle=0x{key:02x}) : {cand[:100]!r}{C.X}\n")

    out(f"{C.CY}{C.BD}== XOR cle repetee (crib dragging, puis Kasiski en secours) =={C.X}")
    flag, key, cand = xor_crib_crack(raw_bytes, flag_re,
                                     cribs=cribs_from_regex(args.flag_regex))
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (cle={key}, methode=crib dragging)")
        return
    flag, key, cand = xor_repeating_key_crack(raw_bytes, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (cle={key}, methode=frequentiel)")
        return
    if key:
        out(f"  {C.GR}meilleur candidat (cle={key}) : {cand[:100]!r}{C.X}\n")

    # --- Vigenere ---
    out(f"{C.CY}{C.BD}== Vigenere (indice de coincidence + frequentiel) =={C.X}")
    flag, key, cand = vigenere_crack(working_text, flag_re)
    if flag:
        out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}  (cle={key})")
        return
    if key:
        out(f"  {C.GR}meilleur candidat (cle={key}) : {cand[:100]!r}{C.X}\n")

    # --- Substitution monoalphabetique (hill-climbing) : seulement si ca ressemble
    #     a du texte alpha (sinon inutile et lent) ---
    alpha = [c for c in working_text if c.isalpha()]
    if 20 <= len(alpha) <= 3000 and len(alpha) / max(len(working_text), 1) > 0.5:
        out(f"{C.CY}{C.BD}== Substitution monoalphabetique (hill-climbing) =={C.X}")
        flag, key, cand = substitution_crack(working_text, flag_re)
        if flag:
            out(f"{C.G}{C.BD}[FLAG] {flag}{C.X}")
            return
        if cand:
            out(f"  {C.GR}meilleur candidat : {cand[:100]!r}{C.X}\n")

    # --- Rien trouve : verdict honnete ---
    out(f"{C.Y}{C.BD}== Aucun flag trouve par les methodes automatiques =={C.X}")
    out(f"""{C.GR}
  Ce que ca signifie probablement :
    - Chiffrement moderne correctement implemente (AES/ChaCha20 avec bonne cle,
      RSA avec des premiers assez grands et un e standard) -> pas cassable sans
      la cle, quel que soit l'outil utilise. Cherche plutot la cle ailleurs
      dans le challenge (fichier annexe, metadata, faille applicative).
    - Chiffrement classique avec une cle longue/aleatoire (Vigenere avec cle
      >20 caracteres par exemple) -> la detection de longueur peut echouer,
      essaie CyberChef en manuel pour visualiser les patterns.
    - Format non reconnu -> verifie 'file <input>' si c'est un fichier binaire,
      peut-etre que c'est de la stego (relance ton outil stego dessus).
{C.X}""")

def main():
    p = argparse.ArgumentParser(
        description="cryptohunt.py - resolution assistee de challenges crypto CTF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemples (DECODAGE, defaut) :
  cryptohunt.py -t "SGVsbG8gV29ybGQ="
  cryptohunt.py -i chall.txt
  echo "n=12345 e=3 c=6789" | cryptohunt.py
  cryptohunt.py -i hash.txt --flag-regex 'CTF\\{[^}]+\\}'

Exemples (ENCODAGE) :
  cryptohunt.py -t "flag{hi}" -e base64
  cryptohunt.py -t "secret" -e base64,hex        # chaine (encode puis encode)
  cryptohunt.py -t "hello" -e morse
  cryptohunt.py --list                            # liste les methodes d'encodage

[!] Usage LEGAL uniquement.""")
    p.add_argument("-i", "--input", help="Fichier contenant le texte/donnees a analyser")
    p.add_argument("-t", "--text", help="Texte inline a analyser (au lieu d'un fichier)")
    p.add_argument("-e", "--encode", help="ENCODER au lieu de decoder : methode(s) separees par des virgules "
                                          "(ex: base64 ou base64,hex)")
    p.add_argument("--list", action="store_true", help="Liste les methodes d'encodage disponibles")
    p.add_argument("-I", "--identify", action="store_true",
                   help="IDENTIFIER seulement le type d'encodage (sans tout decoder)")
    p.add_argument("--flag-regex", help="Regex custom du format de flag (defaut: motif générique {...})")
    p.add_argument("--max-depth", type=int, default=8, help="Profondeur max de la cascade d'encodage (defaut 8)")
    p.add_argument("--no-online", action="store_true", help="Desactive le lookup FactorDB (mode offline)")
    args = p.parse_args()

    # UTF-8 (errors=replace) : le banner en art-bloc ne crashe plus en console Windows (cp1252)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    intro()   # banner anime

    if args.list:
        out(f"{C.CY}{C.BD}Methodes d'encodage (-e) :{C.X}")
        out("  " + ", ".join(ENCODERS))
        return

    def _read():
        if args.input:
            return open(args.input, encoding="utf-8", errors="ignore").read().rstrip("\n")
        if args.text is not None:
            return args.text
        return sys.stdin.read().rstrip("\n")

    try:
        if args.identify:
            # MODE IDENTIFICATION SEULE
            text = _read().strip()
            out(f"{C.B}{C.BD}== Type(s) d'encodage probable(s) =={C.X}")
            hits = identify_encoding(text)
            if not hits:
                out(f"  {C.Y}Aucun format reconnu (texte brut ? chiffrement ?){C.X}")
            for name, conf, preview in hits:
                bar = "#" * (conf // 10)
                out(f"  {C.B}{conf:3d}% {C.GR}{bar:<10}{C.X} {C.CY}{name}{C.X}"
                    + (f"  {C.GR}-> {preview!r}{C.X}" if preview else ""))
        elif args.encode:
            # MODE ENCODAGE
            text = _read()
            out(f"{C.CY}{C.BD}== Encodage ({args.encode}) =={C.X}")
            do_encode(text, args.encode.split(","))
        else:
            run(args)
    except KeyboardInterrupt:
        out(f"\n{C.Y}[!] Interrompu.{C.X}")
        sys.exit(130)

if __name__ == "__main__":
    main()
