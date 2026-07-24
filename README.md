# rakdecode

**Résolution assistée de challenges crypto CTF — décode, identifie, encode, et casse les chiffrements faibles.** Sortie colorée, intro animée.

> ⚠️ **Usage LÉGAL uniquement** : CTF / labs / cibles explicitement autorisées.
> *by 12ak_H4ck*

---

## Ce qu'il fait

- **Cascade de décodage** (auto, jusqu'au flag) : base64 / base64url / base32 / base16 / base85 / base58 / base45 / base62, hex, binaire, URL, morse, ASCII décimal, entités HTML, échappements unicode, NATO, a1z26, bacon, rot13/47, atbash, gzip/zlib/bz2.
- **Identification du type d'encodage** (`-I`, façon *Magic* CyberChef) : dit ce que c'est, avec un % de confiance.
- **Encodage** (`-e`) : applique une ou plusieurs méthodes en chaîne (ex: `-e base64,hex`).
- **Chiffrements classiques cassés** : César, Affine, Rail fence, XOR (simple/répété/crib), Vigenère — bruteforce + analyse fréquentielle (choix du meilleur candidat par score).
- **Identification de hash** → commande hashcat exacte.
- **RSA faible** : petit `e` sans padding, Fermat, common modulus, Wiener, **Håstad broadcast**, multi-prime, `d`/`phi` fournis, FactorDB — avec vérification du clair.

Il est **honnête** : il ne prétend pas casser de l'AES/RSA fort correctement implémenté.

---

## Installation (Kali / Debian / Ubuntu)

```bash
git clone https://github.com/Rachkpt/rakdecode.git
cd rakdecode
./install.sh
```

Ensuite, depuis n'importe où : **`rakdecode`**. Pur Python (aucune dépendance). Mise à jour : `git pull`.

---

## Utilisation

```bash
rakdecode -t "SGVsbG8gV29ybGQ="            # décode en cascade jusqu'au flag
rakdecode -I -t "SGVsbG8="                 # IDENTIFIE le type (sans tout décoder)
rakdecode -i chall.txt                      # depuis un fichier
echo "n=.. e=.. c=.." | rakdecode           # RSA (auto)
rakdecode -t "flag{hi}" -e base64,hex       # ENCODE en chaîne
rakdecode --list                            # méthodes d'encodage
```

### RSA — l'outil détecte tout seul
```bash
rakdecode -t "n=.. e=.. c=.."                       # small-e / Fermat / Wiener / FactorDB
rakdecode -t "n=.. e=.. d=.. c=.."                  # d fourni
rakdecode -t "e=3 n1=.. c1=.. n2=.. c2=.. n3=.. c3=.."   # Håstad broadcast
rakdecode -t "n=.. e1=.. c1=.. e2=.. c2=.."         # common modulus
```

## Options

| Option | Rôle |
|---|---|
| `-t, --text` | Texte inline |
| `-i, --input` | Fichier à analyser |
| `-I, --identify` | Identifier seulement le type d'encodage |
| `-e, --encode` | Encoder (méthode(s) séparées par des virgules) |
| `--list` | Liste des méthodes d'encodage |
| `--flag-regex` | Format de flag custom (ex: `'CTF\{[^}]+\}'`) |
| `--max-depth` | Profondeur max de la cascade (défaut 8) |
| `--no-online` | Mode offline (désactive FactorDB) |

---

*by 12ak_H4ck — outil de sécurité offensive. Usage légal / CTF uniquement.*
