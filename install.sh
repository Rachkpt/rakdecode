#!/usr/bin/env bash
# =====================================================================
# install.sh - installe rakdecode (cryptohunt) en commande globale.
# Kali / Debian / Ubuntu.  Ensuite : rakdecode <options>
# by 12ak_H4ck
# =====================================================================
set -e
G='\033[92m'; Y='\033[93m'; R='\033[91m'; GR='\033[90m'; X='\033[0m'
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/cryptohunt.py"

echo -e "${G}[*] Installation de rakdecode...${X}"
[ -f "$SRC" ] || { echo -e "${R}[!] cryptohunt.py introuvable a cote de install.sh${X}"; exit 1; }

if head -1 "$SRC" | grep -q $'\r' 2>/dev/null; then
  sed -i 's/\r$//' "$SRC" 2>/dev/null || true
fi
chmod +x "$SRC" 2>/dev/null || true

SUDO=""
if [ -w /usr/local/bin ]; then
  BIN=/usr/local/bin
elif command -v sudo >/dev/null 2>&1; then
  BIN=/usr/local/bin; SUDO=sudo
else
  BIN="$HOME/.local/bin"; mkdir -p "$BIN"
fi

# lanceur (wrapper) : robuste peu importe le proprietaire / le bit +x
WRAP="$(mktemp)"
cat > "$WRAP" <<EOF
#!/usr/bin/env bash
exec python3 "$SRC" "\$@"
EOF
$SUDO install -m 0755 "$WRAP" "$BIN/rakdecode"
rm -f "$WRAP"
echo -e "${G}[+] Installe : ${BIN}/rakdecode  ->  python3 ${SRC}${X}"

case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) echo -e "${Y}[i] Ajoute $BIN a ton PATH :${X}"
     echo -e "${GR}    echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${X}";;
esac

echo -e "${G}[+] Termine !${X} Exemples :"
echo -e "    ${G}rakdecode -t \"SGVsbG8=\"${X}          # decode (defaut)"
echo -e "    ${G}rakdecode -t \"flag{hi}\" -e base64,hex${X}   # encode en chaine"
echo -e "    ${G}rakdecode --list${X}                    # methodes d'encodage"
echo -e "${GR}    Mise a jour  : cd $HERE && git pull${X}"
echo -e "${GR}    Desinstaller : ${SUDO} rm \$(command -v rakdecode)${X}"
