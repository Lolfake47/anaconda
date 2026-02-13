#!/bin/bash

# Cores e Estética
G='\033[0;32m'
B='\033[0;34m'
R='\033[0;31m'
Y='\033[1;33m'
NC='\033[0m' 

echo -e "${B}┌────────────────────────────────────────────────────┐${NC}"
echo -e "${B}│${G}         ANACONDA RED SUITE - BY LOLFAKE47          ${B}│${NC}"
echo -e "${B}│${G}            Next-Gen Security Simulator             ${B}│${NC}"
echo -e "${B}└────────────────────────────────────────────────────┘${NC}"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then 
  echo -e "${R}[!] Erro: Precisas de permissões de ROOT (sudo)${NC}"
  exit 1
fi

# 2. Dependency Check
echo -e "${Y}[*] Validando ambiente Kali Linux...${NC}"
dependencies=("node" "npm" "git")
for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo -e "${Y}[!] $dep não encontrado. Instalando via APT...${NC}"
        apt update && apt install -y $dep
    else
        echo -e "${G}[+] $dep detetado.${NC}"
    fi
done

# 3. Serve Installation
if ! command -v serve &> /dev/null; then
    echo -e "${Y}[*] Instalando motor web (serve)...${NC}"
    npm install -g serve
fi

# 4. Global Command Configuration
echo -e "${Y}[*] Mapeando binário 'anaconda'...${NC}"
CURRENT_DIR=$(pwd)
BIN_PATH="/usr/local/bin/anaconda"

cat > $BIN_PATH <<EOF
#!/bin/bash
echo -e "${G}[+] Iniciando Anaconda Red Suite (v4.5)...${NC}"
cd $CURRENT_DIR
serve -s . -l 3000
EOF

chmod +x $BIN_PATH

# 5. Desktop Integration
echo -e "${Y}[*] Integrando ao menu de ferramentas do Kali...${NC}"
DESKTOP_FILE="/usr/share/applications/anaconda.desktop"
cat > $DESKTOP_FILE <<EOF
[Desktop Entry]
Name=Anaconda Red Suite (Lolfake47)
Comment=Advanced Pentest Simulator 2026
Exec=anaconda
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=03-webapp-analysis;01-info-gathering;08-exploitation-tools;
Keywords=pentest;security;anaconda;lolfake47;
EOF

echo -e "${B}──────────────────────────────────────────────────────${NC}"
echo -e "${G}[V] INSTALAÇÃO CONCLUÍDA - LOLFAKE47 EDITION${NC}"
echo -e "${Y}  > Terminal: ${NC}anaconda"
echo -e "${Y}  > Menu:     ${NC}Aplicações > Web App Analysis"
echo -e "${B}──────────────────────────────────────────────────────${NC}"