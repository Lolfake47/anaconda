#!/bin/bash

# Cores e Estética
G='\033[0;32m'
B='\033[0;34m'
R='\033[0;31m'
Y='\033[1;33m'
NC='\033[0m' 

echo -e "${B}┌────────────────────────────────────────────────────┐${NC}"
echo -e "${B}│${G}         ANACONDA RED SUITE - BY LOLFAKE47          ${B}│${NC}"
echo -e "${B}│${G}         ELECTRON NATIVE DESKTOP APP (2026)         ${B}│${NC}"
echo -e "${B}└────────────────────────────────────────────────────┘${NC}"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then 
  echo -e "${R}[!] Erro: Precisas de permissões de ROOT (sudo)${NC}"
  exit 1
fi

# 2. Dependency Check
echo -e "${Y}[*] Verificando dependências do sistema...${NC}"
dependencies=("node" "npm" "git" "libnss3" "libatk-bridge2.0-0" "libcups2" "libdrm2" "libgtk-3-0" "libgbm1" "libasound2")
for dep in "${dependencies[@]}"; do
    if ! dpkg -s $dep >/dev/null 2>&1; then
        echo -e "${Y}[!] $dep não encontrado. Instalando via APT...${NC}"
        apt update && apt install -y $dep
    else
        echo -e "${G}[+] $dep presente.${NC}"
    fi
done

# 3. Project Initialization
echo -e "${Y}[*] Instalando dependências do motor Electron...${NC}"
npm install

# 4. Build Process
echo -e "${Y}[*] Compilando assets do programa...${NC}"
npm run build

# 5. Global Command Configuration (Electron Runner)
echo -e "${Y}[*] Criando binário 'anaconda' em /usr/local/bin/...${NC}"
CURRENT_DIR=$(pwd)
BIN_PATH="/usr/local/bin/anaconda"

# Criamos um wrapper que executa o Electron no diretório correto
cat > $BIN_PATH <<EOF
#!/bin/bash
export NODE_ENV=production
# O Electron precisa de --no-sandbox em alguns ambientes Kali se corrido como root
cd "$CURRENT_DIR" && ./node_modules/.bin/electron . --no-sandbox > /dev/null 2>&1 &
EOF

chmod +x $BIN_PATH

# 6. Desktop Integration
echo -e "${Y}[*] Integrando Anaconda ao Menu do Kali Linux...${NC}"
DESKTOP_FILE="/usr/share/applications/anaconda.desktop"
cat > $DESKTOP_FILE <<EOF
[Desktop Entry]
Name=Anaconda Red Suite
Comment=Software Nativo de Pentest Simulator
Exec=anaconda
Icon=security-high
Terminal=false
Type=Application
Categories=03-webapp-analysis;01-info-gathering;08-exploitation-tools;
StartupNotify=true
EOF

echo -e "${B}──────────────────────────────────────────────────────${NC}"
echo -e "${G}[V] TRANSFORMAÇÃO PARA PROGRAMA NATIVO CONCLUÍDA${NC}"
echo -e "${Y}  > Comando Terminal: ${NC}anaconda"
echo -e "${Y}  > Menu Kali:        ${NC}Applications > Web App Analysis"
echo -e "${B}──────────────────────────────────────────────────────${NC}"