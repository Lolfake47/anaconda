
#!/bin/bash

# Cores para o terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' 

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN}      SECULEARN OS v4.0 - KALI NATIVE INSTALLER${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Verificar permissões de Root (necessário para criar atalhos no sistema)
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Por favor, execute como root (sudo ./install.sh)${NC}"
  exit
fi

# 2. Verificar dependências básicas
echo -e "${YELLOW}[*] Verificando dependências...${NC}"
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}[!] Node.js não encontrado. Instalando via apt...${NC}"
    apt update && apt install -y nodejs npm
else
    echo -e "${GREEN}[+] Node.js detectado.${NC}"
fi

# 3. Instalar o servidor 'serve'
if ! command -v serve &> /dev/null; then
    echo -e "${YELLOW}[*] Instalando servidor estático global...${NC}"
    npm install -g serve
else
    echo -e "${GREEN}[+] Servidor 'serve' já instalado.${NC}"
fi

# 4. Preparar scripts de execução
echo -e "${YELLOW}[*] Configurando scripts de inicialização...${NC}"
CURRENT_DIR=$(pwd)
cat > /usr/local/bin/seculearn <<EOF
#!/bin/bash
cd $CURRENT_DIR
serve -s . -l 3000
EOF
chmod +x /usr/local/bin/seculearn

# 5. Criar atalho no Menu do Kali
echo -e "${YELLOW}[*] Criando atalho no menu de aplicações...${NC}"
cat > /usr/share/applications/seculearn.desktop <<EOF
[Desktop Entry]
Name=SecuLearn Red Suite
Comment=Simulador de Penetration Testing e Burp Suite Web
Exec=/usr/local/bin/seculearn
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=03-webapp-analysis;01-info-gathering;
Keywords=pentest;security;burp;nmap;
EOF

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN}[V] INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}Como usar:${NC}"
echo -e "1. Procure por 'SecuLearn' no menu do Kali."
echo -e "2. Ou digite ${GREEN}seculearn${NC} em qualquer terminal."
echo -e "3. O app abrirá em: ${BLUE}http://localhost:3000${NC}"
echo -e "${BLUE}====================================================${NC}"
