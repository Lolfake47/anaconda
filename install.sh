
#!/bin/bash

# Cores para o terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN}      SECULEARN OS v3.0 - INSTALLER (KALI)${NC}"
echo -e "${BLUE}====================================================${NC}"

# Verificar se Node.js está instalado
if ! command -v node &> /dev/null
then
    echo -e "${RED}[!] Node.js não encontrado. Instalando...${NC}"
    sudo apt update && sudo apt install -y nodejs npm
else
    echo -e "${GREEN}[+] Node.js já está instalado.${NC}"
fi

# Instalar o servidor estático 'serve' globalmente se não existir
if ! command -v serve &> /dev/null
then
    echo -e "${BLUE}[*] Instalando servidor estático leve...${NC}"
    sudo npm install -g serve
fi

echo -e "${GREEN}[+] Instalação concluída!${NC}"
echo -e "${BLUE}[*] Para rodar a ferramenta agora, digite:${NC}"
echo -e "${GREEN}    serve -s .${NC}"
echo -e "${BLUE}[*] E abra o endereço exibido no seu Firefox do Kali.${NC}"
echo -e "${BLUE}====================================================${NC}"
