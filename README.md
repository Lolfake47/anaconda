
# SecuLearn OS v3.0 (Kali Edition)

Ferramenta de simulação de segurança ofensiva focada em reconhecimento, enumeração e planejamento de exploração.

## ⚡ Instalação Rápida (Kali Linux)

Abra seu terminal e cole o seguinte:

```bash
git clone <url-do-seu-repositorio>
cd <nome-da-pasta>
chmod +x install.sh
./install.sh
serve -s .
```

## 🛠️ O que faz:
- **Port Scanning:** Simulação de Nmap (SYN/UDP).
- **Directory Fuzzing:** Enumeração de diretórios sensíveis (`/.git`, `/admin`, etc).
- **Vulnerability Mapping:** Identificação automática de CVEs.
- **Exploitation Plan:** Gera os comandos exatos para usar no `msfconsole`.
- **AI Analysis:** Usa o motor Gemini para explicar a teoria por trás de cada falha.

## 🚀 Como rodar no Windows:
1. Instale o Node.js.
2. Na pasta do projeto, abra o terminal e digite: `npx serve .`
3. Abra o link no navegador.

---
**AVISO:** Desenvolvido apenas para fins de estudo e treinamento ético.
