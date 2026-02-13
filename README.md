
# SecuLearn - Cybersecurity Analysis Simulator

Este projeto é um simulador educacional de enumeração de rede e análise de vulnerabilidades, projetado para rodar nativamente em ambientes como Kali Linux, Windows ou via GitHub Pages.

## 🚀 Como Executar

### Opção 1: GitHub Pages (O mais fácil)
1. Crie um novo repositório no seu GitHub.
2. Faça o upload de todos os arquivos (`index.html`, `App.tsx`, `index.tsx`, etc.).
3. Vá em **Settings > Pages** e ative o GitHub Pages apontando para a branch principal.
4. A aplicação estará disponível online.

### Opção 2: Local (Kali Linux ou Windows)
1. Certifique-se de ter o **Node.js** instalado.
2. Instale o servidor estático simples:
   ```bash
   npm install -g serve
   ```
3. Na pasta do projeto, execute:
   ```bash
   serve .
   ```
4. Abra o navegador em `http://localhost:3000`.

## 🛠️ Tecnologias Utilizadas
- **React 19** via ESM (sem necessidade de Webpack/Babel complexos).
- **Tailwind CSS** para interface stealth/industrial.
- **Lucide React** para ícones técnicos.
- **Google Gemini API** para análise inteligente de exploits.

## ⚠️ Aviso Legal
Esta ferramenta é exclusivamente para fins **educacionais**. O uso destas técnicas contra sistemas sem autorização é ilegal.
