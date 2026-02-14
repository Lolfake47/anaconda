import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './', // Garante que o Electron encontre os assets usando caminhos relativos
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  }
});