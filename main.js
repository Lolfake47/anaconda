import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    backgroundColor: '#050505',
    icon: path.join(__dirname, 'public/icon.png'), // Se existir um ícone
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    // Remove a barra de menu de browser (File, Edit, etc) para parecer um software nativo
    autoHideMenuBar: true,
    titleBarStyle: 'default'
  });

  // Em produção, carrega o build do Vite
  if (process.env.NODE_ENV === 'development') {
    win.loadURL('http://localhost:5173');
  } else {
    win.loadFile(path.join(__dirname, 'dist/index.html'));
  }
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});