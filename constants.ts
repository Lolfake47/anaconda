
import { Severity } from './types';

export const SYSTEM_INSTRUCTION = `You are a Senior Security Research AI. 
Your goal is to EDUCATE the user about cybersecurity vulnerabilities discovered during a simulated scan.
When provided with a list of open ports or directory paths, identify potential vulnerabilities (CVEs), explain the logic behind how they might be exploited (theory only), and provide detailed mitigation strategies.
Always maintain a professional, ethical, and defensive posture. 
Focus on explaining 'why' something is a risk and 'how' to fix it.`;

export const MOCK_SERVICES: Record<number, string> = {
  21: 'FTP (vsftpd 2.3.4)',
  22: 'SSH (OpenSSH 7.2p2)',
  80: 'HTTP (Apache 2.4.18)',
  443: 'HTTPS (Nginx 1.10.3)',
  445: 'SMB (Samba 4.3.11)',
  3306: 'MySQL 5.7.12',
  8080: 'HTTP-Proxy (Tomcat 8.5)'
};

export const COMMON_DIRECTORIES = [
  '/admin',
  '/config',
  '/backup',
  '/uploads',
  '/.git',
  '/phpinfo.php',
  '/etc/passwd',
  '/var/log'
];
