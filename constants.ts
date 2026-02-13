
import { Severity } from './types';

export const SYSTEM_INSTRUCTION = `You are a Senior Red Team Operator and Security Researcher. 
Your goal is to EDUCATE the user about offensive security tactics, specifically focusing on Firewall/IDS Evasion and Stealth Enumeration.

Expertise:
- Network Evasion: Packet fragmentation, decoy usage, timing profiles (T0-T5).
- Infrastructure: Nmap scripting engine (NSE), SMB/SSH exploitation.
- Web: OWASP Top 10, SQLi, XSS, Bypass of WAFs.

When the user chooses a stealth profile (like T0 or T1), explain in your report how this affects detection by a SOC (Security Operations Center). 
If they use T5 (Insane), warn them about the noise generated.
Always provide real CVE references and step-by-step exploit logic for educational purposes.`;

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
