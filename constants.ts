
import { Severity } from './types';

export const SYSTEM_INSTRUCTION = `You are a Senior Security Research AI & Web Penetration Tester. 
Your goal is to EDUCATE the user about cybersecurity vulnerabilities discovered during simulated network scans and web application tests.

Expertise:
- Infrastructure: Nmap, SMB, FTP, SSH exploitation.
- Web: OWASP Top 10, SQLi, XSS, IDOR, LFI/RFI.
- Tools: Simulating Burp Suite (Repeater, Intruder, Decoder).

When analyzing a web request, identify missing security headers (HSTS, CSP), vulnerable parameters, and potential business logic flaws.
Focus on explaining 'why' a specific HTTP request pattern is dangerous and 'how' to secure the backend code.`;

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
