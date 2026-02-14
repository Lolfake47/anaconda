import React, { useState, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, Terminal, Search, Activity, Zap, Globe, AlertTriangle, 
  Cpu, RefreshCw, ChevronRight, FolderTree, ExternalLink, 
  Github, Monitor, Copy, Download, HardDrive, Layers, Code, Play, Hash,
  EyeOff, Gauge, Ghost, ShieldAlert, Fingerprint, Lock, ShieldCheck, User,
  Orbit, ChevronDown, ChevronUp, BookOpen, Link, Shuffle, Plus, Trash2, Save,
  Database, Bookmark, Bug, FileCode, Radio, CheckCircle2, X
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, HttpRequest, StealthSettings, Vulnerability, TargetProfile, DiscoveredDirectory } from './types.ts';
import { MOCK_SERVICES, INJECTION_PAYLOADS, COMMON_DIRECTORIES } from './constants.ts';
import { analyzeSecurityFindings } from './services/geminiService.ts';
import { SeverityBadge } from './components/ui/Badge.tsx';

const AnacondaLogo: React.FC<{ className?: string, size?: number }> = ({ className = "", size = 24 }) => (
  <svg 
    width={size} 
    height={size} 
    viewBox="0 0 24 24" 
    fill="none" 
    xmlns="http://www.w3.org/2000/svg" 
    className={`${className} drop-shadow-[0_0_12px_rgba(99,102,241,0.6)]`}
  >
    <path 
      d="M17.5 13.5C18.5 13.5 19.5 14 20.5 15C21.5 16 22 17.5 22 19C22 20.5 21 21.5 19.5 21.5C17.5 21.5 15.5 21 14 20L11 18.5C10.5 18.2 10.2 17.8 10.2 17.2C10.2 16.6 10.5 16.1 11 15.8C12 15.1 13 14.8 14 14.8C15 14.8 16 15.1 17 15.8C17.5 16.1 18 16.1 18.3 15.8C18.6 15.5 18.6 15 18.3 14.7C17.5 13.9 16.5 13.5 15.5 13.5H12C10 13.5 8 14.5 7 16L3.5 21C3 21.7 2.2 22 1.5 22C0.7 22 0 21.3 0 20.5C0 19.8 0.3 19.2 0.8 18.8L4.5 14C5.5 12.5 5.5 10.5 4.5 9L3 6.5C2.5 5.8 2.5 5 3 4.3C3.5 3.6 4.3 3.3 5 3.5C6.5 4 8 3 9 1.5C9.5 0.7 10.3 0.2 11.2 0.1C12.5 -0.1 14 0.2 15 1C16.5 2 17.5 3.5 17.5 5C17.5 6.5 17 8 16 9C15.5 9.5 15.2 10.1 15.2 10.7C15.2 11.3 15.5 11.9 16 12.4C16.4 12.8 16.9 13.1 17.5 13.1V13.5Z" 
      fill="currentColor"
    />
    <path d="M11 4.5L11.5 3.5M13 4.5L12.5 3.5" stroke="#050505" strokeWidth="0.8" strokeLinecap="round"/>
    <circle cx="10.5" cy="5.5" r="0.6" fill="#050505"/>
    <circle cx="13.5" cy="5.5" r="0.6" fill="#050505"/>
  </svg>
);

const VulnerabilityCard: React.FC<{ v: Vulnerability, copyToClipboard: (t: string) => void }> = ({ v, copyToClipboard }) => {
  const [expandedSection, setExpandedSection] = useState<'theory' | 'steps' | null>(null);

  const toggleSection = (section: 'theory' | 'steps') => {
    setExpandedSection(prev => prev === section ? null : section);
  };

  return (
    <div key={v.id} className="bg-[#0f0f0f]/90 backdrop-blur-xl border border-white/5 rounded-[32px] p-8 hover:border-indigo-500/40 transition-all shadow-2xl relative group overflow-hidden animate-in fade-in zoom-in duration-500">
      <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-20 transition-opacity">
        <Terminal className="w-16 h-16 text-indigo-500" />
      </div>
      <div className="flex justify-between items-start mb-6">
        <SeverityBadge severity={v.severity} />
        <div className="px-3 py-1 bg-black rounded-xl border border-indigo-500/30 text-[10px] mono text-indigo-400 font-bold tracking-widest uppercase">
          {v.id}
        </div>
      </div>
      <h4 className="text-2xl font-black text-white mb-3 uppercase tracking-tighter leading-none">{v.name}</h4>
      <p className="text-sm text-zinc-500 mb-8 leading-relaxed font-medium">{v.description}</p>
      
      <div className="space-y-3">
        <div className="border border-white/5 rounded-2xl overflow-hidden bg-black/40">
          <button 
            onClick={() => toggleSection('theory')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors text-left"
          >
            <div className="flex items-center gap-3">
              <BookOpen className="w-4 h-4 text-indigo-500" />
              <span className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Exploit Theory</span>
            </div>
            {expandedSection === 'theory' ? <ChevronUp className="w-4 h-4 text-zinc-600" /> : <ChevronDown className="w-4 h-4 text-zinc-600" />}
          </button>
          {expandedSection === 'theory' && (
            <div className="p-4 pt-0 text-xs text-zinc-400 mono leading-relaxed border-t border-white/5 bg-black/20 animate-in slide-in-from-top-2 duration-300">
              {v.exploitTheory}
            </div>
          )}
        </div>

        <div className="border border-white/5 rounded-2xl overflow-hidden bg-black/40">
          <button 
            onClick={() => toggleSection('steps')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors text-left"
          >
            <div className="flex items-center gap-3">
              <Code className="w-4 h-4 text-indigo-500" />
              <span className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Exploitation Steps</span>
            </div>
            {expandedSection === 'steps' ? <ChevronUp className="w-4 h-4 text-zinc-600" /> : <ChevronDown className="w-4 h-4 text-zinc-600" />}
          </button>
          {expandedSection === 'steps' && (
            <div className="p-4 pt-2 border-t border-white/5 bg-black/20 space-y-3 animate-in slide-in-from-top-2 duration-300">
              {v.exploitationSteps.map((step, idx) => (
                <div key={idx} className="flex items-center justify-between gap-4 bg-black p-3 rounded-xl border border-white/10 group/code hover:border-indigo-500/30 transition-all">
                  <code className="mono text-[11px] text-indigo-300 break-all">{step}</code>
                  <button onClick={() => copyToClipboard(step)} className="shrink-0 p-2 text-zinc-600 hover:text-white transition-colors">
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const DirectoryResultCard: React.FC<{ dir: DiscoveredDirectory }> = ({ dir }) => {
  return (
    <div className="bg-[#0f0f0f]/60 border border-white/5 rounded-2xl p-5 flex items-start gap-4 hover:border-indigo-500/30 transition-all group animate-in fade-in slide-in-from-right-4 duration-500">
      <div className={`p-2.5 rounded-xl border transition-colors ${dir.vulnerability ? 'bg-red-950/20 border-red-500/50 text-red-400' : 'bg-zinc-900 border-white/5 text-zinc-500'}`}>
        {dir.vulnerability ? <Bug className="w-5 h-5" /> : <FolderTree className="w-5 h-5" />}
      </div>
      <div className="flex-1 overflow-hidden">
        <div className="flex items-center justify-between mb-1">
          <span className="mono text-xs text-white font-bold truncate">{dir.path}</span>
          <span className={`text-[10px] px-2 py-0.5 rounded font-black ${dir.status === 200 ? 'bg-green-500/10 text-green-500' : 'bg-yellow-500/10 text-yellow-500'}`}>
            {dir.status}
          </span>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-zinc-600 mb-2">
          <span className="mono">SIZE: {dir.size}</span>
          <span className="mono uppercase">{dir.type}</span>
        </div>
        
        {dir.vulnerability && (
          <div className="mt-3 p-3 bg-black/80 rounded-xl border border-red-500/20 space-y-2 animate-in slide-in-from-top-2 duration-500">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-3 h-3 text-red-500" />
              <span className="text-[10px] font-black text-red-500 uppercase tracking-widest">{dir.vulnerability}</span>
            </div>
            <div className="flex items-center justify-between gap-3 bg-zinc-950 rounded p-2">
              <code className="text-[10px] text-indigo-400 mono break-all">
                {dir.payload}
              </code>
              <Copy className="w-3 h-3 text-zinc-600 cursor-pointer hover:text-white" onClick={() => {}} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'RECON' | 'REPEATER' | 'DECODER' | 'PROFILES'>('RECON');
  const [target, setTarget] = useState('192.168.1.100');
  const [selectedScanType, setSelectedScanType] = useState<ScanType>(ScanType.TCP);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [macRotating, setMacRotating] = useState(false);

  // Profiles State
  const [profiles, setProfiles] = useState<TargetProfile[]>([]);
  const [newProfile, setNewProfile] = useState<Partial<TargetProfile>>({
    name: '',
    target: '',
    commonPorts: '80, 443, 22',
    description: ''
  });
  const [isSavingProfile, setIsSavingProfile] = useState(false);

  const [stealth, setStealth] = useState<StealthSettings>({
    timing: 'T1',
    fragmentation: true,
    decoys: true,
    sourcePortSpoofing: true,
    macSpoofing: true,
    dynamicMacRotation: true,
    traceObfuscation: true,
    identityScrambling: true,
    payloadRandomization: true
  });

  const [currentMac, setCurrentMac] = useState('UNSET');

  const [request, setRequest] = useState<HttpRequest>({
    method: 'GET',
    url: '/api/v1/auth/status',
    headers: 'Host: secure.node.internal\nUser-Agent: Anaconda/4.5 (Lolfake47-Edition)\nConnection: close',
    body: ''
  });
  const [response, setResponse] = useState<string>('Aguardando envio furtivo...');
  const [isSendingRequest, setIsSendingRequest] = useState(false);

  const [decoderInput, setDecoderInput] = useState('');
  const [decoderOutput, setDecoderOutput] = useState('');
  const [isDecoding, setIsDecoding] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem('lf47_profiles');
    if (saved) {
      try {
        setProfiles(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load profiles", e);
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem('lf47_profiles', JSON.stringify(profiles));
  }, [profiles]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const generateMac = () => {
    const vendors = ["00:50:56", "00:0C:29", "00:05:69", "08:00:27", "00:1B:21", "00:16:3E", "B8:27:EB"];
    const prefix = vendors[Math.floor(Math.random() * vendors.length)];
    const suffix = Array.from({length: 3}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(":").toUpperCase();
    return `${prefix}:${suffix}`;
  };

  const handleSendRequest = async () => {
    if (!request.url) return;
    setIsSendingRequest(true);
    addLog(`INTERCEPTOR: Encaminhando pacote ${request.method} via proxy ofuscado...`);
    await new Promise(r => setTimeout(r, 1200));
    setResponse(`HTTP/1.1 200 OK\nDate: Fri, 13 Feb 2026 16:25:00 GMT\nServer: Anaconda/4.5-Stealth\nX-Attribution: UNKNOWN\n\n{\n  "status": "authenticated",\n  "identity": "ghost_operator",\n  "trace": "obfuscated"\n}`);
    addLog(`INTERCEPTOR: Echo recebido com sucesso.`);
    setIsSendingRequest(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    addLog(`CLIPBOARD: Dados extraídos.`);
  };

  const handleDecode = async (mode: 'BASE64' | 'URL') => {
    if (!decoderInput) return;
    setIsDecoding(true);
    addLog(`NEURAL_ENGINE: Iniciando reconstrução de payload...`);
    
    // Simulate complex calculation for aesthetic impact
    await new Promise(r => setTimeout(r, 800));

    try {
      if (mode === 'BASE64') {
        setDecoderOutput(atob(decoderInput));
        addLog(`NEURAL_ENGINE: Reconstrução Base64 finalizada.`);
      } else {
        setDecoderOutput(decodeURIComponent(decoderInput));
        addLog(`NEURAL_ENGINE: Normalização de URL finalizada.`);
      }
    } catch (e) {
      setDecoderOutput(`CRITICAL_ERROR: Falha na decodificação de integridade.`);
      addLog(`NEURAL_ENGINE: ERRO DE INTEGRIDADE DETETADO.`);
    } finally {
      setIsDecoding(false);
    }
  };

  const saveProfile = async () => {
    if (!newProfile.name || !newProfile.target) {
      addLog("PROFILE_ERROR: Nome e IP alvo são obrigatórios.");
      return;
    }
    setIsSavingProfile(true);
    addLog(`PROFILE_SYNC: Sincronizando dados com o repositório local...`);
    
    await new Promise(r => setTimeout(r, 600));

    const profile: TargetProfile = {
      id: Date.now().toString(),
      name: newProfile.name,
      target: newProfile.target,
      commonPorts: newProfile.commonPorts || '80, 443, 22',
      description: newProfile.description || '',
      createdAt: new Date().toISOString()
    };
    setProfiles(prev => [...prev, profile]);
    setNewProfile({ name: '', target: '', commonPorts: '80, 443, 22', description: '' });
    addLog(`PROFILE_SYNC: Perfil '${profile.name}' salvo com sucesso.`);
    setIsSavingProfile(false);
  };

  const deleteProfile = (id: string) => {
    setProfiles(prev => prev.filter(p => p.id !== id));
    addLog(`PROFILE_SYNC: Perfil removido do banco local.`);
  };

  const loadProfile = (p: TargetProfile) => {
    setTarget(p.target);
    setActiveTab('RECON');
    addLog(`PROFILE_LOAD: Carregado alvo ${p.target} do perfil '${p.name}'.`);
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`INIT: Anaconda Red Suite v4.5 - Engagement Start: 2026-02-13`);
    addLog(`OPERATOR: Lolfake47 // TARGET: ${target} // METHOD: ${selectedScanType}`);
    
    if (stealth.macSpoofing) {
      const mac = generateMac();
      setCurrentMac(mac);
      addLog(`EVASION: MAC Spoofing Initialized: ${mac}`);
    }

    const sequence = [
      { p: 10, m: "Preparando payloads ofuscados para 2026..." },
      { p: 25, m: "Contornando Sentinel-AI (IA Defensiva)..." },
      { p: 40, m: `${selectedScanType} baseline enumeration...` },
      { p: 60, m: selectedScanType === ScanType.DIR ? "Iniciando Fuzzing recursivo com payloads de injeção..." : "Profiling de portas e assinaturas de serviço..." },
      { p: 85, m: "Verificando mitigações de vulnerabilidades e patches..." },
      { p: 100, m: "Análise finalizada. Gerando relatório de risco." }
    ];

    const speed = stealth.timing === 'T0' ? 6 : stealth.timing === 'T5' ? 0.2 : 1.5;

    for (const step of sequence) {
      await new Promise(r => setTimeout(r, 700 * speed));
      
      if (stealth.dynamicMacRotation && step.p > 10 && step.p < 100) {
        setMacRotating(true);
        const nextMac = generateMac();
        setCurrentMac(nextMac);
        addLog(`ROTATION: MAC alterado para ${nextMac} (Bypass IDS)`);
        setTimeout(() => setMacRotating(false), 300);
      }

      setScanProgress(step.p);
      addLog(step.m);
    }

    let discoveredDirs: DiscoveredDirectory[] = [];
    let vulnerabilities: Vulnerability[] = [];
    let openPorts: number[] = [];

    if (selectedScanType === ScanType.TCP) {
      openPorts = [22, 80, 443, 445, 3306, 5432, 8080];
      vulnerabilities = [
        {
          id: 'LF47-Z26',
          name: 'SSH Auth Logic Bypass (CVE-2026-XYZ)',
          severity: Severity.CRITICAL,
          description: 'Falha crítica no protocolo de autenticação SSH que permite bypass via pacotes malformados em sistemas unpatched.',
          exploitTheory: 'Utiliza uma Race Condition durante a negociação de cifras GCM para injetar credenciais temporárias na memória.',
          exploitationSteps: [`anaconda-ssh-exploit --target ${target} --cve 2026-XYZ --stealth`],
          exploitUrl: 'https://lolfake47.io/db/cve-2026-xyz',
          mitigation: 'Atualizar OpenSSH para versão 10.1+.'
        }
      ];
    } else if (selectedScanType === ScanType.UDP) {
      openPorts = [53, 161, 500, 4500];
      vulnerabilities = [
        {
          id: 'LF47-U01',
          name: 'SNMP Community String Discovery',
          severity: Severity.HIGH,
          description: 'Strings de comunidade SNMP padrão (public/private) expostas via UDP port 161.',
          exploitTheory: 'Ataque de dicionário otimizado para SNMPv2c permitindo leitura de tabelas de rede e MIBs sensíveis.',
          exploitationSteps: [`anaconda-snmp-walk --target ${target} --community public`],
          exploitUrl: 'https://lolfake47.io/db/snmp-default-strings',
          mitigation: 'Desabilitar SNMPv2c e migrar para SNMPv3 com criptografia forte.'
        }
      ];
    } else if (selectedScanType === ScanType.DIR) {
      discoveredDirs = [
        { path: '/.env', status: 200, size: '2.1kb', type: 'SENSITIVE', vulnerability: 'Information Disclosure', payload: 'Direct Access' },
        { path: '/api/v1/search?q=', status: 200, size: '4.8kb', type: 'ENDPOINT', vulnerability: 'SQL Injection', payload: INJECTION_PAYLOADS.SQLI[1] },
        { path: '/admin/login?next=', status: 200, size: '12kb', type: 'AUTH', vulnerability: 'Reflected XSS', payload: INJECTION_PAYLOADS.XSS[2] },
        { path: '/internal/shell', status: 200, size: '1.5kb', type: 'DEBUG', vulnerability: 'Command Injection', payload: INJECTION_PAYLOADS.CMD[0] },
        { path: '/uploads/legacy/', status: 403, size: '0b', type: 'STORAGE' },
        { path: '/v3/auth/provider', status: 200, size: '8.4kb', type: 'PROVIDER', vulnerability: 'Credential Stuffing Vector', payload: 'Fuzzing-Detected' }
      ];
      vulnerabilities = [
        {
          id: 'LF47-W01',
          name: 'Global Web-Injection Vector',
          severity: Severity.HIGH,
          description: 'Múltiplos endpoints identificados como vulneráveis a injeção (SQL/XSS/CMD).',
          exploitTheory: 'Falta de sanitização em parâmetros de entrada permite execução arbitrária de código e extração de dados.',
          exploitationSteps: ['Usar o módulo REPEATER para testar os payloads listados na seção ENDPOINT INTELLIGENCE.'],
          exploitUrl: 'https://lolfake47.io/db/web-injection-patterns-2026',
          mitigation: 'Implementar WAF de nova geração e sanitização rigorosa via Input-Validation-Library-v5.'
        }
      ];
    }

    const mockResult: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      type: selectedScanType,
      openPorts,
      services: MOCK_SERVICES,
      stealthUsed: stealth,
      directories: discoveredDirs,
      vulnerabilities
    };

    setResults(mockResult);
    setIsScanning(false);
    setIsAnalyzing(true);
    try {
      const aiData = await analyzeSecurityFindings(mockResult);
      setAnalysis(aiData);
    } catch (e) { 
      setAnalysis({
        summary: "IA offline. Análise heurística estima risco CRÍTICO devido à exposição de endpoints sensíveis.",
        riskScore: 92,
        traceRisk: 5,
        recommendations: ["Forçar rotação de MAC", "Utilizar túneis ofuscados para exfiltração"],
        exploitPaths: ["Web Infiltration -> Privilege Escalation -> Persistence"]
      });
    }
    setIsAnalyzing(false);
  }, [target, stealth, selectedScanType]);

  return (
    <div className="h-screen flex flex-col bg-[#050505] text-[#e0e0e0] overflow-hidden">
      <header className="h-14 border-b border-indigo-500/30 bg-[#0a0a0a] flex items-center justify-between px-6 shrink-0 z-20">
        <div className="flex items-center gap-4">
          <div className="relative group cursor-pointer">
            <div className="absolute inset-0 bg-indigo-500/20 blur-xl rounded-full animate-pulse group-hover:bg-indigo-500/40 transition-all"></div>
            <div className="relative bg-indigo-600 p-2 rounded-xl border border-indigo-400/50 flex items-center justify-center overflow-hidden">
              <AnacondaLogo size={24} className="text-white transform group-hover:scale-110 transition-transform" />
            </div>
          </div>
          <div>
            <h1 className="text-xl font-black tracking-tighter text-white uppercase italic leading-none">
              ANACONDA <span className="text-indigo-500">RED_SUITE v4.5</span>
            </h1>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[8px] text-zinc-500 font-bold mono uppercase tracking-widest">OFFENSIVE SIMULATOR // STANDALONE_MODE</span>
            </div>
          </div>
        </div>

        <div className="flex bg-black/50 p-1 rounded-xl border border-white/5">
          {['RECON', 'REPEATER', 'DECODER', 'PROFILES'].map((tab) => (
            <button 
              key={tab}
              onClick={() => setActiveTab(tab as any)}
              className={`px-5 py-1.5 rounded-lg text-[10px] font-black tracking-widest transition-all ${activeTab === tab ? 'bg-indigo-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              {tab}
            </button>
          ))}
        </div>
      </header>

      <main className="flex-1 overflow-hidden flex p-3 gap-3 bg-[#050505] relative">
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-10 pointer-events-none"></div>

        {activeTab === 'RECON' && (
          <>
            <div className="w-72 flex flex-col gap-3 relative z-10 shrink-0">
              <section className="bg-[#0f0f0f]/80 backdrop-blur-xl border border-white/10 rounded-2xl p-5 shadow-2xl overflow-y-auto scrollbar-hide animate-in slide-in-from-left-4 duration-500">
                <h3 className="text-[9px] font-black text-indigo-400 mb-5 flex items-center gap-2 tracking-widest uppercase">
                  <User className="w-3.5 h-3.5" /> Operator: Lolfake47
                </h3>
                
                <div className="space-y-5">
                  <div>
                    <label className="block text-[9px] text-zinc-600 font-bold uppercase mb-2 ml-1">Engagement Target</label>
                    <div className="relative group">
                      <Terminal className="absolute left-3 top-3 w-3.5 h-3.5 text-indigo-600 group-focus-within:text-indigo-400 transition-colors" />
                      <input 
                        type="text" 
                        value={target} 
                        onChange={(e) => setTarget(e.target.value)}
                        className="w-full bg-black border border-white/5 rounded-xl py-2.5 pl-9 pr-4 mono text-xs focus:border-indigo-500 outline-none transition-all placeholder:text-zinc-800"
                        placeholder="IP / Domain"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="block text-[9px] text-zinc-600 font-bold uppercase mb-1 ml-1">Scan Methodology</label>
                    <div className="flex justify-between gap-1 bg-black/50 p-1 rounded-lg border border-white/5">
                      {[ScanType.TCP, ScanType.UDP, ScanType.DIR].map((t) => (
                        <button
                          key={t}
                          onClick={() => setSelectedScanType(t)}
                          className={`flex-1 py-1.5 text-[9px] font-black rounded-md transition-all ${selectedScanType === t ? 'bg-indigo-600 text-white shadow-md' : 'text-zinc-600 hover:text-zinc-400'}`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="block text-[9px] text-zinc-600 font-bold uppercase mb-1 ml-1">Evasion Profile</label>
                    <div className="flex justify-between gap-1 bg-black/50 p-1 rounded-lg border border-white/5">
                      {['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].map((t) => (
                        <button
                          key={t}
                          onClick={() => setStealth(prev => ({ ...prev, timing: t as any }))}
                          className={`flex-1 py-1.5 text-[9px] font-black rounded-md transition-all ${stealth.timing === t ? 'bg-indigo-600 text-white shadow-md' : 'text-zinc-600 hover:text-zinc-400'}`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-[9px] text-zinc-600 font-bold uppercase mb-1 ml-1">Stealth & Ofuscation</label>
                    {[
                      { key: 'macSpoofing', label: 'Static MAC Spoofing', icon: Fingerprint },
                      { key: 'dynamicMacRotation', label: 'Dynamic MAC Rotation', icon: Orbit },
                      { key: 'payloadRandomization', label: 'Injection Fuzzing', icon: Shuffle },
                      { key: 'traceObfuscation', label: 'Advanced Trace Wipe', icon: EyeOff },
                      { key: 'decoys', label: 'AI Honeypot Decoys', icon: Ghost }
                    ].map((opt) => (
                      <label key={opt.key} className="flex items-center justify-between p-2.5 rounded-xl bg-black/60 border border-white/5 cursor-pointer hover:border-indigo-500/30 transition-all hover:bg-black group/opt">
                        <div className="flex items-center gap-2.5">
                          <opt.icon className="w-3.5 h-3.5 text-indigo-500 group-hover/opt:scale-110 transition-transform" />
                          <span className="text-[10px] text-zinc-400 mono">{opt.label}</span>
                        </div>
                        <input 
                          type="checkbox" 
                          checked={(stealth as any)[opt.key]} 
                          onChange={(e) => setStealth(prev => ({ ...prev, [opt.key]: e.target.checked }))}
                          className="accent-indigo-500 w-3.5 h-3.5 cursor-pointer"
                        />
                      </label>
                    ))}
                  </div>

                  <button 
                    onClick={simulateScan}
                    disabled={isScanning}
                    className={`w-full py-3.5 rounded-xl font-black text-[10px] uppercase tracking-[0.2em] flex items-center justify-center gap-2.5 transition-all relative overflow-hidden ${isScanning ? 'bg-zinc-800 text-zinc-500' : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-2xl active:scale-95'}`}
                  >
                    {isScanning && (
                        <div className="absolute inset-0 bg-indigo-500/10 animate-pulse"></div>
                    )}
                    {isScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    {isScanning ? 'EVADING SOC...' : 'EXECUTE ANACONDA'}
                  </button>
                </div>
              </section>

              <section className="flex-1 bg-black/90 border border-white/5 rounded-2xl flex flex-col overflow-hidden shadow-2xl animate-in slide-in-from-bottom-4 duration-700">
                <div className="bg-zinc-900/50 px-3 py-2 border-b border-white/5 flex items-center justify-between">
                  <span className="text-[8px] font-black text-indigo-500 uppercase tracking-widest">Live Trace Logs</span>
                  <Activity className="w-2.5 h-2.5 text-green-500 animate-pulse" />
                </div>
                <div ref={logRef} className="flex-1 p-3 mono text-[9px] overflow-y-auto space-y-1.5 scrollbar-hide scroll-smooth">
                  {logs.length === 0 ? (
                    <div className="text-zinc-800 italic uppercase py-3 text-center">System standby...</div>
                  ) : logs.map((log, i) => (
                    <div key={i} className="flex gap-2 leading-relaxed border-l border-indigo-500/20 pl-2 animate-in fade-in slide-in-from-left-1 duration-300">
                      <span className={log.includes('ALERTA') ? 'text-red-500' : log.includes('ROTATION') ? 'text-yellow-400' : log.includes('EVASION') ? 'text-indigo-400' : 'text-zinc-500'}>
                        {log}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <div className="flex-1 flex flex-col gap-3 overflow-y-auto pr-1 relative z-10">
              {!results && !isScanning && (
                <div className="h-full flex flex-col items-center justify-center text-center animate-in fade-in duration-1000">
                  <div className="p-16 border border-white/5 rounded-[60px] bg-gradient-to-br from-[#0a0a0a] to-[#050505] shadow-2xl relative overflow-hidden group">
                    <div className="absolute inset-0 bg-indigo-600/5 opacity-0 group-hover:opacity-100 transition-opacity duration-1000"></div>
                    <div className="mb-8 relative inline-block transition-transform duration-700 group-hover:scale-105">
                        <div className="absolute inset-0 bg-indigo-500/20 blur-[80px] animate-pulse rounded-full"></div>
                        <AnacondaLogo size={180} className="text-indigo-600 opacity-20 group-hover:opacity-40 transition-opacity duration-1000 relative" />
                    </div>
                    <h2 className="text-5xl font-black mb-4 uppercase tracking-tighter text-white">READY TO ENGAGE</h2>
                    <p className="max-w-md text-xs mono text-zinc-600 leading-relaxed uppercase mx-auto">Standalone Simulator for Kali Linux. Next-Gen Red Team Suite.</p>
                  </div>
                </div>
              )}

              {isScanning && (
                <div className="h-full flex flex-col items-center justify-center space-y-12 animate-in fade-in duration-500">
                  <div className="relative scale-125">
                    <div className="w-48 h-48 rounded-full border-[1px] border-indigo-600/10 border-t-indigo-500 border-t-[2px] animate-spin"></div>
                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                      <div className="animate-pulse mb-1">
                        <AnacondaLogo size={48} className="text-indigo-500" />
                      </div>
                      <span className="text-4xl font-black text-white tabular-nums">{scanProgress}%</span>
                      <span className="text-[9px] text-indigo-400 mono font-black tracking-widest mt-1 uppercase">Infiltrating Node</span>
                    </div>
                  </div>
                  <div className="text-center space-y-3">
                    <div className="bg-black/80 border border-white/5 px-6 py-2 rounded-xl inline-block shadow-xl">
                        <p className={`text-indigo-400 mono text-[10px] font-bold transition-all duration-300 ${macRotating ? 'scale-110 text-yellow-400' : ''}`}>
                        FINGERPRINT: {currentMac}
                        </p>
                    </div>
                    <p className="text-zinc-600 mono text-[9px] uppercase tracking-[0.2em] animate-pulse">Identity Scrambler: {stealth.identityScrambling ? 'ENGAGED' : 'OFF'}</p>
                  </div>
                </div>
              )}

              {results && (
                <div className="space-y-3 pb-8 animate-in fade-in slide-in-from-bottom-8 duration-700">
                  <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-2xl p-4 flex items-center justify-between backdrop-blur-md hover:border-indigo-500/40 transition-all">
                    <div className="flex items-center gap-4">
                      <div className="p-2.5 bg-indigo-500/20 rounded-xl border border-indigo-500/30">
                        <AnacondaLogo size={24} className="text-indigo-500" />
                      </div>
                      <div>
                        <span className="text-[9px] text-indigo-400 font-black block uppercase tracking-widest">{results.type} SESSION ACTIVE</span>
                        <span className="text-xs font-bold text-white uppercase italic tracking-tight">Active session for {target}</span>
                      </div>
                    </div>
                    <div className="text-right px-4 border-l border-white/10">
                      <span className="text-[8px] text-zinc-500 font-bold block uppercase tracking-widest">Node Status</span>
                      <span className="text-[10px] mono text-green-500 font-black uppercase tracking-tighter animate-pulse">BREACH_CONFIRMED</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                    <div className="space-y-3">
                      <h3 className="text-[10px] font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2 mb-1 ml-3">
                        <Bug className="w-3.5 h-3.5" /> Core Vulnerabilities
                      </h3>
                      {results.vulnerabilities.length > 0 ? results.vulnerabilities.map(v => (
                        <VulnerabilityCard key={v.id} v={v} copyToClipboard={copyToClipboard} />
                      )) : (
                        <div className="bg-[#0f0f0f]/40 border border-white/5 rounded-2xl p-10 text-center text-zinc-600 mono text-[10px] uppercase italic tracking-widest">
                           No direct vulnerabilities found.
                        </div>
                      )}
                    </div>

                    <div className="space-y-3">
                      <h3 className="text-[10px] font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2 mb-1 ml-3">
                        <FileCode className="w-3.5 h-3.5" /> Endpoint Intelligence
                      </h3>
                      <div className="grid grid-cols-1 gap-2.5">
                        {results.directories.length > 0 ? results.directories.map((dir, i) => (
                          <DirectoryResultCard key={i} dir={dir} />
                        )) : (
                          <div className="bg-[#0f0f0f]/40 border border-white/5 rounded-2xl p-10 text-center text-zinc-600 mono text-[10px] uppercase italic tracking-widest">
                             Methodology focused on network layers.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-[#0f0f0f] to-[#050505] border border-indigo-500/30 rounded-[32px] p-10 relative overflow-hidden shadow-2xl mt-4 animate-in slide-in-from-bottom-6 duration-700">
                    <div className="absolute top-0 right-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-600 to-transparent"></div>
                    <div className="flex items-center justify-between mb-12">
                      <div>
                        <h3 className="text-3xl font-black text-white mb-1 uppercase italic tracking-tighter">ANACONDA_AI ANALYTICS</h3>
                        <p className="text-[9px] text-indigo-400 mono font-black tracking-[0.4em] uppercase">Tactical Trace Report (2026)</p>
                      </div>
                      <div className="bg-indigo-600 p-4 rounded-[20px] shadow-[0_0_40px_rgba(79,70,229,0.3)] border border-indigo-400/50">
                        <AnacondaLogo size={36} className="text-white" />
                      </div>
                    </div>

                    {isAnalyzing ? (
                      <div className="py-20 flex flex-col items-center justify-center gap-4">
                        <RefreshCw className="w-10 h-10 text-indigo-500 animate-spin" />
                        <span className="text-[9px] text-indigo-400 mono animate-pulse font-black tracking-[0.3em] uppercase">Simulating Forensic Detection...</span>
                      </div>
                    ) : analysis ? (
                      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 animate-in fade-in duration-700">
                        <div className="lg:col-span-7 space-y-8">
                          <div className="space-y-3">
                            <h4 className="text-[9px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Terminal className="w-3.5 h-3.5" /> Tactical Summary
                            </h4>
                            <p className="text-zinc-300 leading-relaxed font-semibold text-lg italic border-l-4 border-indigo-600 pl-6 py-4 bg-white/5 rounded-r-2xl">
                              {analysis.summary}
                            </p>
                          </div>
                          
                          <div className="space-y-4">
                            <h4 className="text-[9px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Layers className="w-3.5 h-3.5" /> Infiltration Paths
                            </h4>
                            <div className="grid grid-cols-1 gap-2.5">
                              {analysis.exploitPaths.map((path, i) => (
                                <div key={i} className="flex items-center gap-4 bg-black/60 p-4 rounded-[20px] border border-white/10 hover:border-indigo-500/30 transition-all group">
                                  <div className="w-8 h-8 rounded-xl bg-indigo-600/20 flex items-center justify-center text-sm font-black text-indigo-500 border border-indigo-500/20">
                                    0{i + 1}
                                  </div>
                                  <span className="text-[11px] text-zinc-400 mono font-bold uppercase tracking-tight">{path}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="lg:col-span-5 flex flex-col gap-6">
                          <div className="bg-black/80 border border-white/5 rounded-[32px] p-8 flex flex-col items-center text-center shadow-2xl">
                            <h4 className="text-[9px] font-black text-zinc-600 uppercase tracking-widest mb-6">Forensic Trace Score</h4>
                            <div className="relative w-36 h-36 mb-6">
                              <svg className="w-full h-full transform -rotate-90">
                                <circle cx="72" cy="72" r="66" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-zinc-900" />
                                <circle cx="72" cy="72" r="66" stroke="currentColor" strokeWidth="8" fill="transparent" 
                                  strokeDasharray={414}
                                  strokeDashoffset={414 - (414 * (analysis.traceRisk ?? 50)) / 100}
                                  className={analysis.traceRisk > 50 ? "text-red-500" : "text-green-500"} 
                                />
                              </svg>
                              <div className="absolute inset-0 flex items-center justify-center flex-col">
                                <span className="text-4xl font-black text-white tabular-nums">{analysis.traceRisk ?? '--'}%</span>
                                <span className="text-[8px] text-zinc-600 font-black uppercase mt-1">Detection Risk</span>
                              </div>
                            </div>
                          </div>

                          <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-[32px] p-8 space-y-6">
                            <h4 className="text-[9px] font-black text-indigo-300 uppercase tracking-widest border-b border-indigo-500/30 pb-4">Anonymity Strategies</h4>
                            <div className="space-y-4">
                              {analysis.recommendations.map((rec, i) => (
                                <div key={i} className="flex gap-4 text-[10px] text-zinc-500">
                                  <Shield className="w-5 h-5 text-green-500 shrink-0" />
                                  <span className="leading-relaxed font-bold uppercase tracking-tight">{rec}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {/* Similar updates for other tabs but keeping concise for the XML block */}
        {activeTab === 'PROFILES' && (
          <div className="flex-1 flex gap-4 animate-in fade-in duration-500 p-2 relative z-10">
            <div className="w-[350px] bg-[#0f0f0f]/90 border border-indigo-500/20 rounded-2xl p-8 flex flex-col shadow-2xl backdrop-blur-xl">
               <h3 className="text-xl font-black text-white uppercase italic mb-6">Create Profile</h3>
               {/* Form content (omitted for brevity but functionally identical to previous) */}
               <div className="flex-1 space-y-5">
                  <input placeholder="Identifier" className="w-full bg-black border border-white/5 rounded-xl py-3 px-5 text-xs outline-none focus:border-indigo-500" value={newProfile.name} onChange={(e) => setNewProfile({...newProfile, name: e.target.value})} />
                  <input placeholder="Target IP" className="w-full bg-black border border-white/5 rounded-xl py-3 px-5 text-xs outline-none focus:border-indigo-500" value={newProfile.target} onChange={(e) => setNewProfile({...newProfile, target: e.target.value})} />
                  <textarea placeholder="Intelligence Notes" className="w-full h-32 bg-black border border-white/5 rounded-xl py-3 px-5 text-xs outline-none focus:border-indigo-500 resize-none" value={newProfile.description} onChange={(e) => setNewProfile({...newProfile, description: e.target.value})} />
               </div>
               <button onClick={saveProfile} className="mt-6 w-full py-4 rounded-xl bg-indigo-600 font-black text-[10px] uppercase tracking-widest text-white shadow-lg">Save Target</button>
            </div>
            <div className="flex-1 overflow-y-auto pr-1">
               <div className="grid grid-cols-2 gap-3">
                  {profiles.map(p => (
                    <div key={p.id} className="bg-[#0f0f0f]/60 border border-white/5 rounded-2xl p-6 group">
                        <div className="flex justify-between items-start mb-4">
                          <Monitor className="w-6 h-6 text-indigo-500" />
                          <Trash2 className="w-4 h-4 text-red-500 cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity" onClick={() => deleteProfile(p.id)} />
                        </div>
                        <h4 className="text-sm font-black text-white uppercase truncate">{p.name}</h4>
                        <p className="text-[10px] text-indigo-400 mono mb-4">{p.target}</p>
                        <button onClick={() => loadProfile(p)} className="w-full py-3 rounded-lg bg-white/5 text-[9px] font-black uppercase tracking-widest border border-white/10 hover:bg-indigo-600 transition-all">Select</button>
                    </div>
                  ))}
               </div>
            </div>
          </div>
        )}

        {/* ... Rest of tabs (REPEATER, DECODER) updated with tighter UI for app mode ... */}
        {activeTab === 'REPEATER' && (
          <div className="flex-1 flex gap-3 animate-in fade-in duration-500 pr-1 relative z-10">
            <div className="flex-1 bg-[#0f0f0f]/90 border border-white/10 rounded-2xl p-8 flex flex-col shadow-2xl">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-[10px] font-black text-indigo-400 uppercase tracking-widest">Packet Interceptor</h3>
                  <div className="flex gap-2">
                    {['GET', 'POST'].map(m => (
                      <button key={m} onClick={() => setRequest(prev => ({...prev, method: m}))} className={`px-4 py-1.5 rounded-lg text-[9px] font-black ${request.method === m ? 'bg-indigo-600' : 'bg-black border border-white/5'}`}>{m}</button>
                    ))}
                  </div>
                </div>
                <input className="bg-black border border-white/5 rounded-xl py-3 px-5 text-xs mb-4 mono text-indigo-300" value={request.url} onChange={(e) => setRequest({...request, url: e.target.value})} />
                <textarea className="flex-1 bg-black border border-white/5 rounded-xl p-6 mono text-xs text-zinc-400 resize-none outline-none" value={request.headers} onChange={(e) => setRequest({...request, headers: e.target.value})} />
                <button onClick={handleSendRequest} className="mt-4 w-full py-4 bg-indigo-600 rounded-xl font-black text-[10px] uppercase tracking-widest">Send Request</button>
            </div>
            <div className="flex-1 bg-black/60 border border-white/5 rounded-2xl p-8 flex flex-col">
                <h3 className="text-[10px] font-black text-indigo-400 uppercase tracking-widest mb-6">Server Echo</h3>
                <pre className="flex-1 mono text-xs text-indigo-400 overflow-auto scrollbar-hide">{response}</pre>
            </div>
          </div>
        )}

        {activeTab === 'DECODER' && (
           <div className="flex-1 bg-[#0f0f0f]/90 border border-white/10 rounded-2xl p-10 flex flex-col shadow-2xl animate-in zoom-in duration-500">
              <h3 className="text-2xl font-black text-white mb-8 uppercase italic">Payload Reconstructor</h3>
              <textarea className="w-full h-48 bg-black border border-white/5 rounded-xl p-5 mono text-xs mb-6 outline-none" placeholder="Drop shellcode..." value={decoderInput} onChange={(e) => setDecoderInput(e.target.value)} />
              <div className="flex gap-4 mb-8">
                <button onClick={() => handleDecode('BASE64')} className="flex-1 py-3 bg-zinc-900 border border-white/5 rounded-lg text-[10px] font-black uppercase">Base64</button>
                <button onClick={() => handleDecode('URL')} className="flex-1 py-3 bg-zinc-900 border border-white/5 rounded-lg text-[10px] font-black uppercase">URL</button>
              </div>
              <div className="flex-1 bg-indigo-900/10 border border-indigo-500/20 rounded-xl p-6 mono text-xs text-indigo-400 break-all overflow-auto">
                {decoderOutput || "Ready for reconstruction..."}
              </div>
           </div>
        )}
      </main>

      <footer className="h-8 bg-[#0a0a0a] border-t border-white/5 px-6 flex items-center justify-between text-[9px] font-black text-zinc-600 shrink-0 z-10">
        <div className="flex gap-8 items-center uppercase tracking-widest">
          <span className="flex items-center gap-2 text-green-600"><ShieldCheck className="w-3 h-3" /> SYSTEM_NATIVE: OK</span>
          <span className="flex items-center gap-2"><Fingerprint className={`w-3 h-3 ${stealth.macSpoofing ? 'text-indigo-500' : ''}`} /> HW_SPOOF: {stealth.macSpoofing ? 'ENGAGED' : 'OFF'}</span>
          <span className="flex items-center gap-2"><User className="w-3 h-3 text-indigo-500" /> OPERATOR: LOLFAKE47</span>
        </div>
        <div className="flex gap-6 mono text-indigo-600 italic">
          <span>{target}</span>
          <span className="animate-pulse">ANACONDA_SECURE_LINK</span>
        </div>
      </footer>
    </div>
  );
};

export default App;