import React, { useState, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, Terminal, Search, Activity, Zap, Globe, AlertTriangle, 
  Cpu, RefreshCw, ChevronRight, FolderTree, ExternalLink, 
  Github, Monitor, Copy, Download, HardDrive, Layers, Code, Play, Hash,
  EyeOff, Gauge, Ghost, ShieldAlert, Fingerprint, Lock, ShieldCheck, User,
  Orbit, ChevronDown, ChevronUp, BookOpen, Link, Shuffle, Plus, Trash2, Save,
  Database, Bookmark, Bug, FileCode, Radio
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, HttpRequest, StealthSettings, Vulnerability, TargetProfile, DiscoveredDirectory } from './types.ts';
import { MOCK_SERVICES, INJECTION_PAYLOADS, COMMON_DIRECTORIES } from './constants.ts';
import { analyzeSecurityFindings } from './services/geminiService.ts';
import { SeverityBadge } from './components/ui/Badge.tsx';

// Custom Anaconda Logo Component
const AnacondaLogo: React.FC<{ className?: string, size?: number }> = ({ className = "", size = 24 }) => (
  <svg 
    width={size} 
    height={size} 
    viewBox="0 0 24 24" 
    fill="none" 
    xmlns="http://www.w3.org/2000/svg" 
    className={`${className} drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]`}
  >
    <path 
      d="M12 2C10.5 2 9 3 8 4.5C7 6 7 8 8 9.5C8.5 10.3 9.3 11 10.2 11.5L7 18C6.5 19 7 20 8 20.5C9.5 21.3 11.2 21.8 13 22C16 22.3 19 21 21 18.5C22.5 16.5 22.5 13.5 21 11.5C20.5 10.8 19.8 10.3 19 10L16 9C15.5 8.8 15 8.5 14.5 8C14 7.5 13.8 7 13.8 6.5C13.8 6 14 5.5 14.5 5.2C15 4.9 15.6 4.8 16.2 5L17.5 5.5C18 5.7 18.5 5.5 18.7 5C19 4.5 18.8 4 18.3 3.8L17 3.3C15.5 2.5 13.5 2 12 2ZM12 4C12.8 4 13.5 4.3 14 4.8C14.5 5.3 14.8 6 14.8 6.5C14.8 7.3 14.5 8 14 8.5C13.5 9 12.8 9.3 12 9.3C11.2 9.3 10.5 9 10 8.5C9.5 8 9.2 7.3 9.2 6.5C9.2 5.7 9.5 5 10 4.5C10.5 4 11.2 4 12 4ZM10 13C11 12.5 12 12.3 13 12.3C14.5 12.3 16 12.8 17.2 13.8C18.4 14.8 19 16.2 19 17.5C19 18.8 18.4 20 17.2 20.8C16 21.6 14.5 22 13 22C11.5 22 10.1 21.6 9 20.9L11.5 16C11.8 15.4 11.8 14.6 11.5 14L10 13Z" 
      fill="currentColor"
    />
    <circle cx="10" cy="6.5" r="0.8" fill="#050505" />
    <circle cx="14" cy="6.5" r="0.8" fill="#050505" />
    <path d="M11 8.5C11 8.5 11.5 9 12 9C12.5 9 13 8.5 13 8.5" stroke="#050505" strokeWidth="0.5" strokeLinecap="round" />
  </svg>
);

const VulnerabilityCard: React.FC<{ v: Vulnerability, copyToClipboard: (t: string) => void }> = ({ v, copyToClipboard }) => {
  const [expandedSection, setExpandedSection] = useState<'theory' | 'steps' | 'url' | null>(null);

  const toggleSection = (section: 'theory' | 'steps' | 'url') => {
    setExpandedSection(prev => prev === section ? null : section);
  };

  return (
    <div key={v.id} className="bg-[#0f0f0f]/90 backdrop-blur-xl border border-white/5 rounded-[32px] p-8 hover:border-indigo-500/40 transition-all shadow-2xl relative group overflow-hidden">
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
            <div className="p-4 pt-0 text-xs text-zinc-400 mono leading-relaxed border-t border-white/5 bg-black/20">
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
            <div className="p-4 pt-2 border-t border-white/5 bg-black/20 space-y-3">
              {v.exploitationSteps.map((step, idx) => (
                <div key={idx} className="flex items-center justify-between gap-4 bg-black p-3 rounded-xl border border-white/10 group/code">
                  <code className="mono text-[11px] text-indigo-300 break-all">{step}</code>
                  <button onClick={() => copyToClipboard(step)} className="shrink-0 p-2 text-zinc-600 hover:text-white transition-colors">
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="border border-white/5 rounded-2xl overflow-hidden bg-black/40">
          <button 
            onClick={() => toggleSection('url')}
            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors text-left"
          >
            <div className="flex items-center gap-3">
              <Link className="w-4 h-4 text-indigo-500" />
              <span className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Exploit Source</span>
            </div>
            {expandedSection === 'url' ? <ChevronUp className="w-4 h-4 text-zinc-600" /> : <ChevronDown className="w-4 h-4 text-zinc-600" />}
          </button>
          {expandedSection === 'url' && (
            <div className="p-4 pt-2 border-t border-white/5 bg-black/20">
              <a 
                href={v.exploitUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center justify-between bg-black p-3 rounded-xl border border-white/10 text-indigo-400 hover:text-indigo-300 transition-colors group/link"
              >
                <span className="mono text-[11px] truncate mr-4">{v.exploitUrl}</span>
                <ExternalLink className="w-3.5 h-3.5 shrink-0" />
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const DirectoryResultCard: React.FC<{ dir: DiscoveredDirectory }> = ({ dir }) => {
  return (
    <div className="bg-[#0f0f0f]/60 border border-white/5 rounded-2xl p-5 flex items-start gap-4 hover:border-indigo-500/30 transition-all group">
      <div className={`p-2.5 rounded-xl border ${dir.vulnerability ? 'bg-red-950/20 border-red-500/50 text-red-400' : 'bg-zinc-900 border-white/5 text-zinc-500'}`}>
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
          <div className="mt-3 p-3 bg-black/80 rounded-xl border border-red-500/20 space-y-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-3 h-3 text-red-500" />
              <span className="text-[10px] font-black text-red-500 uppercase tracking-widest">{dir.vulnerability}</span>
            </div>
            <code className="block p-2 bg-zinc-950 rounded text-[10px] text-indigo-400 mono break-all">
              {dir.payload}
            </code>
          </div>
        )}
      </div>
    </div>
  );
};

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'RECON' | 'REPEATER' | 'DECODER' | 'PROFILES'>('RECON');
  const [target, setTarget] = useState('192.168.1.100');
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

  const logRef = useRef<HTMLDivElement>(null);

  // Load profiles from LocalStorage on mount
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

  // Save profiles to LocalStorage whenever they change
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
    await new Promise(r => setTimeout(r, 1500));
    setResponse(`HTTP/1.1 200 OK\nDate: Fri, 13 Feb 2026 16:25:00 GMT\nServer: Anaconda/4.5-Stealth\nX-Attribution: UNKNOWN\n\n{\n  "status": "authenticated",\n  "identity": "ghost_operator",\n  "trace": "obfuscated"\n}`);
    addLog(`INTERCEPTOR: Echo recebido com sucesso.`);
    setIsSendingRequest(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    addLog(`CLIPBOARD: Dados extraídos.`);
  };

  const handleDecode = (mode: 'BASE64' | 'URL') => {
    try {
      if (mode === 'BASE64') {
        setDecoderOutput(atob(decoderInput));
        addLog(`NEURAL_ENGINE: Reconstrução Base64 finalizada.`);
      } else {
        setDecoderOutput(decodeURIComponent(decoderInput));
        addLog(`NEURAL_ENGINE: Normalização de URL finalizada.`);
      }
    } catch (e) {
      setDecoderOutput(`CRITICAL_ERROR: Falha na decodificação.`);
      addLog(`NEURAL_ENGINE: ERRO DE INTEGRIDADE.`);
    }
  };

  // Profile Management Functions
  const saveProfile = () => {
    if (!newProfile.name || !newProfile.target) {
      addLog("PROFILE_ERROR: Nome e IP alvo são obrigatórios.");
      return;
    }
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
    addLog(`OPERATOR: Lolfake47 // TARGET: ${target}`);
    
    if (stealth.macSpoofing) {
      const mac = generateMac();
      setCurrentMac(mac);
      addLog(`EVASION: MAC Spoofing Initialized: ${mac}`);
    }

    const sequence = [
      { p: 10, m: "Preparando payloads ofuscados para 2026..." },
      { p: 25, m: "Contornando Sentinel-AI (IA Defensiva)..." },
      { p: 40, m: "Port enumeration & service profiling..." },
      { p: 60, m: "Deep Endpoint Fuzzing (SQLi/XSS/CMD Probe)..." },
      { p: 80, m: "Verificando mitigações de vulnerabilidades (Patches 2026)..." },
      { p: 100, m: "Análise finalizada. Gerando relatório de risco." }
    ];

    const speed = stealth.timing === 'T0' ? 6 : stealth.timing === 'T5' ? 0.2 : 1.5;

    for (const step of sequence) {
      await new Promise(r => setTimeout(r, 700 * speed));
      
      if (stealth.dynamicMacRotation && step.p > 10 && step.p < 100) {
        setMacRotating(true);
        const nextMac = generateMac();
        setCurrentMac(nextMac);
        addLog(`ROTATION: MAC alterado para ${nextMac}`);
        setTimeout(() => setMacRotating(false), 300);
      }

      setScanProgress(step.p);
      addLog(step.m);
    }

    // Advanced Directory and Injection Discovery
    const discoveredDirs: DiscoveredDirectory[] = [
      { path: '/.env', status: 200, size: '1.2kb', type: 'FILE', vulnerability: 'Information Disclosure' },
      { path: '/api/v1/debug', status: 200, size: '4.5kb', type: 'ENDPOINT', vulnerability: 'Command Injection', payload: INJECTION_PAYLOADS.CMD[0] },
      { path: '/graphql', status: 200, size: '0.8kb', type: 'GATEWAY', vulnerability: 'SQL Injection', payload: INJECTION_PAYLOADS.SQLI[1] },
      { path: '/admin/login', status: 200, size: '12kb', type: 'UI', vulnerability: 'Stored XSS', payload: INJECTION_PAYLOADS.XSS[2] },
      { path: '/config/backup.sql', status: 200, size: '45mb', type: 'DATA' }
    ];

    const mockResult: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      type: ScanType.TCP,
      openPorts: [80, 443, 22, 5432],
      services: MOCK_SERVICES,
      stealthUsed: stealth,
      directories: discoveredDirs,
      vulnerabilities: [
        {
          id: 'LF47-Z01',
          name: 'SSH Zero-Day (2026.02 Logic Bypass)',
          severity: Severity.CRITICAL,
          description: 'Falha crítica na troca de chaves que permite bypass de autenticação em sistemas com patch inferior a 13-02-2026.',
          exploitTheory: 'A exploração utiliza uma vulnerabilidade de Race Condition no buffer de memória do daemon SSH durante a handshake.',
          exploitationSteps: [`anaconda-exploit --ssh --target ${target} --stealth --rotate-mac`],
          exploitUrl: 'https://lolfake47.io/database/zday-2026-ssh',
          mitigation: 'Aplicar Patch Emergencial de 13-02-2026.'
        }
      ]
    };

    setResults(mockResult);
    setIsScanning(false);
    setIsAnalyzing(true);
    try {
      const aiData = await analyzeSecurityFindings(mockResult);
      setAnalysis(aiData);
    } catch (e) { 
      setAnalysis({
        summary: "Falha na análise via IA. Risco manual estimado como CRÍTICO devido à falta de mitigação na data especificada.",
        riskScore: 98,
        traceRisk: 2,
        recommendations: ["Forçar rotação de MAC a cada 30s", "Usar túneis DNS para exfiltração"],
        exploitPaths: ["SSH Bypass -> Root Access -> Persistence"]
      });
    }
    setIsAnalyzing(false);
  }, [target, stealth]);

  return (
    <div className="min-h-screen flex flex-col bg-[#050505] text-[#e0e0e0]">
      <header className="h-16 border-b border-indigo-500/30 bg-[#0a0a0a] flex items-center justify-between px-6 shrink-0 z-20">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-indigo-500/20 blur-lg rounded-full animate-pulse"></div>
            <div className="relative bg-indigo-600 p-2.5 rounded-xl border border-indigo-400/50 flex items-center justify-center">
              <AnacondaLogo size={24} className="text-white" />
            </div>
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tighter text-white uppercase italic leading-none">
              ANACONDA <span className="text-indigo-500">RED_SUITE v4.5</span>
            </h1>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[9px] text-zinc-500 font-bold mono uppercase tracking-widest">OFFENSIVE SIMULATOR // DEV: LOLFAKE47</span>
            </div>
          </div>
        </div>

        <div className="flex bg-black/50 p-1 rounded-xl border border-white/5">
          {['RECON', 'REPEATER', 'DECODER', 'PROFILES'].map((tab) => (
            <button 
              key={tab}
              onClick={() => setActiveTab(tab as any)}
              className={`px-6 py-2 rounded-lg text-xs font-black tracking-widest transition-all ${activeTab === tab ? 'bg-indigo-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              {tab}
            </button>
          ))}
        </div>
      </header>

      <main className="flex-1 overflow-hidden flex p-4 gap-4 bg-[#050505] relative">
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-10 pointer-events-none"></div>

        {activeTab === 'RECON' && (
          <>
            <div className="w-80 flex flex-col gap-4 relative z-10 shrink-0">
              <section className="bg-[#0f0f0f]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-6 shadow-2xl overflow-y-auto scrollbar-hide">
                <h3 className="text-[10px] font-black text-indigo-400 mb-6 flex items-center gap-2 tracking-widest uppercase">
                  <User className="w-4 h-4" /> Operator: Lolfake47
                </h3>
                
                <div className="space-y-6">
                  <div>
                    <label className="block text-[10px] text-zinc-600 font-bold uppercase mb-2 ml-1">Engagement Target</label>
                    <div className="relative">
                      <Terminal className="absolute left-3 top-3.5 w-4 h-4 text-indigo-600" />
                      <input 
                        type="text" 
                        value={target} 
                        onChange={(e) => setTarget(e.target.value)}
                        className="w-full bg-black border border-white/5 rounded-2xl py-3.5 pl-10 pr-4 mono text-sm focus:border-indigo-500 outline-none transition-all"
                      />
                    </div>
                  </div>

                  <div className="space-y-3">
                    <label className="block text-[10px] text-zinc-600 font-bold uppercase mb-1 ml-1">Evasion Profile</label>
                    <div className="flex justify-between gap-1 bg-black/50 p-1 rounded-xl border border-white/5">
                      {['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].map((t) => (
                        <button
                          key={t}
                          onClick={() => setStealth(prev => ({ ...prev, timing: t as any }))}
                          className={`flex-1 py-2 text-[10px] font-black rounded-lg transition-all ${stealth.timing === t ? 'bg-indigo-600 text-white shadow-md' : 'text-zinc-600 hover:text-zinc-400'}`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="block text-[10px] text-zinc-600 font-bold uppercase mb-1 ml-1">Stealth & Ofuscation</label>
                    {[
                      { key: 'macSpoofing', label: 'Static MAC Spoofing', icon: Fingerprint },
                      { key: 'dynamicMacRotation', label: 'Dynamic MAC Rotation', icon: Orbit },
                      { key: 'payloadRandomization', label: 'Injection Fuzzing', icon: Shuffle },
                      { key: 'traceObfuscation', label: 'Advanced Trace Wipe', icon: EyeOff },
                      { key: 'decoys', label: 'AI Honeypot Decoys', icon: Ghost }
                    ].map((opt) => (
                      <label key={opt.key} className="flex items-center justify-between p-3 rounded-2xl bg-black/60 border border-white/5 cursor-pointer hover:border-indigo-500/30 transition-all">
                        <div className="flex items-center gap-3">
                          <opt.icon className="w-4 h-4 text-indigo-500" />
                          <span className="text-[11px] text-zinc-400 mono">{opt.label}</span>
                        </div>
                        <input 
                          type="checkbox" 
                          checked={(stealth as any)[opt.key]} 
                          onChange={(e) => setStealth(prev => ({ ...prev, [opt.key]: e.target.checked }))}
                          className="accent-indigo-500 w-4 h-4"
                        />
                      </label>
                    ))}
                  </div>

                  <button 
                    onClick={simulateScan}
                    disabled={isScanning}
                    className={`w-full py-4 rounded-2xl font-black text-xs uppercase tracking-[0.2em] flex items-center justify-center gap-3 transition-all ${isScanning ? 'bg-zinc-800 text-zinc-500' : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-2xl shadow-indigo-500/20'}`}
                  >
                    {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {isScanning ? 'EVADING SOC...' : 'EXECUTE ANACONDA'}
                  </button>
                </div>
              </section>

              <section className="flex-1 bg-black/90 border border-white/5 rounded-3xl flex flex-col overflow-hidden shadow-2xl">
                <div className="bg-zinc-900/50 px-4 py-2.5 border-b border-white/5 flex items-center justify-between">
                  <span className="text-[9px] font-black text-indigo-500 uppercase tracking-widest">Live Trace Logs</span>
                  <Activity className="w-3 h-3 text-green-500 animate-pulse" />
                </div>
                <div ref={logRef} className="flex-1 p-4 mono text-[10px] overflow-y-auto space-y-2 scrollbar-hide">
                  {logs.length === 0 ? (
                    <div className="text-zinc-800 italic uppercase py-4 text-center">System standby...</div>
                  ) : logs.map((log, i) => (
                    <div key={i} className="flex gap-2 leading-relaxed border-l-2 border-indigo-500/20 pl-2">
                      <span className={log.includes('ALERTA') ? 'text-red-500' : log.includes('ROTATION') ? 'text-yellow-400' : log.includes('EVASION') ? 'text-indigo-400' : 'text-zinc-500'}>
                        {log}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <div className="flex-1 flex flex-col gap-4 overflow-y-auto pr-2 relative z-10">
              {!results && !isScanning && (
                <div className="h-full flex flex-col items-center justify-center text-center">
                  <div className="p-20 border border-white/5 rounded-[60px] bg-gradient-to-br from-[#0a0a0a] to-[#050505] shadow-2xl relative overflow-hidden group">
                    <div className="absolute inset-0 bg-indigo-600/5 opacity-0 group-hover:opacity-100 transition-opacity duration-1000"></div>
                    <AnacondaLogo size={200} className="text-indigo-600 opacity-20 mb-8 mx-auto animate-pulse" />
                    <h2 className="text-5xl font-black mb-4 uppercase tracking-tighter text-white">READY TO ENGAGE</h2>
                    <p className="max-w-md text-sm mono text-zinc-600 leading-relaxed uppercase">Next-Gen Red Team Simulator for 2026. Bypassing AI-Sentinel & Forensic Scanners.</p>
                  </div>
                </div>
              )}

              {isScanning && (
                <div className="h-full flex flex-col items-center justify-center space-y-12">
                  <div className="relative scale-150">
                    <div className="w-48 h-48 rounded-full border-[1px] border-indigo-600/10 border-t-indigo-500 animate-spin"></div>
                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                      <span className="text-5xl font-black text-white">{scanProgress}%</span>
                      <span className="text-[10px] text-indigo-400 mono font-black tracking-widest mt-2 uppercase">Tracing Path</span>
                    </div>
                  </div>
                  <div className="text-center space-y-2">
                    <p className={`text-indigo-400 mono text-xs font-bold transition-all duration-300 ${macRotating ? 'scale-110 text-yellow-400 shadow-[0_0_15px_rgba(250,204,21,0.5)]' : ''}`}>
                      CURRENT MAC: {currentMac}
                    </p>
                    <p className="text-zinc-600 mono text-[10px] uppercase">Rotation Shield: {stealth.dynamicMacRotation ? 'ACTIVE' : 'IDLE'}</p>
                  </div>
                </div>
              )}

              {results && (
                <div className="space-y-4 pb-12 animate-in fade-in slide-in-from-bottom-8 duration-700">
                  <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-3xl p-5 flex items-center justify-between backdrop-blur-md">
                    <div className="flex items-center gap-4">
                      <div className="p-3 bg-green-500/20 rounded-2xl border border-green-500/30">
                        <Radio className="w-6 h-6 text-green-500" />
                      </div>
                      <div>
                        <span className="text-[10px] text-indigo-400 font-black block uppercase tracking-widest">Infiltration Intelligence // 2026.02.13</span>
                        <span className="text-sm font-bold text-white uppercase italic tracking-tight">Active session for {target}</span>
                      </div>
                    </div>
                    <div className="text-right px-6 border-l border-white/10">
                      <span className="text-[9px] text-zinc-500 font-bold block uppercase tracking-widest">Discovery State</span>
                      <span className="text-xs mono text-green-500 font-black uppercase">COMPLETED</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    {/* Vulnerabilities Section */}
                    <div className="space-y-4">
                      <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2 mb-2 ml-4">
                        <Bug className="w-4 h-4" /> Core Vulnerabilities
                      </h3>
                      {results.vulnerabilities.map(v => (
                        <VulnerabilityCard key={v.id} v={v} copyToClipboard={copyToClipboard} />
                      ))}
                    </div>

                    {/* Endpoint Fuzzing Section */}
                    <div className="space-y-4">
                      <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2 mb-2 ml-4">
                        <FileCode className="w-4 h-4" /> Endpoint Intelligence
                      </h3>
                      <div className="grid grid-cols-1 gap-3">
                        {results.directories.map((dir, i) => (
                          <DirectoryResultCard key={i} dir={dir} />
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-[#0f0f0f] to-[#050505] border border-indigo-500/30 rounded-[40px] p-12 relative overflow-hidden shadow-2xl">
                    <div className="absolute top-0 right-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-600 to-transparent"></div>
                    <div className="flex items-center justify-between mb-16">
                      <div>
                        <h3 className="text-4xl font-black text-white mb-2 uppercase italic tracking-tighter">ANACONDA_AI ANALYTICS</h3>
                        <p className="text-xs text-indigo-400 mono font-black tracking-[0.5em] uppercase">Deep Fuzzing & Trace Report (2026-02-13)</p>
                      </div>
                      <div className="bg-indigo-600 p-5 rounded-[24px] shadow-[0_0_60px_rgba(79,70,229,0.4)] border border-indigo-400/50">
                        <AnacondaLogo size={48} className="text-white" />
                      </div>
                    </div>

                    {isAnalyzing ? (
                      <div className="py-24 flex flex-col items-center justify-center gap-6">
                        <RefreshCw className="w-12 h-12 text-indigo-500 animate-spin" />
                        <span className="text-xs text-indigo-400 mono animate-pulse font-black tracking-[0.3em] uppercase">Simulating Forensic Detection...</span>
                      </div>
                    ) : analysis ? (
                      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                        <div className="lg:col-span-7 space-y-10">
                          <div className="space-y-4">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Terminal className="w-4 h-4" /> Tactical Summary
                            </h4>
                            <p className="text-zinc-300 leading-relaxed font-semibold text-xl italic border-l-8 border-indigo-600 pl-8 py-6 bg-white/5 rounded-r-3xl">
                              {analysis.summary}
                            </p>
                          </div>
                          
                          <div className="space-y-6">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Layers className="w-4 h-4" /> Infiltration Paths
                            </h4>
                            <div className="grid grid-cols-1 gap-3">
                              {analysis.exploitPaths.map((path, i) => (
                                <div key={i} className="flex items-center gap-6 bg-black/60 p-5 rounded-[24px] border border-white/10 hover:border-indigo-500/30 transition-all group">
                                  <div className="w-10 h-10 rounded-2xl bg-indigo-600/20 flex items-center justify-center text-lg font-black text-indigo-500 border border-indigo-500/20 group-hover:scale-110 transition-transform">
                                    0{i + 1}
                                  </div>
                                  <span className="text-sm text-zinc-400 mono font-bold uppercase tracking-tight">{path}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="lg:col-span-5 flex flex-col gap-8">
                          <div className="bg-black/80 border border-white/5 rounded-[40px] p-10 flex flex-col items-center text-center shadow-2xl">
                            <h4 className="text-[10px] font-black text-zinc-600 uppercase tracking-widest mb-8">Forensic Trace Score</h4>
                            <div className="relative w-48 h-48 mb-8">
                              <svg className="w-full h-full transform -rotate-90">
                                <circle cx="96" cy="96" r="88" stroke="currentColor" strokeWidth="10" fill="transparent" className="text-zinc-900" />
                                <circle cx="96" cy="96" r="88" stroke="currentColor" strokeWidth="10" fill="transparent" 
                                  strokeDasharray={552}
                                  strokeDashoffset={552 - (552 * (analysis.traceRisk ?? 50)) / 100}
                                  className={analysis.traceRisk > 50 ? "text-red-500 shadow-[0_0_20px_rgba(239,68,68,0.5)]" : "text-green-500 shadow-[0_0_20px_rgba(34,197,94,0.5)]"} 
                                />
                              </svg>
                              <div className="absolute inset-0 flex items-center justify-center flex-col">
                                <span className="text-6xl font-black text-white">{analysis.traceRisk ?? '--'}%</span>
                                <span className="text-[10px] text-zinc-600 font-black uppercase mt-2">Detection Risk</span>
                              </div>
                            </div>
                            <span className="text-[11px] mono text-indigo-400 font-black uppercase tracking-[0.3em]">
                              {analysis.traceRisk < 15 ? "ANONYMITY_SHIELD_V4" : "REVEAL_LEVEL_CAUTION"}
                            </span>
                          </div>

                          <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-[40px] p-10 space-y-8">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest border-b border-indigo-500/30 pb-6">Anonymity Strategies</h4>
                            <div className="space-y-5">
                              {analysis.recommendations.map((rec, i) => (
                                <div key={i} className="flex gap-5 text-xs text-zinc-500">
                                  <Shield className="w-6 h-6 text-green-500 shrink-0" />
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

        {activeTab === 'PROFILES' && (
          <div className="flex-1 flex gap-6 overflow-hidden animate-in fade-in duration-500 relative z-10 p-4">
            <div className="w-[450px] shrink-0 bg-[#0f0f0f]/90 border border-indigo-500/20 rounded-[40px] p-10 flex flex-col shadow-2xl backdrop-blur-xl">
              <h3 className="text-2xl font-black text-white mb-8 uppercase italic tracking-tighter flex items-center gap-4">
                <Plus className="w-8 h-8 text-indigo-500" /> Create Node Profile
              </h3>
              
              <div className="space-y-6 flex-1">
                <div>
                  <label className="block text-[10px] text-zinc-500 font-black uppercase mb-2 tracking-widest ml-1">Profile Identifier</label>
                  <input 
                    type="text" 
                    placeholder="e.g. Internal Financial Server"
                    className="w-full bg-black border border-white/5 rounded-2xl py-4 px-6 mono text-sm focus:border-indigo-500 outline-none transition-all placeholder:text-zinc-800"
                    value={newProfile.name}
                    onChange={(e) => setNewProfile({...newProfile, name: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-zinc-500 font-black uppercase mb-2 tracking-widest ml-1">Engagement Target (IP/Host)</label>
                  <input 
                    type="text" 
                    placeholder="10.0.0.5 or node.secure.int"
                    className="w-full bg-black border border-white/5 rounded-2xl py-4 px-6 mono text-sm focus:border-indigo-500 outline-none transition-all placeholder:text-zinc-800"
                    value={newProfile.target}
                    onChange={(e) => setNewProfile({...newProfile, target: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-zinc-500 font-black uppercase mb-2 tracking-widest ml-1">Critical Port List</label>
                  <input 
                    type="text" 
                    placeholder="22, 80, 443, 3306"
                    className="w-full bg-black border border-white/5 rounded-2xl py-4 px-6 mono text-sm focus:border-indigo-500 outline-none transition-all placeholder:text-zinc-800"
                    value={newProfile.commonPorts}
                    onChange={(e) => setNewProfile({...newProfile, commonPorts: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-zinc-500 font-black uppercase mb-2 tracking-widest ml-1">Strategic Intelligence / Notes</label>
                  <textarea 
                    placeholder="Legacy OS, possibly unpatched..."
                    className="w-full h-32 bg-black border border-white/5 rounded-2xl py-4 px-6 mono text-sm focus:border-indigo-500 outline-none transition-all resize-none placeholder:text-zinc-800"
                    value={newProfile.description}
                    onChange={(e) => setNewProfile({...newProfile, description: e.target.value})}
                  />
                </div>
              </div>

              <button 
                onClick={saveProfile}
                className="mt-8 w-full bg-indigo-600 hover:bg-indigo-500 py-5 rounded-[24px] font-black uppercase text-xs tracking-[0.3em] flex items-center justify-center gap-3 shadow-2xl shadow-indigo-600/30 transition-all text-white"
              >
                <Save className="w-5 h-5" />
                COMMIT TO DATABASE
              </button>
            </div>

            <div className="flex-1 flex flex-col gap-6 overflow-hidden">
              <div className="flex items-center justify-between px-4">
                <h3 className="text-xs font-black text-indigo-400 uppercase tracking-[0.4em] flex items-center gap-3">
                  <Database className="w-5 h-5" /> Target Repository // LF47
                </h3>
                <span className="text-[10px] text-zinc-600 font-bold mono">ENTRIES: {profiles.length}</span>
              </div>

              <div className="flex-1 overflow-y-auto scrollbar-hide pr-2">
                {profiles.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center opacity-20 text-center grayscale">
                    <Bookmark className="w-32 h-32 mb-6" />
                    <p className="text-sm font-black uppercase tracking-widest">Repository empty</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {profiles.map(p => (
                      <div key={p.id} className="bg-[#0f0f0f]/60 border border-white/5 rounded-[32px] p-8 flex flex-col group hover:border-indigo-500/40 transition-all">
                        <div className="flex justify-between items-start mb-6">
                          <div className="bg-indigo-600/20 p-3 rounded-2xl border border-indigo-500/30">
                            <Monitor className="w-6 h-6 text-indigo-500" />
                          </div>
                          <button 
                            onClick={() => deleteProfile(p.id)}
                            className="p-3 bg-red-500/10 text-red-500 rounded-xl border border-red-500/20 opacity-0 group-hover:opacity-100 transition-all hover:bg-red-500/20"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                        <h4 className="text-xl font-black text-white mb-1 uppercase tracking-tighter truncate">{p.name}</h4>
                        <p className="text-xs text-indigo-400 mono font-bold mb-4">{p.target}</p>
                        <div className="flex-1 space-y-4">
                          <div className="bg-black/40 rounded-2xl p-4 border border-white/5">
                            <span className="text-[9px] text-zinc-600 font-black uppercase block mb-1 tracking-widest">Active Services</span>
                            <span className="text-[11px] mono text-zinc-400">{p.commonPorts}</span>
                          </div>
                          {p.description && (
                            <p className="text-[11px] text-zinc-500 italic leading-relaxed px-1">
                              "{p.description}"
                            </p>
                          )}
                        </div>
                        <button 
                          onClick={() => loadProfile(p)}
                          className="mt-6 w-full bg-white/5 hover:bg-indigo-600/20 border border-white/10 hover:border-indigo-500/40 py-4 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all text-zinc-400 hover:text-white flex items-center justify-center gap-2"
                        >
                          <Play className="w-3 h-3" />
                          Engage Profile
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'REPEATER' && (
          <div className="flex-1 flex gap-4 animate-in fade-in duration-500 pr-2 relative z-10">
            <div className="flex-1 flex flex-col gap-4">
              <div className="bg-[#0f0f0f]/90 border border-white/10 rounded-[40px] p-12 flex-1 flex flex-col shadow-2xl">
                <div className="flex items-center justify-between mb-8">
                  <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" /> Packet Interceptor v4.5
                  </h3>
                  <div className="flex gap-3">
                    {['GET', 'POST', 'PUT', 'DELETE'].map(m => (
                      <button 
                        key={m}
                        onClick={() => setRequest(prev => ({ ...prev, method: m }))}
                        className={`px-5 py-2 rounded-xl text-[10px] font-black transition-all ${request.method === m ? 'bg-indigo-600 text-white' : 'bg-black border border-white/5 text-zinc-600 hover:text-zinc-400'}`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="bg-black border border-white/5 rounded-2xl px-6 py-4 mono text-sm flex items-center gap-4 mb-6 shadow-inner">
                   <Globe className="w-5 h-5 text-indigo-500" />
                   <input 
                     className="bg-transparent w-full outline-none text-indigo-300 font-bold"
                     value={request.url}
                     onChange={(e) => setRequest(prev => ({ ...prev, url: e.target.value }))}
                   />
                </div>
                <textarea 
                  className="flex-1 bg-black border border-white/5 rounded-3xl p-8 mono text-sm resize-none outline-none focus:border-indigo-500 text-zinc-400 shadow-inner"
                  value={request.headers}
                  onChange={(e) => setRequest(prev => ({ ...prev, headers: e.target.value }))}
                />
                <button 
                  onClick={handleSendRequest}
                  disabled={isSendingRequest}
                  className="mt-8 w-full bg-indigo-600 hover:bg-indigo-500 py-5 rounded-[24px] font-black uppercase text-xs tracking-[0.3em] flex items-center justify-center gap-3 shadow-2xl shadow-indigo-600/30 transition-all text-white"
                >
                  {isSendingRequest ? <RefreshCw className="animate-spin w-5 h-5" /> : <Play className="w-5 h-5" />}
                  SEND THROUGH ANONYMOUS PROXY
                </button>
              </div>
            </div>
            <div className="flex-1 flex flex-col bg-[#0f0f0f]/80 border border-white/5 rounded-[40px] p-12 shadow-2xl">
              <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest mb-8 flex items-center gap-2">
                <Hash className="w-4 h-4" /> Server Response
              </h3>
              <pre className="flex-1 bg-black/60 border border-white/5 rounded-3xl p-8 mono text-sm text-indigo-400 overflow-auto scrollbar-hide shadow-inner leading-relaxed">
                {response}
              </pre>
            </div>
          </div>
        )}

        {activeTab === 'DECODER' && (
          <div className="flex-1 flex flex-col gap-4 animate-in fade-in duration-500 pr-2 relative z-10">
            <div className="bg-[#0f0f0f]/90 border border-white/10 rounded-[60px] p-16 max-w-6xl mx-auto w-full shadow-2xl">
              <h3 className="text-3xl font-black text-white mb-10 uppercase tracking-tighter flex items-center gap-6 leading-none">
                <Layers className="w-10 h-10 text-indigo-600" /> Neural Payload Reconstructor
              </h3>
              <div className="space-y-10">
                <div>
                  <label className="text-[10px] text-zinc-600 font-black uppercase mb-4 block tracking-[0.3em]">Encrypted Blob / Byte Stream</label>
                  <textarea 
                    className="w-full h-64 bg-black border border-white/5 rounded-[32px] p-8 mono text-sm focus:border-indigo-500 outline-none text-zinc-400 shadow-inner"
                    placeholder="Drop obfuscated shellcode here..."
                    value={decoderInput}
                    onChange={(e) => setDecoderInput(e.target.value)}
                  />
                </div>
                <div className="flex gap-6">
                  <button onClick={() => handleDecode('BASE64')} className="flex-1 bg-zinc-900/50 border border-white/5 hover:border-indigo-500/50 py-5 rounded-2xl font-black text-[11px] uppercase tracking-widest transition-all text-zinc-500 hover:text-white">
                    Base64 Decrypt
                  </button>
                  <button onClick={() => handleDecode('URL')} className="flex-1 bg-zinc-900/50 border border-white/5 hover:border-indigo-500/50 py-5 rounded-2xl font-black text-[11px] uppercase tracking-widest transition-all text-zinc-500 hover:text-white">
                    URL Decode
                  </button>
                </div>
                <div>
                  <label className="text-[10px] text-zinc-600 font-black uppercase mb-4 block tracking-[0.3em]">Recovered Cleartext</label>
                  <div className="w-full min-h-40 bg-indigo-900/10 border border-indigo-500/20 rounded-[32px] p-8 mono text-sm text-indigo-400 break-all whitespace-pre-wrap shadow-inner relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-indigo-600 opacity-30"></div>
                    {decoderOutput || "ENGINE_STATUS: STANDBY..."}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="h-10 bg-[#0a0a0a] border-t border-white/5 px-8 flex items-center justify-between text-[10px] font-black text-zinc-600 shrink-0 z-10">
        <div className="flex gap-10 items-center uppercase tracking-[0.2em]">
          <span className="flex items-center gap-2.5 text-green-600 font-black"><ShieldCheck className="w-3.5 h-3.5" /> SYSTEM_SYNC: 2026.02.13</span>
          <span className="flex items-center gap-2.5"><Fingerprint className="w-3.5 h-3.5 text-indigo-500" /> HW_SPOOF: {stealth.macSpoofing ? 'ENGAGED' : 'OFF'}</span>
          <span className="flex items-center gap-2.5"><Orbit className={`w-3.5 h-3.5 ${macRotating ? 'text-yellow-400' : 'text-indigo-500'}`} /> ROTATION: {stealth.dynamicMacRotation ? 'ON' : 'OFF'}</span>
          <span className="flex items-center gap-2.5"><Shuffle className="w-3.5 h-3.5 text-indigo-500" /> INJECTION_FUZZ: {stealth.payloadRandomization ? 'ACTIVE' : 'OFF'}</span>
          <span className="flex items-center gap-2.5"><User className="w-3.5 h-3.5 text-indigo-500" /> OPERATOR: LOLFAKE47</span>
        </div>
        <div className="flex gap-10 mono text-indigo-600 font-black tracking-widest italic">
          <span>{target}</span>
          <span className="animate-pulse">ANACONDA_SECURE_LINK</span>
        </div>
      </footer>
    </div>
  );
};

export default App;