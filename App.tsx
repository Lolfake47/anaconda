
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, Terminal, Search, Activity, Zap, Globe, AlertTriangle, 
  Cpu, RefreshCw, ChevronRight, FolderTree, ExternalLink, 
  Github, Monitor, Copy, Download, HardDrive, Layers, Code, Play, Hash,
  EyeOff, Gauge, Ghost, ShieldAlert, Fingerprint, Lock, ShieldCheck, User
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, HttpRequest, StealthSettings } from './types.ts';
import { MOCK_SERVICES } from './constants.ts';
import { analyzeSecurityFindings } from './services/geminiService.ts';
import { SeverityBadge } from './components/ui/Badge.tsx';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'RECON' | 'REPEATER' | 'DECODER'>('RECON');
  const [target, setTarget] = useState('192.168.1.100');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Stealth & Evasion State (Lolfake47 Security Standards)
  const [stealth, setStealth] = useState<StealthSettings>({
    timing: 'T1',
    fragmentation: true,
    decoys: true,
    sourcePortSpoofing: true,
    macSpoofing: true,
    traceObfuscation: true
  });

  const [currentMac, setCurrentMac] = useState('UNSET');

  // Burp Repeater States
  const [request, setRequest] = useState<HttpRequest>({
    method: 'GET',
    url: '/api/v1/auth/status',
    headers: 'Host: secure.node.internal\nUser-Agent: Anaconda/4.5 (Lolfake47-Edition)\nConnection: close',
    body: ''
  });
  const [response, setResponse] = useState<string>('Aguardando envio furtivo...');
  const [isSendingRequest, setIsSendingRequest] = useState(false);

  // Decoder States
  const [decoderInput, setDecoderInput] = useState('');
  const [decoderOutput, setDecoderOutput] = useState('');

  const logRef = useRef<HTMLDivElement>(null);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const generateMac = () => {
    return "00:" + Array.from({length: 5}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(":").toUpperCase();
  };

  // Fix: Added handleSendRequest for REPEATER tab
  const handleSendRequest = async () => {
    if (!request.url) return;
    setIsSendingRequest(true);
    addLog(`INTERCEPTOR: Encaminhando pacote ${request.method} para ${request.url} via túnel cifrado...`);
    
    // Simulating network delay for 2026 infrastructure
    await new Promise(r => setTimeout(r, 1500));
    
    setResponse(`HTTP/1.1 200 OK
Date: Fri, 13 Feb 2026 16:25:00 GMT
Server: Apache/2.4.62 (Unix) OpenSSL/3.0.13
Content-Type: application/json; charset=utf-8
X-Trace-ID: LF47-${Math.random().toString(16).toUpperCase().slice(2, 10)}
Connection: close

{
  "status": "authenticated",
  "identity": "ghost_operator",
  "node": "secure.node.internal",
  "privileges": ["ROOT", "RED_TEAM_ACCESS"],
  "simulated_environment": "ANACONDA_V4.5"
}`);
    addLog(`INTERCEPTOR: Echo recebido com sucesso.`);
    setIsSendingRequest(false);
  };

  // Fix: Added copyToClipboard for offensive commands
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    addLog(`CLIPBOARD: Payload copiado para a área de transferência.`);
  };

  // Fix: Added handleDecode for DECODER tab
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
      setDecoderOutput(`CRITICAL_ERROR: Falha na decodificação do blob. O payload pode estar corrompido.`);
      addLog(`NEURAL_ENGINE: FALHA AO PROCESSAR PAYLOAD.`);
    }
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`INIT: Anaconda Red Suite Engine v4.5 - Author: Lolfake47`);
    addLog(`STAMP: Simulation Date 2026-02-13`);
    
    if (stealth.macSpoofing) {
      const mac = generateMac();
      setCurrentMac(mac);
      addLog(`EVASION: MAC Address Spoofing ativado. Novo HWID: ${mac}`);
    }
    
    if (stealth.traceObfuscation) {
      addLog("EVASION: Ofuscação de rastro de memória ativa. Limpeza de heap ativada.");
    }

    const sequence = [
      { p: 5, m: "Preparando payloads ofuscados..." },
      { p: 25, m: "Evadindo SOC Baseado em IA (Detecção de Anomalia 2026)..." },
      { p: 50, m: "Injeção de pacotes fragmentados (MTU 512)..." },
      { p: 75, m: "Identificando Zero-Days e Misconfigurations..." },
      { p: 100, m: "Enumeration complete. Analisando mitigação de 2026." }
    ];

    const speedMultiplier = stealth.timing === 'T0' ? 5 : stealth.timing === 'T5' ? 0.3 : 1.2;

    for (const step of sequence) {
      await new Promise(r => setTimeout(r, 800 * speedMultiplier));
      setScanProgress(step.p);
      addLog(step.m);
    }

    const mockResult: ScanResult = {
      target,
      timestamp: "2026-02-13T16:20:00Z",
      type: ScanType.TCP,
      openPorts: [80, 443, 22, 5432],
      services: MOCK_SERVICES,
      stealthUsed: stealth,
      directories: [{ path: '/.env', status: 200, size: '1.2kb', type: 'CRITICAL' }],
      vulnerabilities: [
        {
          id: 'LF47-Z01',
          name: 'Memory-Only RCE: SSH Key Exchange (2026.02 Patch Bypass)',
          severity: Severity.CRITICAL,
          description: 'Vulnerabilidade descoberta em Fevereiro de 2026. Permite execução de código sem tocar o disco (Fileless).',
          exploitTheory: 'Corrupção de lógica no buffer de troca de chaves que permite saltar para o endereço da shell.',
          exploitationSteps: [`anaconda-rce -t ${target} --bypass-soc --mac ${generateMac()}`],
          exploitUrl: 'https://lolfake47.security/exploits/ssh-2026',
          mitigation: 'Implementar auditoria de memória em tempo real e isolar kernels SSH.'
        },
        {
          id: 'LF47-Z02',
          name: 'Advanced PostgreSQL Credential Leak',
          severity: Severity.HIGH,
          description: 'Vazamento de metadados de sessão em versões 2025/2026 sob carga alta.',
          exploitTheory: 'Abuso de concorrência em triggers de auditoria para ler buffers de memória cruzada.',
          exploitationSteps: [`pg_leak -h ${target} --stealth --timing T1`],
          exploitUrl: 'https://exploit-db.com/lolfake47/pg-leak',
          mitigation: 'Atualizar driver de auditoria e desativar triggers legados.'
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
        summary: "Erro crítico na IA do Lolfake47. Risco estimado: EXTREMO.",
        riskScore: 95,
        traceRisk: 5,
        recommendations: ["Abortar operação se o MAC for detetado", "Mudar de IP via proxy-chain"],
        exploitPaths: ["Database Leak -> Admin Account -> Global System Access"]
      });
    }
    setIsAnalyzing(false);
  }, [target, stealth]);

  return (
    <div className="min-h-screen flex flex-col bg-[#050505] text-[#e0e0e0]">
      {/* Header Lolfake47 Edition */}
      <header className="h-16 border-b border-indigo-500/30 bg-[#0a0a0a] flex items-center justify-between px-6 shrink-0 z-10">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-indigo-500/20 blur-lg rounded-full animate-pulse"></div>
            <div className="relative bg-indigo-600 p-2.5 rounded-xl border border-indigo-400/50">
              <Shield className="w-5 h-5 text-white" />
            </div>
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tighter text-white uppercase italic leading-none">
              ANACONDA <span className="text-indigo-500">RED_SUITE v4.5</span>
            </h1>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[9px] text-zinc-500 font-bold mono uppercase tracking-widest">
                OFFENSIVE SECURITY SIMULATOR
              </span>
              <span className="h-2 w-[1px] bg-zinc-800"></span>
              <span className="text-[9px] text-indigo-400 font-bold mono uppercase">
                DEV: LOLFAKE47
              </span>
            </div>
          </div>
        </div>

        <div className="flex bg-black/50 p-1 rounded-xl border border-white/5">
          {['RECON', 'REPEATER', 'DECODER'].map((tab) => (
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
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-20 pointer-events-none"></div>

        {activeTab === 'RECON' && (
          <>
            <div className="w-80 flex flex-col gap-4 relative z-10">
              <section className="bg-[#0f0f0f]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-6 shadow-2xl">
                <h3 className="text-[10px] font-black text-indigo-400 mb-6 flex items-center gap-2 tracking-widest uppercase">
                  <User className="w-4 h-4" /> Operator: Lolfake47
                </h3>
                
                <div className="space-y-6">
                  <div>
                    <label className="block text-[10px] text-zinc-600 font-bold uppercase mb-2 ml-1">Engagement Node</label>
                    <div className="relative group">
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
                    <div className="flex justify-between gap-1.5 bg-black/50 p-1.5 rounded-xl border border-white/5">
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
                    <label className="block text-[10px] text-zinc-600 font-bold uppercase mb-1 ml-1">Security Bypasses</label>
                    {[
                      { key: 'macSpoofing', label: 'MAC Address Rotation', icon: Fingerprint },
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
                          className="accent-indigo-500 w-4 h-4 rounded-full"
                        />
                      </label>
                    ))}
                  </div>

                  <button 
                    onClick={simulateScan}
                    disabled={isScanning}
                    className={`w-full py-4 rounded-2xl font-black text-xs uppercase tracking-[0.2em] flex items-center justify-center gap-3 transition-all ${isScanning ? 'bg-zinc-800 text-zinc-500' : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_10px_30px_rgba(79,70,229,0.3)]'}`}
                  >
                    {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {isScanning ? 'BYPASSING SOC...' : 'ENGAGE ANACONDA'}
                  </button>
                </div>
              </section>

              <section className="flex-1 bg-black/90 border border-white/5 rounded-3xl flex flex-col overflow-hidden shadow-2xl">
                <div className="bg-zinc-900/50 px-4 py-2.5 border-b border-white/5 flex items-center justify-between">
                  <span className="text-[9px] font-black text-indigo-500 uppercase tracking-widest">Trace Logs // Lolfake47</span>
                  <Activity className="w-3 h-3 text-green-500 animate-pulse" />
                </div>
                <div ref={logRef} className="flex-1 p-4 mono text-[10px] overflow-y-auto space-y-2 scrollbar-hide">
                  {logs.length === 0 ? (
                    <div className="text-zinc-800 italic uppercase">Awaiting connection parameters...</div>
                  ) : logs.map((log, i) => (
                    <div key={i} className="flex gap-2 leading-relaxed border-l-2 border-indigo-500/20 pl-2">
                      <span className={log.includes('ALERTA') ? 'text-red-500 font-bold' : log.includes('EVASION') ? 'text-indigo-400' : 'text-zinc-500'}>
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
                  <div className="p-16 border border-white/5 rounded-[60px] bg-gradient-to-br from-[#0a0a0a] to-[#050505] shadow-2xl">
                    <Zap className="w-40 h-40 text-indigo-600 opacity-20 mb-8 mx-auto" />
                    <h2 className="text-5xl font-black mb-4 uppercase tracking-tighter text-white">READY TO ENGAGE</h2>
                    <p className="max-w-md text-sm mono text-zinc-600 leading-relaxed uppercase">Anaconda OS v4.5 Optimized for 2026 Evasion Strategies. Toolset by Lolfake47.</p>
                  </div>
                </div>
              )}

              {isScanning && (
                <div className="h-full flex flex-col items-center justify-center space-y-12">
                  <div className="relative scale-150">
                    <div className="w-48 h-48 rounded-full border-[1px] border-indigo-600/10 border-t-indigo-500 animate-spin"></div>
                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                      <span className="text-5xl font-black text-white">{scanProgress}%</span>
                      <span className="text-[10px] text-indigo-400 mono font-black tracking-widest mt-2">ANACONDA_RECON</span>
                    </div>
                  </div>
                </div>
              )}

              {results && (
                <div className="space-y-4 pb-12 animate-in fade-in slide-in-from-bottom-8 duration-700">
                  <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-3xl p-5 flex items-center justify-between backdrop-blur-md">
                    <div className="flex items-center gap-4">
                      <div className="p-3 bg-green-500/20 rounded-2xl border border-green-500/30">
                        <ShieldCheck className="w-6 h-6 text-green-500" />
                      </div>
                      <div>
                        <span className="text-[10px] text-indigo-400 font-black block uppercase tracking-widest">Engagement: Success</span>
                        <span className="text-sm font-bold text-white uppercase italic tracking-tight">Vulnerabilities found on {target} (Simulated 2026)</span>
                      </div>
                    </div>
                    <div className="text-right px-6 border-l border-white/10">
                      <span className="text-[9px] text-zinc-500 font-bold block uppercase tracking-widest">MAC Spoofed</span>
                      <span className="text-xs mono text-zinc-300">{currentMac}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    {results.vulnerabilities.map(v => (
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
                        
                        <div className="space-y-4 bg-black/60 rounded-3xl p-6 border border-white/5 shadow-inner">
                          <h5 className="text-[9px] font-black text-zinc-600 uppercase tracking-widest flex items-center gap-2">
                            <Play className="w-3 h-3 text-indigo-500" /> Offensive Command
                          </h5>
                          {v.exploitationSteps.map((step, idx) => (
                            <div key={idx} className="flex items-center justify-between gap-4 bg-black p-4 rounded-2xl border border-white/10">
                              <code className="mono text-xs text-indigo-300 break-all">{step}</code>
                              <button onClick={() => copyToClipboard(step)} className="shrink-0 p-2 text-zinc-600 hover:text-white transition-colors">
                                <Copy className="w-4 h-4" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="bg-gradient-to-br from-[#0f0f0f] to-[#050505] border border-indigo-500/30 rounded-[40px] p-12 relative overflow-hidden shadow-2xl">
                    <div className="absolute top-0 right-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-600 to-transparent"></div>
                    <div className="flex items-center justify-between mb-16">
                      <div>
                        <h3 className="text-4xl font-black text-white mb-2 uppercase italic tracking-tighter">LOLFAKE47_AI ENGINE</h3>
                        <p className="text-xs text-indigo-400 mono font-black tracking-[0.5em] uppercase">Attribution Defense & Exploit Logic (2026-02-13)</p>
                      </div>
                      <div className="bg-indigo-600 p-5 rounded-[24px] shadow-[0_0_60px_rgba(79,70,229,0.4)] border border-indigo-400/50">
                        <Cpu className="w-12 h-12 text-white" />
                      </div>
                    </div>

                    {isAnalyzing ? (
                      <div className="py-24 flex flex-col items-center justify-center gap-6">
                        <RefreshCw className="w-12 h-12 text-indigo-500 animate-spin" />
                        <span className="text-xs text-indigo-400 mono animate-pulse font-black tracking-[0.3em] uppercase">Simulating Exploit attribution...</span>
                      </div>
                    ) : analysis ? (
                      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                        <div className="lg:col-span-7 space-y-10">
                          <div className="space-y-4">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Terminal className="w-4 h-4" /> Red Team Summary
                            </h4>
                            <p className="text-zinc-300 leading-relaxed font-semibold text-xl italic border-l-8 border-indigo-600 pl-8 py-6 bg-white/5 rounded-r-3xl">
                              {analysis.summary}
                            </p>
                          </div>
                          
                          <div className="space-y-6">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest flex items-center gap-2">
                              <Layers className="w-4 h-4" /> Escalation Paths
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
                            <h4 className="text-[10px] font-black text-zinc-600 uppercase tracking-widest mb-8">Detection Vulnerability</h4>
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
                                <span className="text-[10px] text-zinc-600 font-black uppercase mt-2">Trace Score</span>
                              </div>
                            </div>
                            <span className="text-[11px] mono text-indigo-400 font-black uppercase tracking-[0.3em]">
                              {analysis.traceRisk < 15 ? "GHOST_OPERATOR_ACTIVE" : "HIGH_RISK_OF_DETECTION"}
                            </span>
                          </div>

                          <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-[40px] p-10 space-y-8">
                            <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-widest border-b border-indigo-500/30 pb-6">Remediation Strategies</h4>
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

        {/* Tab contents (REPEATER & DECODER) updated with Lolfake47 style */}
        {activeTab === 'REPEATER' && (
          <div className="flex-1 flex gap-4 animate-in fade-in duration-500 pr-2 relative z-10">
            <div className="flex-1 flex flex-col gap-4">
              <div className="bg-[#0f0f0f]/90 border border-white/10 rounded-[40px] p-12 flex-1 flex flex-col shadow-2xl">
                <div className="flex items-center justify-between mb-8">
                  <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" /> Packet Interceptor 2026
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
                  className="mt-8 w-full bg-indigo-600 hover:bg-indigo-500 py-5 rounded-[24px] font-black uppercase text-xs tracking-[0.3em] flex items-center justify-center gap-3 shadow-2xl shadow-indigo-600/30 transition-all"
                >
                  {isSendingRequest ? <RefreshCw className="animate-spin w-5 h-5" /> : <Play className="w-5 h-5" />}
                  SEND PACKET THROUGH PROXY
                </button>
              </div>
            </div>
            <div className="flex-1 flex flex-col bg-[#0f0f0f]/80 border border-white/5 rounded-[40px] p-12 shadow-2xl">
              <h3 className="text-xs font-black text-indigo-400 uppercase tracking-widest mb-8 flex items-center gap-2">
                <Hash className="w-4 h-4" /> Server Echo
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
                  <label className="text-[10px] text-zinc-600 font-black uppercase mb-4 block tracking-[0.3em]">Encrypted Blob / Shellcode</label>
                  <textarea 
                    className="w-full h-64 bg-black border border-white/5 rounded-[32px] p-8 mono text-sm focus:border-indigo-500 outline-none text-zinc-400 shadow-inner"
                    placeholder="Paste 2026 obfuscated hex/base64 payload here..."
                    value={decoderInput}
                    onChange={(e) => setDecoderInput(e.target.value)}
                  />
                </div>
                <div className="flex gap-6">
                  <button onClick={() => handleDecode('BASE64')} className="flex-1 bg-zinc-900/50 border border-white/5 hover:border-indigo-500/50 py-5 rounded-2xl font-black text-[11px] uppercase tracking-widest transition-all text-zinc-500 hover:text-white">
                    Base64 Engine
                  </button>
                  <button onClick={() => handleDecode('URL')} className="flex-1 bg-zinc-900/50 border border-white/5 hover:border-indigo-500/50 py-5 rounded-2xl font-black text-[11px] uppercase tracking-widest transition-all text-zinc-500 hover:text-white">
                    URL Normalizer
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
          <span className="flex items-center gap-2.5 text-green-600"><ShieldCheck className="w-3.5 h-3.5" /> ENCRYPTED_LINK: ACTIVE</span>
          <span className="flex items-center gap-2.5"><Fingerprint className="w-3.5 h-3.5 text-indigo-500" /> HW_SPOOF: {stealth.macSpoofing ? 'ENGAGED' : 'OFF'}</span>
          <span className="flex items-center gap-2.5"><EyeOff className="w-3.5 h-3.5 text-indigo-500" /> TRACE_WIPE: {stealth.traceObfuscation ? 'ENGAGED' : 'OFF'}</span>
          <span className="flex items-center gap-2.5"><User className="w-3.5 h-3.5 text-indigo-500" /> OPERATOR: LOLFAKE47</span>
        </div>
        <div className="flex gap-10 mono text-indigo-600 font-black tracking-widest italic">
          <span>{target}</span>
          <span className="animate-pulse">2026.02.13_SYNC_OK</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
