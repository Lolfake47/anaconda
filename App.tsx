import React, { useState, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, Terminal, Search, Activity, Zap, Globe, AlertTriangle, 
  Cpu, RefreshCw, ChevronRight, FolderTree, ExternalLink, 
  Github, Monitor, Copy, Download, HardDrive, Layers, Code, Play, Hash,
  EyeOff, Gauge, Ghost, ShieldAlert
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, HttpRequest, StealthSettings } from './types.ts';
import { MOCK_SERVICES } from './constants.ts';
import { analyzeSecurityFindings } from './services/geminiService.ts';
import { SeverityBadge } from './components/ui/Badge.tsx';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'RECON' | 'REPEATER' | 'DECODER'>('RECON');
  const [target, setTarget] = useState('127.0.0.1');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Stealth & Evasion State
  const [stealth, setStealth] = useState<StealthSettings>({
    timing: 'T3',
    fragmentation: false,
    decoys: false,
    sourcePortSpoofing: false
  });

  // Burp Repeater States
  const [request, setRequest] = useState<HttpRequest>({
    method: 'GET',
    url: '/api/v1/user?id=1',
    headers: 'Host: target.local\nUser-Agent: Mozilla/5.0\nAccept: */*',
    body: ''
  });
  const [response, setResponse] = useState<string>('Aguardando envio...');
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    addLog(`Comando copiado: ${text.substring(0, 20)}...`);
  };

  const handleSendRequest = async () => {
    setIsSendingRequest(true);
    addLog(`REPEATER: Enviando ${request.method} para ${request.url}`);
    await new Promise(r => setTimeout(r, 800));
    setResponse("HTTP/1.1 200 OK\nContent-Type: application/json\nServer: Anaconda/1.0\n\n{\"status\": \"active\", \"target\": \"verified\"}");
    setIsSendingRequest(false);
  };

  const handleDecode = (type: 'BASE64' | 'URL') => {
    try {
      if (type === 'BASE64') {
        setDecoderOutput(atob(decoderInput));
      } else {
        setDecoderOutput(decodeURIComponent(decoderInput));
      }
      addLog(`DECODER: Sucesso ao decodificar ${type}`);
    } catch (e) {
      setDecoderOutput("ERRO: Formato inválido.");
      addLog(`DECODER: Falha ao decodificar ${type}`);
    }
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`INIT: Reconhecimento ANACONDA iniciado em ${target}`);
    addLog(`CONFIG: Perfil de Temporização: ${stealth.timing}`);
    
    if (stealth.fragmentation) addLog("EVASION: Fragmentação de pacotes ativada (-f).");
    if (stealth.decoys) addLog("EVASION: Gerando 10 IPs de isca (Decoys) para ocultar origem.");
    if (stealth.sourcePortSpoofing) addLog("EVASION: Spoofing de porta de origem (Porta 53/DNS).");

    const sequence = [
      { p: 10, m: "Iniciando mapeamento de rede..." },
      { p: 40, m: "Analisando stack TCP/IP para fingerprinting..." },
      { p: 70, m: "Evadindo regras de Firewall/IDS locais..." },
      { p: 100, m: "Scan concluído com sucesso." }
    ];

    const speedMultiplier = stealth.timing === 'T0' ? 3 : stealth.timing === 'T5' ? 0.5 : 1;

    for (const step of sequence) {
      await new Promise(r => setTimeout(r, 600 * speedMultiplier));
      setScanProgress(step.p);
      addLog(step.m);
      
      if (stealth.timing === 'T5' && step.p === 40) {
        addLog("ALERTA: Tráfego agressivo detectado pelo Firewall do alvo!");
      }
      if (stealth.timing === 'T0' && step.p === 70) {
        addLog("INFO: Tráfego extremamente lento simulado. Risco de detecção mínimo.");
      }
    }

    const mockResult: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      type: ScanType.TCP,
      openPorts: [80, 443, 22, 445],
      services: MOCK_SERVICES,
      stealthUsed: stealth,
      directories: [{ path: '/config', status: 200, size: '4kb', type: 'SENSITIVE' }],
      vulnerabilities: [
        {
          id: '1',
          name: 'SSH Brute Force Vulnerability',
          severity: Severity.MEDIUM,
          description: 'Serviço SSH permite múltiplas tentativas de login sem bloqueio.',
          exploitTheory: 'Falta de implementação de Fail2Ban ou limites de tentativa.',
          exploitationSteps: ['hydra -l admin -P wordlist.txt ' + target + ' ssh'],
          exploitUrl: 'https://github.com/vanhauser-thc/thc-hydra',
          mitigation: 'Instalar Fail2Ban e usar chaves SSH em vez de senhas.'
        },
        {
          id: '2',
          name: 'EternalBlue (MS17-010)',
          severity: Severity.CRITICAL,
          description: 'Vulnerabilidade no protocolo SMBv1 permite RCE.',
          exploitTheory: 'Exploração de buffer overflow na memória do kernel do Windows.',
          exploitationSteps: ['msfconsole', 'use exploit/windows/smb/ms17_010_eternalblue', 'set RHOSTS ' + target, 'exploit'],
          exploitUrl: 'https://www.exploit-db.com/exploits/42315',
          mitigation: 'Desativar SMBv1 e aplicar patches de segurança da Microsoft.'
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
      addLog("ERRO: IA offline ou chave de API ausente.");
      setAnalysis({
        summary: "Não foi possível gerar a análise da IA. Verifique as configurações.",
        riskScore: 75,
        recommendations: ["Revise as portas 22 e 445 manualmente.", "Aplique patches críticos no SMB."],
        exploitPaths: ["Vetor SMB -> EternalBlue -> System Access"]
      });
    }
    setIsAnalyzing(false);
  }, [target, stealth]);

  return (
    <div className="min-h-screen flex flex-col bg-[#050505] text-[#e0e0e0]">
      {/* Header Estilo Kali */}
      <header className="h-14 border-b border-indigo-500/20 bg-[#0a0a0a] flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-3">
          <div className="bg-indigo-600 p-1.5 rounded-lg shadow-[0_0_15px_rgba(79,70,229,0.4)]">
            <Monitor className="w-5 h-5 text-white" />
          </div>
          <h1 className="text-xl font-black tracking-tighter text-white uppercase italic">
            ANACONDA <span className="text-indigo-500">RED_SUITE</span>
          </h1>
          <div className="h-4 w-[1px] bg-white/10 mx-2"></div>
          <span className="mono text-xs text-indigo-400 font-bold flex items-center gap-1.5">
            <Ghost className="w-3 h-3" /> SESSION: ACTIVE // {target}
          </span>
        </div>
        <div className="flex gap-4">
          <button 
            onClick={() => setActiveTab('RECON')}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-bold transition-all ${activeTab === 'RECON' ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/50' : 'text-zinc-500 hover:text-indigo-400'}`}
          >
            <Activity className="w-4 h-4" /> RECON
          </button>
          <button 
            onClick={() => setActiveTab('REPEATER')}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-bold transition-all ${activeTab === 'REPEATER' ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/50' : 'text-zinc-500 hover:text-indigo-400'}`}
          >
            <RefreshCw className="w-4 h-4" /> REPEATER
          </button>
          <button 
            onClick={() => setActiveTab('DECODER')}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-bold transition-all ${activeTab === 'DECODER' ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/50' : 'text-zinc-500 hover:text-indigo-400'}`}
          >
            <Code className="w-4 h-4" /> DECODER
          </button>
        </div>
      </header>

      <main className="flex-1 overflow-hidden flex p-4 gap-4">
        {activeTab === 'RECON' && (
          <>
            {/* Sidebar de Configurações */}
            <div className="w-80 flex flex-col gap-4">
              <section className="bg-[#0f0f0f] border border-white/5 rounded-xl p-5 shadow-2xl">
                <h3 className="text-xs font-bold text-indigo-400 mb-4 flex items-center gap-2 tracking-widest uppercase">
                  <Search className="w-3 h-3" /> Target Configuration
                </h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-[10px] text-zinc-500 font-bold uppercase mb-1.5">Network Target</label>
                    <div className="relative group">
                      <Terminal className="absolute left-3 top-3 w-4 h-4 text-zinc-600 group-focus-within:text-indigo-500 transition-colors" />
                      <input 
                        type="text" 
                        value={target} 
                        onChange={(e) => setTarget(e.target.value)}
                        className="w-full bg-[#050505] border border-white/10 rounded-lg py-2.5 pl-10 pr-4 mono text-sm focus:border-indigo-500 outline-none transition-all"
                        placeholder="IP ou Host..."
                      />
                    </div>
                  </div>

                  <div className="pt-2">
                    <label className="block text-[10px] text-zinc-500 font-bold uppercase mb-3 flex items-center gap-1.5">
                      <Gauge className="w-3 h-3" /> Timing Profile: {stealth.timing}
                    </label>
                    <div className="flex justify-between gap-1">
                      {['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].map((t) => (
                        <button
                          key={t}
                          onClick={() => setStealth(prev => ({ ...prev, timing: t as any }))}
                          className={`flex-1 py-2 text-[10px] font-black rounded border transition-all ${stealth.timing === t ? 'bg-indigo-600 border-indigo-400 text-white' : 'bg-black border-white/5 text-zinc-600 hover:border-indigo-500/50'}`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-3 pt-2">
                    <label className="block text-[10px] text-zinc-500 font-bold uppercase flex items-center gap-1.5">
                      <ShieldAlert className="w-3 h-3" /> Evasion Techniques
                    </label>
                    {[
                      { key: 'fragmentation', label: 'Packet Fragmentation (-f)' },
                      { key: 'decoys', label: 'Use Decoy IPs (-D)' },
                      { key: 'sourcePortSpoofing', label: 'Spoof Source Port 53' }
                    ].map((opt) => (
                      <label key={opt.key} className="flex items-center justify-between p-2 rounded-lg bg-black/50 border border-white/5 cursor-pointer hover:border-indigo-500/30 transition-all">
                        <span className="text-[11px] text-zinc-400 mono">{opt.label}</span>
                        <input 
                          type="checkbox" 
                          checked={(stealth as any)[opt.key]} 
                          onChange={(e) => setStealth(prev => ({ ...prev, [opt.key]: e.target.checked }))}
                          className="accent-indigo-600 w-4 h-4"
                        />
                      </label>
                    ))}
                  </div>

                  <button 
                    onClick={simulateScan}
                    disabled={isScanning}
                    className={`w-full py-4 rounded-xl font-black text-xs uppercase tracking-widest flex items-center justify-center gap-3 transition-all ${isScanning ? 'bg-zinc-800 text-zinc-500' : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_20px_rgba(79,70,229,0.3)]'}`}
                  >
                    {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {isScanning ? 'Scanning Network...' : 'Execute Anaconda Scan'}
                  </button>
                </div>
              </section>

              {/* Console Logs */}
              <section className="flex-1 bg-black border border-white/5 rounded-xl flex flex-col overflow-hidden">
                <div className="bg-[#0f0f0f] px-4 py-2 border-b border-white/5 flex items-center justify-between">
                  <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">System Logs</span>
                  <div className="flex gap-1.5">
                    <div className="w-2 h-2 rounded-full bg-red-500/50"></div>
                    <div className="w-2 h-2 rounded-full bg-yellow-500/50"></div>
                    <div className="w-2 h-2 rounded-full bg-green-500/50"></div>
                  </div>
                </div>
                <div ref={logRef} className="flex-1 p-4 mono text-[11px] overflow-y-auto space-y-1.5 scrollbar-hide">
                  {logs.length === 0 ? (
                    <div className="text-zinc-700 italic">Anaconda aguardando comando...</div>
                  ) : logs.map((log, i) => (
                    <div key={i} className="flex gap-2 leading-relaxed">
                      <span className="text-indigo-500 shrink-0">➜</span>
                      <span className={log.includes('ALERTA') ? 'text-red-400' : log.includes('INFO') ? 'text-blue-400' : 'text-zinc-400'}>
                        {log}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            {/* Dashboard Central */}
            <div className="flex-1 flex flex-col gap-4 overflow-y-auto">
              {!results && !isScanning && (
                <div className="h-full flex flex-col items-center justify-center text-zinc-800 p-12 text-center opacity-40">
                  <div className="mb-8 p-12 border-2 border-dashed border-zinc-900 rounded-full">
                    <Zap className="w-32 h-32" />
                  </div>
                  <h2 className="text-4xl font-black mb-4 uppercase tracking-tighter">Pronto para Enumerar</h2>
                  <p className="max-w-md text-sm mono">Insira o alvo e escolha o perfil de evasão para iniciar o simulador de Red Team Anaconda.</p>
                </div>
              )}

              {isScanning && (
                <div className="h-full flex flex-col items-center justify-center space-y-12">
                  <div className="relative">
                    <div className="w-48 h-48 rounded-full border-4 border-indigo-600/20 border-t-indigo-500 animate-spin"></div>
                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                      <span className="text-4xl font-black text-white">{scanProgress}%</span>
                      <span className="text-[10px] text-indigo-400 mono font-bold animate-pulse">RECON_MODE</span>
                    </div>
                  </div>
                  <div className="w-full max-w-lg space-y-3">
                    <div className="h-1 w-full bg-zinc-900 rounded-full overflow-hidden">
                      <div className="h-full bg-indigo-500 transition-all duration-500" style={{ width: `${scanProgress}%` }}></div>
                    </div>
                    <div className="flex justify-between items-center px-2">
                      <span className="text-[10px] text-zinc-600 mono uppercase">Bypassing IDS...</span>
                      <span className="text-[10px] text-zinc-600 mono uppercase">Timing: {stealth.timing}</span>
                    </div>
                  </div>
                </div>
              )}

              {results && (
                <div className="space-y-4 pb-8">
                  {/* Vulnerability Grid */}
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    {results.vulnerabilities.map(v => (
                      <div key={v.id} className="bg-[#0f0f0f] border border-white/5 rounded-2xl p-6 hover:border-indigo-500/20 transition-all shadow-xl">
                        <div className="flex justify-between items-start mb-4">
                          <SeverityBadge severity={v.severity} />
                          <div className="p-2 bg-black rounded-lg border border-white/5">
                            <Shield className="w-4 h-4 text-indigo-400" />
                          </div>
                        </div>
                        <h4 className="text-lg font-black text-white mb-2 uppercase tracking-tight">{v.name}</h4>
                        <p className="text-sm text-zinc-400 mb-6 leading-relaxed">{v.description}</p>
                        
                        <div className="space-y-4">
                          <div className="bg-black/40 rounded-xl p-4 border border-white/5">
                            <h5 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                              <Terminal className="w-3 h-3" /> Execution Payload
                            </h5>
                            {v.exploitationSteps.map((step, idx) => (
                              <div key={idx} className="flex items-center justify-between gap-3 bg-black p-3 rounded-lg border border-indigo-500/10">
                                <code className="mono text-xs text-indigo-400 break-all">{step}</code>
                                <button onClick={() => copyToClipboard(step)} className="shrink-0 text-zinc-600 hover:text-white transition-colors">
                                  <Copy className="w-4 h-4" />
                                </button>
                              </div>
                            ))}
                          </div>
                          <a 
                            href={v.exploitUrl} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-2 text-xs font-bold text-indigo-400 hover:text-indigo-300 transition-colors"
                          >
                            <ExternalLink className="w-3 h-3" /> View Source in Exploit-DB
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Grounding & AI Analysis Section */}
                  <div className="bg-indigo-600/5 border border-indigo-500/20 rounded-2xl p-8">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-2xl font-black text-white mb-1 uppercase italic tracking-tighter">AI RED TEAM ANALYSIS</h3>
                        <p className="text-xs text-indigo-400 mono font-bold tracking-widest uppercase">Powered by Gemini 3 Flash / Anaconda Engine</p>
                      </div>
                      <div className="bg-indigo-600 p-3 rounded-2xl shadow-[0_0_30px_rgba(79,70,229,0.4)]">
                        <Cpu className="w-8 h-8 text-white" />
                      </div>
                    </div>

                    {isAnalyzing ? (
                      <div className="py-12 flex flex-col items-center justify-center gap-4">
                        <RefreshCw className="w-10 h-10 text-indigo-500 animate-spin" />
                        <span className="text-sm text-indigo-400 mono animate-pulse font-bold">GENERATING OFFENSIVE REPORT...</span>
                      </div>
                    ) : analysis ? (
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
                        <div className="lg:col-span-2 space-y-6">
                          <div className="space-y-4">
                            <h4 className="text-xs font-black text-indigo-300 uppercase tracking-widest">Executive Summary</h4>
                            <p className="text-zinc-300 leading-relaxed font-medium">{analysis.summary}</p>
                          </div>
                          
                          <div className="space-y-4">
                            <h4 className="text-xs font-black text-indigo-300 uppercase tracking-widest">Post-Exploitation Paths</h4>
                            <div className="space-y-2">
                              {analysis.exploitPaths.map((path, i) => (
                                <div key={i} className="flex items-center gap-4 bg-black/40 p-3 rounded-xl border border-white/5">
                                  <div className="w-6 h-6 rounded-full bg-indigo-600/20 flex items-center justify-center text-[10px] font-bold text-indigo-400 border border-indigo-500/30">
                                    {i + 1}
                                  </div>
                                  <span className="text-sm text-zinc-300 mono">{path}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <div className="bg-black/60 border border-white/10 rounded-2xl p-6 flex flex-col items-center text-center">
                            <h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">Target Risk Score</h4>
                            <div className="relative w-32 h-32 mb-4">
                              <svg className="w-full h-full transform -rotate-90">
                                <circle cx="64" cy="64" r="58" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-zinc-900" />
                                <circle cx="64" cy="64" r="58" stroke="currentColor" strokeWidth="8" fill="transparent" 
                                  strokeDasharray={364.4}
                                  strokeDashoffset={364.4 - (364.4 * analysis.riskScore) / 100}
                                  className={analysis.riskScore > 70 ? "text-red-500" : analysis.riskScore > 40 ? "text-yellow-500" : "text-green-500"} 
                                />
                              </svg>
                              <div className="absolute inset-0 flex items-center justify-center">
                                <span className="text-3xl font-black text-white">{analysis.riskScore}</span>
                              </div>
                            </div>
                            <span className="text-[10px] mono text-zinc-500 uppercase">Likelihood of compromise: HIGH</span>
                          </div>

                          <div className="space-y-3">
                            <h4 className="text-xs font-black text-indigo-300 uppercase tracking-widest">Remediation Steps</h4>
                            <div className="space-y-2">
                              {analysis.recommendations.map((rec, i) => (
                                <div key={i} className="flex gap-3 text-xs text-zinc-400 bg-black/40 p-3 rounded-lg border border-white/5">
                                  <Shield className="w-4 h-4 text-green-500 shrink-0" />
                                  <span>{rec}</span>
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

        {activeTab === 'REPEATER' && (
          <div className="flex-1 flex gap-4 overflow-hidden animate-in fade-in duration-300">
            <div className="flex-1 flex flex-col gap-4">
              <div className="bg-[#0f0f0f] border border-white/5 rounded-xl p-6 flex-1 flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-bold text-indigo-400 uppercase tracking-widest flex items-center gap-2">
                    <Code className="w-4 h-4" /> HTTP Request Editor
                  </h3>
                  <div className="flex gap-2">
                    {['GET', 'POST', 'PUT', 'DELETE'].map(m => (
                      <button 
                        key={m}
                        onClick={() => setRequest(prev => ({ ...prev, method: m }))}
                        className={`px-3 py-1 rounded text-[10px] font-black border transition-all ${request.method === m ? 'bg-indigo-600 border-indigo-400' : 'bg-black border-white/5 text-zinc-500'}`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
                <input 
                  className="w-full bg-black border border-white/10 rounded-lg p-3 mono text-sm mb-4 outline-none focus:border-indigo-500"
                  value={request.url}
                  onChange={(e) => setRequest(prev => ({ ...prev, url: e.target.value }))}
                />
                <textarea 
                  className="flex-1 bg-black border border-white/10 rounded-lg p-4 mono text-sm resize-none outline-none focus:border-indigo-500"
                  value={request.headers}
                  onChange={(e) => setRequest(prev => ({ ...prev, headers: e.target.value }))}
                />
                <button 
                  onClick={handleSendRequest}
                  disabled={isSendingRequest}
                  className="mt-4 w-full bg-indigo-600 hover:bg-indigo-500 py-3 rounded-xl font-black uppercase text-xs tracking-widest flex items-center justify-center gap-2"
                >
                  {isSendingRequest ? <RefreshCw className="animate-spin w-4 h-4" /> : <Play className="w-4 h-4" />}
                  Send Request
                </button>
              </div>
            </div>
            <div className="flex-1 flex flex-col bg-[#0f0f0f] border border-white/5 rounded-xl p-6">
              <h3 className="text-sm font-bold text-indigo-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                <Globe className="w-4 h-4" /> Server Response
              </h3>
              <pre className="flex-1 bg-black border border-white/10 rounded-lg p-4 mono text-sm text-indigo-300 overflow-auto">
                {response}
              </pre>
            </div>
          </div>
        )}

        {activeTab === 'DECODER' && (
          <div className="flex-1 flex flex-col gap-4 animate-in fade-in duration-300">
            <div className="bg-[#0f0f0f] border border-white/5 rounded-2xl p-8 max-w-4xl mx-auto w-full">
              <h3 className="text-xl font-black text-white mb-6 uppercase tracking-tight flex items-center gap-3">
                <Layers className="w-6 h-6 text-indigo-500" /> Smart Payload Decoder
              </h3>
              <div className="space-y-6">
                <div>
                  <label className="text-[10px] text-zinc-500 font-bold uppercase mb-2 block">Raw / Encoded Input</label>
                  <textarea 
                    className="w-full h-48 bg-black border border-white/10 rounded-xl p-4 mono text-sm focus:border-indigo-500 outline-none"
                    placeholder="Cole seu payload aqui (ex: Base64 ou URL encoded)..."
                    value={decoderInput}
                    onChange={(e) => setDecoderInput(e.target.value)}
                  />
                </div>
                <div className="flex gap-4">
                  <button onClick={() => handleDecode('BASE64')} className="flex-1 bg-zinc-900 border border-white/5 hover:border-indigo-500/50 py-3 rounded-xl font-bold text-xs uppercase transition-all">
                    Decode Base64
                  </button>
                  <button onClick={() => handleDecode('URL')} className="flex-1 bg-zinc-900 border border-white/5 hover:border-indigo-500/50 py-3 rounded-xl font-bold text-xs uppercase transition-all">
                    Decode URL
                  </button>
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 font-bold uppercase mb-2 block">Cleartext Output</label>
                  <div className="w-full min-h-32 bg-indigo-900/10 border border-indigo-500/20 rounded-xl p-4 mono text-sm text-indigo-300 break-all whitespace-pre-wrap">
                    {decoderOutput || "O resultado aparecerá aqui..."}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer Estilo Barra de Status */}
      <footer className="h-8 bg-black border-t border-white/5 px-6 flex items-center justify-between text-[10px] font-bold text-zinc-600 shrink-0">
        <div className="flex gap-6 items-center uppercase tracking-widest">
          <span className="flex items-center gap-1.5"><Shield className="w-3 h-3 text-indigo-500" /> Anaconda System: Nominal</span>
          <span className="flex items-center gap-1.5"><Cpu className="w-3 h-3 text-indigo-500" /> CPU: {Math.floor(Math.random() * 20 + 5)}%</span>
          <span className="flex items-center gap-1.5"><HardDrive className="w-3 h-3 text-indigo-500" /> Storage: 1.2TB Free</span>
        </div>
        <div className="flex gap-6 mono text-indigo-400">
          <span>{new Date().toLocaleDateString()}</span>
          <span className="animate-pulse">CONNECTED_TO_KALI_NODE_01</span>
        </div>
      </footer>
    </div>
  );
};

export default App;