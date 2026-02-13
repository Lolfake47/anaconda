
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
    setResponse("HTTP/1.1 200 OK\nContent-Type: application/json\nServer: SecuLearn/1.0\n\n{\"status\": \"active\"}");
    setIsSendingRequest(false);
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`INIT: Reconhecimento avançado iniciado em ${target}`);
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
      openPorts: [80, 443, 22],
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
        }
      ]
    };

    setResults(mockResult);
    setIsScanning(false);
    setIsAnalyzing(true);
    try {
      const aiData = await analyzeSecurityFindings(mockResult);
      setAnalysis(aiData);
    } catch (e) { addLog("ERRO: IA offline."); }
    setIsAnalyzing(false);
  }, [target, stealth]);

  // Cálculo de Risco de Detecção Visual
  const getDetectionRisk = () => {
    let risk = 10; // Base
    if (stealth.timing === 'T4') risk += 30;
    if (stealth.timing === 'T5') risk += 70;
    if (stealth.fragmentation) risk -= 15;
    if (stealth.decoys) risk -= 20;
    if (stealth.sourcePortSpoofing) risk -= 10;
    return Math.max(5, Math.min(100, risk));
  };

  return (
    <div className="flex flex-col h-screen bg-[#050505] text-gray-400 font-sans selection:bg-indigo-500/30">
      {/* Top Bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#111] border-b border-white/5 text-[11px] font-bold uppercase tracking-tighter shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-indigo-500">
            <Shield className="w-4 h-4" /> <span>SECULEARN_RED_SUITE_V4</span>
          </div>
          <div className="flex items-center gap-2 text-gray-600">
            <Monitor className="w-3 h-3" /> SESSION: KALI_X64
          </div>
        </div>
        <div className="flex items-center gap-6">
          <span className="text-gray-500">{new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex bg-[#0a0a0a] border-b border-white/5 px-2 shrink-0">
        {[
          { id: 'RECON', icon: Search, label: 'Infrastructure Recon' },
          { id: 'REPEATER', icon: Layers, label: 'Web Repeater' },
          { id: 'DECODER', icon: Code, label: 'Smart Decoder' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-6 py-3 text-[10px] font-black uppercase tracking-widest transition-all border-b-2 ${
              activeTab === tab.id 
              ? 'border-indigo-500 text-white bg-indigo-500/5' 
              : 'border-transparent text-gray-600 hover:text-gray-400'
            }`}
          >
            <tab.icon className="w-3 h-3" /> {tab.label}
          </button>
        ))}
      </div>

      <div className="flex flex-1 overflow-hidden p-4 gap-4">
        {/* Main Content Area */}
        <main className="flex-1 flex flex-col gap-4 overflow-hidden">
          
          {activeTab === 'RECON' && (
            <div className="flex-1 flex flex-col gap-4 overflow-y-auto pr-1">
              <div className="bg-[#111] p-6 rounded-xl border border-white/5 space-y-6 shrink-0">
                <div className="flex gap-4 items-center">
                  <div className="flex-1 relative">
                    <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-indigo-500" />
                    <input 
                      type="text" 
                      value={target}
                      onChange={e => setTarget(e.target.value)}
                      className="w-full bg-[#0a0a0a] border border-white/10 rounded-lg pl-10 pr-4 py-3 text-sm mono focus:border-indigo-500 outline-none"
                      placeholder="TARGET_IP"
                    />
                  </div>
                  <button 
                    onClick={simulateScan}
                    disabled={isScanning}
                    className="px-8 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-800 text-white rounded-lg font-bold text-xs flex items-center gap-2 shadow-lg shadow-indigo-500/20"
                  >
                    {isScanning ? <RefreshCw className="w-4 h-4 animate-spin"/> : <Zap className="w-4 h-4"/>}
                    EXECUTE_STEALTH_RECON
                  </button>
                </div>

                {/* Stealth Controls Panel */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-white/5">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                       <label className="text-[10px] font-bold text-gray-500 uppercase flex items-center gap-2">
                          <Gauge className="w-3 h-3 text-indigo-500"/> Aggressiveness (Timing)
                       </label>
                       <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${stealth.timing === 'T0' ? 'bg-blue-500/10 text-blue-400' : stealth.timing === 'T5' ? 'bg-red-500/10 text-red-400' : 'bg-gray-500/10'}`}>
                          {stealth.timing === 'T0' ? 'PARANOID' : stealth.timing === 'T1' ? 'SNEAKY' : stealth.timing === 'T3' ? 'NORMAL' : 'AGGRESSIVE'}
                       </span>
                    </div>
                    <input 
                      type="range" min="0" max="5" step="1"
                      value={stealth.timing.replace('T', '')}
                      onChange={(e) => setStealth({...stealth, timing: `T${e.target.value}` as any})}
                      className="w-full h-1.5 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
                    />
                    <div className="flex justify-between text-[8px] mono text-gray-600 uppercase">
                      <span>Slow/Stealth</span>
                      <span>Fast/Loud</span>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <label className="text-[10px] font-bold text-gray-500 uppercase flex items-center gap-2">
                       <Ghost className="w-3 h-3 text-indigo-500"/> Evasion Techniques
                    </label>
                    <div className="grid grid-cols-1 gap-2">
                      {[
                        { id: 'fragmentation', label: 'Packet Fragmentation (-f)', desc: 'Evade simple stateless firewalls' },
                        { id: 'decoys', label: 'Decoy Scanning (-D)', desc: 'Hide origin in noise' },
                        { id: 'sourcePortSpoofing', label: 'Source Port 53/DNS', desc: 'Bypass port restrictions' }
                      ].map(item => (
                        <label key={item.id} className="flex items-center gap-3 p-2 bg-black/40 rounded border border-white/5 hover:border-indigo-500/30 cursor-pointer transition-all">
                          <input 
                            type="checkbox"
                            checked={(stealth as any)[item.id]}
                            onChange={(e) => setStealth({...stealth, [item.id]: e.target.checked})}
                            className="w-3 h-3 rounded bg-gray-800 border-gray-700 text-indigo-500 focus:ring-0"
                          />
                          <div>
                            <div className="text-[10px] font-bold text-gray-300">{item.label}</div>
                            <div className="text-[8px] text-gray-600">{item.desc}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Detection Risk Indicator */}
                <div className="pt-4 border-t border-white/5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[9px] font-bold text-gray-500 uppercase flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3"/> Firewall Detection Risk
                    </span>
                    <span className={`text-[10px] font-black mono ${getDetectionRisk() > 60 ? 'text-red-500' : 'text-green-500'}`}>
                      {getDetectionRisk()}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-900 h-1 rounded-full overflow-hidden">
                    <div 
                      className={`h-full transition-all duration-1000 ${getDetectionRisk() > 60 ? 'bg-red-600 shadow-[0_0_10px_rgba(220,38,38,0.5)]' : 'bg-green-600'}`}
                      style={{ width: `${getDetectionRisk()}%` }}
                    />
                  </div>
                </div>
              </div>

              {results && (
                <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                   <div className="bg-[#111] p-6 rounded-xl border border-white/5">
                      <div className="flex items-center justify-between mb-6">
                         <h3 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
                            <Activity className="w-4 h-4 text-indigo-500" /> Vulnerability Assessment
                         </h3>
                         <SeverityBadge severity={results.vulnerabilities[0].severity} />
                      </div>
                      {results.vulnerabilities.map(v => (
                        <div key={v.id} className="space-y-4">
                           <h4 className="text-xl font-bold text-indigo-400">{v.name}</h4>
                           <div className="p-4 bg-black/50 rounded-lg border border-white/5 text-sm leading-relaxed">
                              {v.description}
                           </div>
                           <div className="p-4 bg-red-950/10 rounded-lg border border-red-900/20">
                              <p className="text-[10px] font-bold text-red-500 uppercase mb-2">Manual Exploitation Step</p>
                              <code className="text-xs mono text-gray-300 bg-black p-2 block rounded border border-white/5">
                                 {v.exploitationSteps[0]}
                              </code>
                           </div>
                        </div>
                      ))}
                   </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'REPEATER' && (
            <div className="flex-1 flex flex-col gap-4 overflow-hidden">
               {/* Repeater UI... (mantido conforme a versão anterior para brevidade, mas funcional) */}
               <div className="grid grid-cols-2 flex-1 gap-4 overflow-hidden">
                  <div className="bg-[#111] rounded-xl border border-white/5 flex flex-col">
                    <div className="p-3 bg-[#181818] border-b border-white/5 flex items-center justify-between">
                      <span className="text-[9px] font-black uppercase text-indigo-400">Request Editor</span>
                      <button onClick={handleSendRequest} className="bg-indigo-600 text-white px-3 py-1 rounded text-[9px] font-bold">SEND</button>
                    </div>
                    <textarea value={request.headers} onChange={e => setRequest({...request, headers: e.target.value})} className="flex-1 bg-black p-4 text-[11px] mono outline-none resize-none text-gray-400" />
                  </div>
                  <div className="bg-[#111] rounded-xl border border-white/5 flex flex-col">
                    <div className="p-3 bg-[#181818] border-b border-white/5 text-[9px] font-black uppercase text-green-500">Response</div>
                    <pre className="flex-1 p-4 text-[11px] mono text-green-500/80 overflow-auto">{response}</pre>
                  </div>
               </div>
            </div>
          )}

          {activeTab === 'DECODER' && (
             <div className="bg-[#111] p-6 rounded-xl border border-white/5 flex-1 flex flex-col gap-4">
                <textarea 
                  value={decoderInput} 
                  onChange={e => setDecoderInput(e.target.value)}
                  className="h-1/2 bg-black border border-white/10 rounded-lg p-4 mono text-sm"
                  placeholder="Paste here to Encode/Decode..."
                />
                <div className="flex gap-2">
                  <button onClick={() => setDecoderOutput(btoa(decoderInput))} className="flex-1 py-2 bg-indigo-600 text-white rounded font-bold text-xs uppercase">B64 Encode</button>
                  <button onClick={() => setDecoderOutput(atob(decoderInput))} className="flex-1 py-2 bg-indigo-900 text-white rounded font-bold text-xs uppercase">B64 Decode</button>
                </div>
                <div className="flex-1 bg-black/50 p-4 border border-white/10 rounded-lg mono text-sm text-indigo-400 overflow-auto">
                  {decoderOutput}
                </div>
             </div>
          )}
        </main>

        {/* Sidebar Logs (Persistent) */}
        <aside className="w-80 flex flex-col gap-4 shrink-0 overflow-hidden">
          <div className="bg-[#111] flex-1 rounded-xl border border-white/5 overflow-hidden flex flex-col">
            <div className="px-4 py-2 bg-[#181818] text-[9px] font-black uppercase tracking-widest text-gray-500 flex justify-between shrink-0">
              Active_Monitor <Activity className="w-3 h-3"/>
            </div>
            <div ref={logRef} className="flex-1 p-4 mono text-[10px] space-y-1 overflow-y-auto bg-black/50">
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-gray-700 select-none">{i}</span>
                  <span className={`break-all ${log.includes('ALERTA') ? 'text-red-500 font-bold' : log.includes('EVASION') ? 'text-indigo-400' : 'text-gray-400'}`}>{log}</span>
                </div>
              ))}
              {isScanning && (
                <div className="mt-2 text-indigo-500 animate-pulse">
                  EXECUTING_SCAN: {scanProgress}% [##########]
                </div>
              )}
            </div>
          </div>
          
          <div className="bg-indigo-600/10 p-4 rounded-xl border border-indigo-500/20 text-center">
             <p className="text-[9px] font-bold text-indigo-500 uppercase mb-1">Evasion Strategy</p>
             <p className="text-[10px] text-gray-400 italic">
               {getDetectionRisk() > 60 
                 ? "Atenção: Agressividade alta pode alertar SIEM/SOC." 
                 : "Tática Sneaky ativa: Bypass de assinaturas simples."}
             </p>
          </div>
        </aside>
      </div>

      <footer className="px-4 py-2 bg-[#111] border-t border-white/5 flex justify-between items-center text-[10px] font-bold text-gray-700 shrink-0">
        <div className="flex gap-4">
          <span>&copy; SECULEARN // KALI_SYSTEM_V4</span>
          <span className="text-indigo-500/50">STEALTH_MODE: {getDetectionRisk() < 30 ? 'OPTIMIZED' : 'LOUD'}</span>
        </div>
        <div className="flex gap-4">
          <span className="flex items-center gap-1"><HardDrive className="w-3 h-3"/> ENCRYPTED_FS</span>
          <span className="text-indigo-500">ENGINE: V4.1_FLASH_AI</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
