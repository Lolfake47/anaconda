
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { 
  Shield, Terminal, Search, Activity, Zap, Globe, AlertTriangle, 
  Cpu, RefreshCw, ChevronRight, FolderTree, ExternalLink, 
  Github, Monitor, Copy, Download, HardDrive, Layers, Code, Play, Hash
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, HttpRequest } from './types.ts';
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

  const decodeBase64 = () => {
    try {
      setDecoderOutput(atob(decoderInput));
      addLog("DECODER: Base64 string processada.");
    } catch {
      setDecoderOutput("ERRO: String Base64 inválida.");
    }
  };

  const encodeBase64 = () => {
    setDecoderOutput(btoa(decoderInput));
    addLog("DECODER: String codificada em Base64.");
  };

  const handleSendRequest = async () => {
    setIsSendingRequest(true);
    addLog(`REPEATER: Enviando ${request.method} para ${request.url}`);
    
    // Simulação de delay de rede
    await new Promise(r => setTimeout(r, 1200));

    // Lógica de simulação de vulnerabilidade baseada no input
    let simulatedResponse = "HTTP/1.1 200 OK\nContent-Type: application/json\nServer: Apache/2.4.18\n\n";
    
    if (request.url.includes("'") || request.body.includes("'")) {
      simulatedResponse += '{"error": "SQL Syntax Error near \'\'", "query": "SELECT * FROM users WHERE id = \'" }';
      addLog("REPEATER: Possível Injeção SQL detectada na resposta!");
    } else if (request.url.includes("<script>")) {
      simulatedResponse += '<html><body><h1>User: <script>alert(1)</script></h1></body></html>';
      addLog("REPEATER: Reflected XSS confirmado na resposta.");
    } else {
      simulatedResponse += '{"status": "success", "data": {"id": 1, "username": "admin", "role": "superuser"}}';
    }

    setResponse(simulatedResponse);
    setIsSendingRequest(false);
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`INIT: Sequência de reconhecimento em ${target}`);
    
    const sequence = [
      { p: 10, m: "Iniciando NMAP Stealth Scan (SYN)..." },
      { p: 30, m: "Enumeração de portas concluída." },
      { p: 50, m: "Fuzzing de diretórios (Burp Intruder mode)..." },
      { p: 90, m: "Análise de vulnerabilidades web (OWASP Top 10)..." }
    ];

    for (const step of sequence) {
      await new Promise(r => setTimeout(r, 400));
      setScanProgress(step.p);
      addLog(step.m);
    }

    const mockResult: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      type: ScanType.TCP,
      openPorts: [80, 443, 8080],
      services: MOCK_SERVICES,
      directories: [
        { path: '/admin', status: 200, size: '2kb', type: 'DIR' },
        { path: '/.env', status: 200, size: '1kb', type: 'SENSITIVE' },
      ],
      vulnerabilities: [
        {
          id: '1',
          name: 'Unauthenticated IDOR',
          severity: Severity.HIGH,
          description: 'A API permite acessar dados de outros usuários apenas trocando o ID na URL.',
          exploitTheory: 'Falta de verificação de propriedade no backend.',
          exploitationSteps: [
            '1. Abra o REPEATER',
            '2. Mude o ID de 1 para 2',
            '3. Analise se os dados retornados pertencem a outro usuário'
          ],
          exploitUrl: 'https://portswigger.net/web-security/access-control/idor',
          mitigation: 'Implementar Access Control Lists (ACL) e validar sessões.'
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
      addLog("ERRO: IA offline.");
    }
    setIsAnalyzing(false);
  }, [target]);

  return (
    <div className="flex flex-col h-screen bg-[#050505] text-gray-400 font-sans selection:bg-indigo-500/30">
      {/* Top Bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#111] border-b border-white/5 text-[11px] font-bold uppercase tracking-tighter shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-indigo-500">
            <Shield className="w-4 h-4" /> <span>SECULEARN_WEB_SUITE</span>
          </div>
          <div className="flex items-center gap-2 text-gray-600">
            <Monitor className="w-3 h-3" /> TTY1
          </div>
        </div>
        <div className="flex items-center gap-6">
          <span className="text-green-500/80 flex items-center gap-1"><Activity className="w-3 h-3"/> KALI_STABLE</span>
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
            <div className="flex-1 flex flex-col gap-4 overflow-y-auto">
              <div className="bg-[#111] p-5 rounded-xl border border-white/5 flex gap-4 items-center shrink-0">
                <div className="flex-1 relative">
                  <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-indigo-500" />
                  <input 
                    type="text" 
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    className="w-full bg-[#0a0a0a] border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm mono focus:border-indigo-500 focus:outline-none"
                    placeholder="TARGET_IP_OR_DOMAIN"
                  />
                </div>
                <button 
                  onClick={simulateScan}
                  disabled={isScanning}
                  className="px-6 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-800 text-white rounded-lg font-bold text-xs flex items-center gap-2"
                >
                  {isScanning ? <RefreshCw className="w-3 h-3 animate-spin"/> : <Zap className="w-3 h-3"/>}
                  RUN_SCAN
                </button>
              </div>

              {results && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-[#111] p-4 rounded-xl border border-white/5">
                    <h3 className="text-[10px] font-bold text-indigo-400 uppercase mb-3 flex items-center gap-2">
                      <Globe className="w-3 h-3"/> Ports Found
                    </h3>
                    <div className="space-y-1">
                      {results.openPorts.map(p => (
                        <div key={p} className="flex justify-between p-2 bg-black/30 rounded text-[11px] mono">
                          <span>{p}/TCP</span>
                          <span className="text-gray-600">{results.services[p]}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="bg-[#111] p-4 rounded-xl border border-white/5">
                    <h3 className="text-[10px] font-bold text-yellow-500 uppercase mb-3 flex items-center gap-2">
                      <FolderTree className="w-3 h-3"/> Directory Fuzz
                    </h3>
                    <div className="space-y-1">
                      {results.directories.map((d, i) => (
                        <div key={i} className="flex justify-between p-2 bg-black/30 rounded text-[11px] mono">
                          <span>{d.path}</span>
                          <span className="text-green-500">{d.status}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'REPEATER' && (
            <div className="flex-1 flex flex-col gap-4 overflow-hidden">
              <div className="grid grid-cols-2 flex-1 gap-4 overflow-hidden">
                {/* Request Side */}
                <div className="bg-[#111] rounded-xl border border-white/5 flex flex-col overflow-hidden">
                  <div className="p-3 bg-[#181818] border-b border-white/5 flex items-center justify-between">
                    <span className="text-[9px] font-black uppercase text-indigo-400">Request Editor</span>
                    <button 
                      onClick={handleSendRequest}
                      disabled={isSendingRequest}
                      className="bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded text-[9px] font-bold flex items-center gap-2"
                    >
                      {isSendingRequest ? <RefreshCw className="w-3 h-3 animate-spin"/> : <Play className="w-3 h-3"/>}
                      SEND
                    </button>
                  </div>
                  <div className="flex-1 p-4 space-y-4 overflow-y-auto">
                    <div className="flex gap-2">
                      <select 
                        value={request.method}
                        onChange={e => setRequest({...request, method: e.target.value})}
                        className="bg-[#0a0a0a] border border-white/10 rounded px-2 py-1 text-[11px] mono text-indigo-400"
                      >
                        {['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'].map(m => <option key={m}>{m}</option>)}
                      </select>
                      <input 
                        type="text" 
                        value={request.url}
                        onChange={e => setRequest({...request, url: e.target.value})}
                        className="flex-1 bg-[#0a0a0a] border border-white/10 rounded px-3 py-1 text-[11px] mono focus:outline-none"
                      />
                    </div>
                    <div className="flex-1 flex flex-col gap-2 h-full">
                       <label className="text-[9px] font-bold text-gray-600 uppercase">Headers</label>
                       <textarea 
                         value={request.headers}
                         onChange={e => setRequest({...request, headers: e.target.value})}
                         className="flex-1 bg-[#050505] border border-white/10 rounded p-3 text-[11px] mono focus:outline-none resize-none min-h-[150px]"
                       />
                       <label className="text-[9px] font-bold text-gray-600 uppercase">Body</label>
                       <textarea 
                         value={request.body}
                         onChange={e => setRequest({...request, body: e.target.value})}
                         className="h-32 bg-[#050505] border border-white/10 rounded p-3 text-[11px] mono focus:outline-none resize-none"
                         placeholder="(Optional for POST/PUT)"
                       />
                    </div>
                  </div>
                </div>

                {/* Response Side */}
                <div className="bg-[#111] rounded-xl border border-white/5 flex flex-col overflow-hidden">
                  <div className="p-3 bg-[#181818] border-b border-white/5 flex items-center gap-2">
                    <span className="text-[9px] font-black uppercase text-green-500">Server Response</span>
                  </div>
                  <pre className="flex-1 p-4 text-[11px] mono bg-[#050505] overflow-auto whitespace-pre-wrap text-green-500/80">
                    {response}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'DECODER' && (
            <div className="flex-1 flex flex-col gap-4">
              <div className="bg-[#111] p-6 rounded-xl border border-white/5 flex-1 flex flex-col gap-4">
                <div className="flex items-center justify-between border-b border-white/5 pb-4">
                   <div className="flex items-center gap-2 text-white font-bold text-xs uppercase">
                      <Hash className="w-4 h-4 text-indigo-500" /> Encoder / Decoder Tools
                   </div>
                </div>
                <div className="grid grid-cols-2 gap-6 flex-1">
                  <div className="flex flex-col gap-2">
                    <label className="text-[10px] font-bold text-gray-500 uppercase">Input Text</label>
                    <textarea 
                      value={decoderInput}
                      onChange={e => setDecoderInput(e.target.value)}
                      className="flex-1 bg-[#0a0a0a] border border-white/10 rounded-xl p-4 text-sm mono focus:border-indigo-500 outline-none resize-none"
                      placeholder="Paste your string here..."
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-[10px] font-bold text-gray-500 uppercase">Output Result</label>
                    <div className="flex-1 bg-[#050505] border border-white/10 rounded-xl p-4 text-sm mono text-indigo-400 break-all overflow-y-auto">
                      {decoderOutput || <span className="text-gray-800">Resultado aparecerá aqui...</span>}
                    </div>
                  </div>
                </div>
                <div className="flex gap-4">
                  <button onClick={decodeBase64} className="flex-1 py-3 bg-[#181818] hover:bg-indigo-600 text-white rounded-lg font-bold text-[10px] uppercase transition-all">Decode Base64</button>
                  <button onClick={encodeBase64} className="flex-1 py-3 bg-[#181818] hover:bg-indigo-600 text-white rounded-lg font-bold text-[10px] uppercase transition-all">Encode Base64</button>
                  <button onClick={() => setDecoderOutput(encodeURIComponent(decoderInput))} className="flex-1 py-3 bg-[#181818] hover:bg-indigo-600 text-white rounded-lg font-bold text-[10px] uppercase transition-all">URL Encode</button>
                  <button onClick={() => setDecoderOutput(decodeURIComponent(decoderInput))} className="flex-1 py-3 bg-[#181818] hover:bg-indigo-600 text-white rounded-lg font-bold text-[10px] uppercase transition-all">URL Decode</button>
                </div>
              </div>
            </div>
          )}
        </main>

        {/* Sidebar Logs (Persistent) */}
        <aside className="w-80 flex flex-col gap-4 shrink-0 overflow-hidden">
          <div className="bg-[#111] flex-1 rounded-xl border border-white/5 overflow-hidden flex flex-col">
            <div className="px-4 py-2 bg-[#181818] text-[9px] font-black uppercase tracking-widest text-gray-500 flex justify-between shrink-0">
              System_Logs <Activity className="w-3 h-3"/>
            </div>
            <div ref={logRef} className="flex-1 p-4 mono text-[10px] space-y-1 overflow-y-auto bg-black/50">
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-gray-700 select-none">{i}</span>
                  <span className={`break-all ${log.includes('detectada') ? 'text-red-500' : 'text-gray-400'}`}>{log}</span>
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
             <p className="text-[9px] font-bold text-indigo-500 uppercase mb-1">Active Intelligence</p>
             <p className="text-[10px] text-gray-400 italic">"Analise cabeçalhos para encontrar Server Fingerprinting."</p>
          </div>
        </aside>
      </div>

      <footer className="px-4 py-2 bg-[#111] border-t border-white/5 flex justify-between items-center text-[10px] font-bold text-gray-700 shrink-0">
        <div className="flex gap-4">
          <span>&copy; SECULEARN // KALI_WEB_SUITE</span>
          <span className="text-indigo-500/50">SIMULATION_ACTIVE</span>
        </div>
        <div className="flex gap-4">
          <span className="flex items-center gap-1"><HardDrive className="w-3 h-3"/> DISK_ENCRYPTED</span>
          <span className="text-indigo-500">ENGINE: V3.2_FLASH</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
