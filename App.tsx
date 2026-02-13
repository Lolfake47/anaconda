
import React, { useState, useCallback, useRef } from 'react';
import { 
  Shield, 
  Terminal, 
  Search, 
  Activity, 
  Lock, 
  Zap, 
  Globe, 
  AlertTriangle, 
  Cpu,
  RefreshCw,
  CheckCircle2,
  ChevronRight,
  FolderTree,
  ExternalLink,
  Github,
  Monitor,
  EyeOff
} from 'lucide-react';
import { ScanType, ScanResult, Severity, AIAnalysisResponse, DiscoveredDirectory } from './types.ts';
import { MOCK_SERVICES } from './constants.ts';
import { analyzeSecurityFindings } from './services/geminiService.ts';
import { SeverityBadge } from './components/ui/Badge.tsx';

const App: React.FC = () => {
  const [target, setTarget] = useState('192.168.1.54');
  const [stealthLevel, setStealthLevel] = useState<'Silent' | 'Stealth' | 'Normal'>('Stealth');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-49), `[${new Date().toLocaleTimeString()}] ${msg}`]);
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 50);
  };

  const simulateScan = useCallback(async () => {
    if (!target) return;
    
    setIsScanning(true);
    setScanProgress(0);
    setLogs([]);
    setResults(null);
    setAnalysis(null);

    addLog(`Iniciando sequência de scan em ${target}...`);
    addLog(`Modo: ${stealthLevel} | Otimizando assinatura de pacotes.`);
    
    const steps = 30;
    for (let i = 1; i <= steps; i++) {
      setScanProgress(Math.floor((i / steps) * 100));
      const delay = stealthLevel === 'Silent' ? 250 : stealthLevel === 'Stealth' ? 100 : 40;
      await new Promise(r => setTimeout(r, delay));
      
      if (i === 5) addLog("Detectando interfaces ativas...");
      if (i === 10) addLog("SYN Stealth Scan: Probing portas TCP...");
      if (i === 15) addLog("Discovery: Buscando diretórios web ocultos...");
      if (i === 20) addLog("Banner Grabbing: Identificando serviços...");
      if (i === 25) addLog("Consultando banco de dados CVE...");
    }

    const mockPorts = [21, 22, 80, 443, 445, 3306, 8080];
    const mockDirs: DiscoveredDirectory[] = [
      { path: '/admin', status: 200, size: '4.2kb', type: 'Directory' },
      { path: '/config.php', status: 200, size: '1.1kb', type: 'File' },
      { path: '/.git/config', status: 200, size: '0.5kb', type: 'Critical File' },
      { path: '/uploads', status: 403, size: '0b', type: 'Forbidden' },
    ];

    const mockVulnerabilities = [
      {
        id: 'v1',
        name: 'vsftpd 2.3.4 Backdoor',
        cve: 'CVE-2011-2523',
        severity: Severity.CRITICAL,
        description: 'Backdoor clássico que permite execução de comandos remotos.',
        exploitTheory: 'A inserção da string \":)\" no username ativa uma shell na porta 6200.',
        exploitationSteps: [
          '1. nc -v target 21',
          '2. USER root:)',
          '3. PASS qualquer_coisa',
          '4. nc -v target 6200'
        ],
        exploitUrl: 'https://www.exploit-db.com/exploits/17491',
        mitigation: 'Atualize o vsftpd para uma versão estável.'
      }
    ];

    const finalResult: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      type: ScanType.TCP,
      openPorts: mockPorts,
      services: MOCK_SERVICES,
      vulnerabilities: mockVulnerabilities,
      directories: mockDirs
    };

    setResults(finalResult);
    setIsScanning(false);
    addLog("Scan completo. Iniciando análise heurística...");
    
    setIsAnalyzing(true);
    try {
      const aiResponse = await analyzeSecurityFindings(finalResult);
      setAnalysis(aiResponse);
    } catch (err) {
      addLog("Erro na análise de IA. Verifique sua chave API.");
    } finally {
      setIsAnalyzing(false);
      addLog("Sistema pronto.");
    }
  }, [target, stealthLevel]);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-gray-300 p-4 md:p-8 flex flex-col gap-6 font-sans">
      <nav className="flex items-center justify-between border-b border-white/5 pb-4 px-2">
        <div className="flex items-center gap-2 text-indigo-500 font-bold tracking-tighter text-xl">
          <Shield className="w-6 h-6" /> SECULEARN <span className="text-gray-600 font-light">OS_V3</span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono uppercase text-gray-500">
          <span className="hidden sm:flex items-center gap-1"><Monitor className="w-3 h-3"/> ENV: KALI_LINUX</span>
          <span className="flex items-center gap-1"><Activity className="w-3 h-3 text-green-500"/> STATUS: ONLINE</span>
        </div>
      </nav>

      <header className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-[#111] p-6 rounded-2xl border border-white/5 shadow-2xl flex flex-col md:flex-row items-center gap-6">
          <div className="flex-grow w-full">
            <label className="block text-[10px] font-bold text-gray-500 uppercase mb-2 ml-1">Target IP / Domain</label>
            <div className="relative">
              <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-indigo-500" />
              <input 
                type="text" 
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Ex: 127.0.0.1"
                className="w-full bg-[#050505] border border-white/10 rounded-xl pl-10 pr-4 py-3 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-all mono"
              />
            </div>
          </div>
          
          <div className="w-full md:w-48">
            <label className="block text-[10px] font-bold text-gray-500 uppercase mb-2 ml-1">Stealth Policy</label>
            <div className="flex bg-[#050505] border border-white/10 rounded-xl p-1">
              {['Silent', 'Stealth', 'Normal'].map(level => (
                <button
                  key={level}
                  onClick={() => setStealthLevel(level as any)}
                  className={`flex-grow py-2 text-[10px] font-bold rounded-lg transition-all ${
                    stealthLevel === level ? 'bg-indigo-600 text-white shadow-lg' : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  {level[0]}
                </button>
              ))}
            </div>
          </div>

          <button 
            onClick={simulateScan}
            disabled={isScanning}
            className={`w-full md:w-auto mt-2 md:mt-0 flex items-center justify-center gap-2 px-8 py-3 rounded-xl font-bold transition-all ${
              isScanning 
              ? 'bg-gray-800 text-gray-500 cursor-not-allowed' 
              : 'bg-indigo-600 hover:bg-indigo-500 text-white active:scale-95'
            }`}
          >
            {isScanning ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
            {isScanning ? 'SCANNING' : 'RUN SCAN'}
          </button>
        </div>

        <div className="lg:col-span-4 bg-[#111] p-6 rounded-2xl border border-white/5 flex flex-col justify-center gap-4">
          <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Repository Ops</p>
          <button className="flex items-center justify-center gap-2 w-full bg-[#181818] hover:bg-[#222] border border-white/10 py-3 rounded-xl text-xs font-bold transition-colors">
            <Github className="w-4 h-4" /> Push to GitHub
          </button>
        </div>
      </header>

      <main className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-grow">
        <div className="lg:col-span-4 flex flex-col gap-6">
          <section className="bg-[#111] rounded-2xl border border-white/5 overflow-hidden flex flex-col h-[450px]">
            <div className="px-4 py-3 bg-[#181818] border-b border-white/5 flex justify-between items-center">
              <span className="text-[10px] font-bold uppercase tracking-widest text-indigo-500">Live_Console</span>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-indigo-500/50" />
              </div>
            </div>
            <div ref={logRef} className="p-4 flex-grow overflow-y-auto mono text-[11px] leading-relaxed space-y-1 bg-[#050505]">
              {logs.length === 0 && <div className="text-gray-700">Aguardando comando...</div>}
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-gray-800 shrink-0">{i}</span>
                  <span className={log.includes('CRITICAL') ? 'text-red-500' : 'text-gray-400'}>{log}</span>
                </div>
              ))}
            </div>
          </section>

          <div className="bg-indigo-900/10 p-5 rounded-2xl border border-indigo-500/20 flex items-center justify-between">
            <div>
              <p className="text-[10px] font-bold text-gray-500 uppercase mb-1">Stealth Integrity</p>
              <div className="text-2xl font-black text-indigo-400">
                {stealthLevel === 'Silent' ? '99.9%' : stealthLevel === 'Stealth' ? '85.0%' : '60.0%'}
              </div>
            </div>
            <EyeOff className="w-8 h-8 text-indigo-500/30" />
          </div>
        </div>

        <div className="lg:col-span-8 space-y-6 overflow-y-auto max-h-[calc(100vh-250px)]">
          {!results && !isScanning && (
            <div className="bg-[#111] h-full rounded-2xl border border-dashed border-white/10 flex flex-col items-center justify-center p-20 text-center">
              <Search className="w-12 h-12 text-gray-800 mb-4" />
              <p className="text-gray-600 font-mono text-sm uppercase tracking-widest">Nenhum dado de scan disponível</p>
            </div>
          )}

          {results && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-[#111] p-6 rounded-2xl border border-white/5">
                  <h3 className="font-bold text-white mb-4 text-sm flex items-center gap-2">
                    <Globe className="w-4 h-4 text-blue-500" /> Open Ports
                  </h3>
                  <div className="space-y-2">
                    {results.openPorts.map(port => (
                      <div key={port} className="flex justify-between text-xs p-2 bg-[#0a0a0a] rounded border border-white/5">
                        <span className="text-indigo-400 font-bold">{port}</span>
                        <span className="text-gray-500 uppercase">{results.services[port]}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-[#111] p-6 rounded-2xl border border-white/5">
                  <h3 className="font-bold text-white mb-4 text-sm flex items-center gap-2">
                    <FolderTree className="w-4 h-4 text-yellow-500" /> Web Directories
                  </h3>
                  <div className="space-y-2">
                    {results.directories.map((dir, i) => (
                      <div key={i} className="flex justify-between text-xs p-2 bg-[#0a0a0a] rounded border border-white/5">
                        <span className="text-gray-300 truncate">{dir.path}</span>
                        <span className="text-green-500 font-bold">{dir.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {results.vulnerabilities.map(v => (
                <div key={v.id} className="bg-[#111] p-6 rounded-2xl border border-white/5">
                  <div className="flex justify-between items-start mb-4">
                    <h3 className="text-lg font-bold text-white uppercase">{v.name}</h3>
                    <SeverityBadge severity={v.severity} />
                  </div>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <p className="text-xs text-gray-400 leading-relaxed">{v.description}</p>
                      <div className="p-3 bg-red-500/5 border border-red-500/10 rounded-lg">
                        <p className="text-[10px] font-bold text-red-500 uppercase mb-2">Exploit Steps</p>
                        {v.exploitationSteps.map((s, i) => (
                          <p key={i} className="text-[10px] font-mono text-gray-500">{s}</p>
                        ))}
                      </div>
                    </div>
                    <div className="flex flex-col gap-4">
                      <a href={v.exploitUrl} target="_blank" className="flex items-center justify-between p-3 bg-indigo-500/10 rounded-lg text-xs font-bold text-indigo-400">
                        Get Exploit Code <ExternalLink className="w-3 h-3" />
                      </a>
                      <div className="p-3 bg-green-500/5 border border-green-500/10 rounded-lg">
                        <p className="text-[10px] font-bold text-green-500 uppercase mb-2">Mitigation</p>
                        <p className="text-[10px] text-gray-400">{v.mitigation}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      <footer className="p-3 bg-[#111] rounded-xl border border-white/5 text-[10px] mono text-gray-700 text-center uppercase tracking-widest">
        SecuLearn Framework &bull; Kali Edition &bull; Simulation Mode Only
      </footer>
    </div>
  );
}

export default App;
