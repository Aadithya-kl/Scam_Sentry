import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { ShieldAlert, Activity, Search, Crosshair, AlertTriangle, CheckCircle2 } from 'lucide-react';

const API_URL = process.env.API_BASE_URL || "http://localhost:8000";
const DASHBOARD_URL = process.env.DASHBOARD_URL || "http://localhost:3000";

const SIMULATION_STEPS = [
  "READING URL...",
  "INSPECTING STRUCTURE...",
  "QUERYING THREAT INTEL...",
  "FUSING EVIDENCE...",
  "FINAL VERDICT..."
];

const PAGE_SIMULATION_STEPS = [
  "READING PAGE...",
  "EXTRACTING LINKS...",
  "NORMALIZING DOMAINS...",
  "CHECKING THREAT INTEL...",
  "BUILDING PAGE RISK...",
  "FINAL VERDICT..."
];

function Popup() {
  const [mode, setMode] = useState<'URL' | 'PAGE'>('URL');
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [currentDomain, setCurrentDomain] = useState<string>('');
  
  const [status, setStatus] = useState<'IDLE' | 'SCANNING' | 'DONE' | 'ERROR'>('IDLE');
  const [simStep, setSimStep] = useState(0);
  const [result, setResult] = useState<any>(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [intelStatus, setIntelStatus] = useState<string>("CHECKING INTELLIGENCE...");
  const [tabId, setTabId] = useState<number | null>(null);

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || '';
      setCurrentUrl(url);
      setTabId(tabs[0]?.id || null);
      try {
        const urlObj = new URL(url);
        setCurrentDomain(urlObj.hostname);
      } catch (e) {
        setCurrentDomain('Invalid URL');
      }
    });

    fetch(`${API_URL}/config/providers`)
      .then(res => res.json())
      .then(data => {
         const providers = data.providers || {};
         let online = 0;
         let total = 0;
         for (const [key, val] of Object.entries(providers)) {
            const v = val as any;
            if (v.enabled) {
              total++;
              if (v.status === "READY") {
                online++;
              }
            }
         }
         if (online > 0) {
           setIntelStatus(`${online} / ${total} ONLINE`);
         } else {
           setIntelStatus("LOCAL ONLY");
         }
      })
      .catch(() => {
         setIntelStatus("LOCAL ONLY");
      });
  }, []);

  const getLinksFromPage = async (): Promise<string[]> => {
    if (!tabId) return [];
    
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          const links = Array.from(document.querySelectorAll('a[href]')).map(a => (a as HTMLAnchorElement).href);
          return links;
        }
      });
      
      if (results && results[0] && results[0].result) {
        let rawLinks = results[0].result as string[];
        let validLinks = new Set<string>();
        
        for (let href of rawLinks) {
          try {
            if (href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('chrome:')) {
               continue;
            }
            const urlObj = new URL(href, currentUrl);
            validLinks.add(urlObj.href.split('#')[0]);
          } catch {}
        }
        return Array.from(validLinks);
      }
    } catch (e) {
       console.error("Failed to inject script", e);
    }
    return [];
  };

  const handleScan = async () => {
    if (!currentUrl.startsWith('http')) {
      setStatus('ERROR');
      setErrorMessage("Cannot scan internal browser pages.");
      return;
    }

    setStatus('SCANNING');
    setSimStep(0);
    
    const steps = mode === 'PAGE' ? PAGE_SIMULATION_STEPS : SIMULATION_STEPS;
    
    const stepInterval = setInterval(() => {
      setSimStep(s => Math.min(s + 1, steps.length - 1));
    }, mode === 'PAGE' ? 800 : 400);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

      let response;
      if (mode === 'URL') {
        response = await fetch(`${API_URL}/scan-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: currentUrl }),
          signal: controller.signal
        });
      } else {
        const links = await getLinksFromPage();
        response = await fetch(`${API_URL}/scan-page`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ page_url: currentUrl, links: links }),
          signal: controller.signal
        });
      }
      
      clearTimeout(timeoutId);

      if (!response.ok) {
        let msg = "Analysis engine isn't reachable.";
        try {
           const errBody = await response.json();
           if (errBody.detail && typeof errBody.detail === "string") {
             msg = errBody.detail;
           } else if (errBody.error && errBody.error.message) {
             msg = errBody.error.message;
             if (errBody.error.details && Array.isArray(errBody.error.details) && errBody.error.details.length > 0) {
                 msg = errBody.error.details.map((issue: any) => issue.msg ?? "Invalid input").join(" ");
             }
           }
        } catch {}
        throw new Error(msg);
      }
      
      let data = await response.json();
      
      // Normalize safe defaults to prevent crashes
      data = {
        prediction: data.prediction || "SAFE",
        risk_level: data.risk_level || "LOW",
        risk_score: data.risk_score || 0,
        total_links_found: data.total_links_found || 0,
        links_analyzed: data.links_analyzed || 0,
        summary: data.summary || { clean: 0, suspicious: 0, threats: 0 },
        threat_intelligence: data.threat_intelligence || [],
        scan_id: data.scan_id || null
      };

      setTimeout(() => {
        clearInterval(stepInterval);
        setResult(data);
        setStatus('DONE');
      }, 500);
      
    } catch (err: any) {
      clearInterval(stepInterval);
      setStatus('ERROR');
      if (err.name === 'AbortError') {
        setErrorMessage("Analysis timeout. The server took too long to respond.");
      } else {
        setErrorMessage(err.message || "Failed to connect to ScamSentry.");
      }
    }
  };

  const openDashboard = () => {
    if (mode === 'PAGE' && result?.scan_id) {
       chrome.tabs.create({ url: `${DASHBOARD_URL}/?scan_id=${result.scan_id}` });
    } else {
       chrome.tabs.create({ url: `${DASHBOARD_URL}/?url=${encodeURIComponent(currentUrl)}` });
    }
  };

  return (
    <div className="flex flex-col h-full bg-bgBase p-4 font-sans text-textPrimary relative z-10 w-[320px] min-h-[400px]">
      
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-white/5 pb-3 mb-4">
        <div className="relative w-6 h-6 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-accentCyan/30 animate-ping opacity-20" />
          <Activity className="absolute w-4 h-4 text-accentCyan opacity-50" />
          <Search className="absolute w-3 h-3 text-textPrimary" />
        </div>
        <div className="flex flex-col flex-1">
          <span className="font-bold text-xs tracking-wider leading-none">SCAMSENTRY</span>
          <span className="text-[8px] font-mono tracking-widest mt-0.5" style={{ color: intelStatus === 'LOCAL ONLY' ? '#969BA8' : '#00F0FF' }}>
            INTELLIGENCE: {intelStatus}
          </span>
        </div>
        
        {/* Mode Toggle */}
        <div className="flex bg-bgSurface rounded border border-bgElevated p-0.5 ml-auto text-[10px] font-mono font-bold">
          <button 
            onClick={() => setMode('URL')} 
            className={`px-2 py-1 rounded transition-colors ${mode === 'URL' ? 'bg-accentCyan/10 text-accentCyan' : 'text-textSecondary hover:text-textPrimary'}`}
          >
            URL
          </button>
          <button 
            onClick={() => setMode('PAGE')} 
            className={`px-2 py-1 rounded transition-colors ${mode === 'PAGE' ? 'bg-accentCyan/10 text-accentCyan' : 'text-textSecondary hover:text-textPrimary'}`}
          >
            PAGE
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col justify-start">
        
        {status === 'IDLE' && (
          <div className="flex flex-col h-full gap-4">
            <div>
              <div className="text-[10px] font-mono tracking-widest text-textSecondary mb-1">CURRENT PAGE</div>
              <div className="text-xs font-mono text-textPrimary break-all bg-bgSurface p-2 rounded border border-bgElevated">
                {currentDomain}
              </div>
            </div>
            
            <div className="flex flex-col gap-2 mt-2">
               <div className="flex items-center gap-2 text-[10px] font-mono text-accentCyan">
                  <span className="w-1.5 h-1.5 rounded-full bg-accentCyan animate-pulse" /> LOCAL ENGINE READY
               </div>
               <div className="flex items-center gap-2 text-[10px] font-mono" style={{ color: intelStatus === 'LOCAL ONLY' ? '#969BA8' : '#00F0FF' }}>
                  <span className={`w-1.5 h-1.5 rounded-full ${intelStatus === 'LOCAL ONLY' ? 'bg-[#969BA8]' : 'bg-accentCyan animate-pulse'}`} /> 
                  {intelStatus === 'LOCAL ONLY' ? 'LOCAL ANALYSIS ONLY' : 'THREAT INTELLIGENCE READY'}
               </div>
            </div>
            
            <button 
              onClick={handleScan}
              className="mt-auto w-full py-3 bg-accentCyan/10 text-accentCyan border border-accentCyan/30 hover:bg-accentCyan/20 text-xs font-mono font-bold tracking-widest rounded flex items-center justify-center gap-2 transition-colors uppercase"
            >
              <Crosshair className="w-4 h-4" />
              {mode === 'PAGE' ? 'SCAN CURRENT PAGE' : 'SCAN THIS URL'}
            </button>
            <div className="text-[9px] text-textMuted text-center">
              {mode === 'PAGE' 
                ? "ScamSentry only inspects page links when you explicitly request a scan." 
                : `ScamSentry analyzes the URL you choose to scan.${intelStatus === 'LOCAL ONLY' ? " No external threat-intelligence sources are available." : " It does not automatically inspect every page you visit."}`
              }
            </div>
          </div>
        )}

        {status === 'SCANNING' && (
          <div className="flex flex-col items-center justify-center h-48 border border-accentCyan/20 bg-accentCyan/5 rounded-lg relative overflow-hidden">
             <div className="absolute inset-0 flex items-center justify-center opacity-10">
               <div className="w-32 h-32 border border-accentCyan rounded-full animate-ping" />
             </div>
             <Search className="w-6 h-6 text-accentCyan animate-pulse mb-4 relative z-10" />
             <div className="text-[10px] font-mono tracking-widest text-accentCyan relative z-10 text-center uppercase">
                {mode === 'PAGE' ? PAGE_SIMULATION_STEPS[simStep] : SIMULATION_STEPS[simStep]}
             </div>
          </div>
        )}

        {status === 'ERROR' && (
          <div className="flex flex-col items-center justify-center h-48 border border-statusScam/20 bg-statusScam/5 rounded-lg">
             <AlertTriangle className="w-8 h-8 text-statusScam mb-2" />
             <div className="text-xs font-bold text-statusScam tracking-widest mb-1 uppercase">SCAMSENTRY OFFLINE</div>
             <div className="text-[10px] text-textSecondary text-center px-4">{errorMessage}</div>
             <button onClick={() => setStatus('IDLE')} className="mt-4 text-[10px] font-mono border border-white/10 px-3 py-1 rounded hover:bg-white/5">BACK</button>
          </div>
        )}

        {status === 'DONE' && result && (
          <div className="flex flex-col gap-4 animate-in fade-in">
             <div className="text-[10px] font-mono tracking-widest text-textSecondary uppercase">
               {mode === 'PAGE' ? 'PAGE RISK' : 'RISK'}
             </div>
             
             {/* Score Ring */}
             <div className="flex items-center gap-6 mb-2">
                <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                  <svg className="absolute inset-0 w-full h-full transform -rotate-90">
                    <circle cx="32" cy="32" r="28" fill="transparent" stroke="#161922" strokeWidth="4" />
                    <circle 
                      cx="32" cy="32" r="28" fill="transparent" 
                      stroke={result.risk_level === 'CRITICAL' ? '#FF3366' : result.risk_level === 'HIGH' ? '#FF7B00' : result.risk_level === 'MEDIUM' ? '#FFB800' : '#00F0FF'} 
                      strokeWidth="4" 
                      strokeDasharray={2 * Math.PI * 28} 
                      strokeDashoffset={(2 * Math.PI * 28) - ((result.risk_score / 100) * (2 * Math.PI * 28))} 
                    />
                  </svg>
                  <div className="flex flex-col items-center justify-center relative z-10">
                    <span className="text-lg font-mono font-bold leading-none">{result.risk_score}</span>
                  </div>
                </div>
                
                <div className="flex flex-col">
                  <div className={`text-sm font-bold tracking-wide uppercase ${result.risk_level === 'CRITICAL' ? 'text-statusScam' : result.risk_level === 'HIGH' ? 'text-statusSpam' : result.risk_level === 'MEDIUM' ? 'text-statusSuspicious' : 'text-statusSafe'}`}>
                    {mode === 'PAGE' ? (
                       result.prediction === 'SAFE' ? 'CLEAN PAGE' : result.prediction === 'SUSPICIOUS' ? 'SUSPICIOUS PAGE' : 'THREAT DETECTED'
                    ) : (
                       result.prediction === 'SAFE' ? 'LOOKS CLEAN' : result.prediction === 'SUSPICIOUS' ? 'TAKE A CLOSER LOOK' : result.prediction === 'SPAM' ? 'LIKELY SPAM' : 'SCAM DETECTED'
                    )}
                  </div>
                  <div className="text-[10px] font-mono text-textSecondary uppercase">{result.risk_level} RISK</div>
                </div>
             </div>

             {mode === 'PAGE' ? (
                <div className="flex flex-col gap-2">
                   <div className="flex justify-between text-[10px] font-mono border-b border-white/5 pb-2">
                      <span className="text-textSecondary">LINKS FOUND</span>
                      <span className="text-textPrimary">{result.total_links_found}</span>
                   </div>
                   <div className="flex justify-between text-[10px] font-mono border-b border-white/5 pb-2">
                      <span className="text-textSecondary">ANALYZED</span>
                      <span className="text-textPrimary">{result.links_analyzed} EXTERNAL</span>
                   </div>
                   <div className="mt-2 space-y-1">
                      {result.summary.threats > 0 && <div className="text-[10px] font-mono text-statusScam">âš  {result.summary.threats} THREAT DETECTED</div>}
                      {result.summary.suspicious > 0 && <div className="text-[10px] font-mono text-statusSuspicious">! {result.summary.suspicious} SUSPICIOUS LINKS</div>}
                      {result.summary.clean > 0 && <div className="text-[10px] font-mono text-statusSafe">âœ“ {result.summary.clean} LOW-RISK LINKS</div>}
                   </div>
                </div>
             ) : (
                <div className="bg-bgSurface border border-bgElevated rounded p-3 space-y-2">
                  {result.threat_intelligence?.map((t: any, idx: number) => {
                    const isMatch = t.status === "MATCH";
                    return (
                      <div key={idx} className="flex items-center justify-between text-[9px] font-mono">
                        <span className="text-textPrimary flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${isMatch ? 'bg-statusScam' : 'bg-statusSafe'}`} />
                          {t.provider}
                        </span>
                        {t.provider === "VirusTotal" && t.malicious_votes !== undefined && ( <span className="text-[8px] text-textSecondary mr-2">{t.malicious_votes} malicious / {(t.malicious_votes || 0) + (t.suspicious_votes || 0) + (t.harmless_votes || 0)} engines</span> )} <span className={isMatch ? 'text-statusScam font-bold' : 'text-textSecondary'}>
                          {isMatch ? 'MATCH' : t.status.replace(/_/g, ' ')}
                        </span>
                      </div>
                    );
                  })}
                </div>
             )}

             <button 
               onClick={openDashboard}
               className="mt-2 w-full py-2 bg-bgSurface border border-bgElevated hover:border-white/20 text-xs font-mono text-textPrimary rounded flex items-center justify-center gap-2 transition-colors uppercase"
             >
               VIEW FULL ANALYSIS &rarr;
             </button>
          </div>
        )}

      </div>
    </div>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<Popup />);
