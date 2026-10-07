"use client";

import React, { useEffect, useState } from "react";
import { Search, Activity, RotateCcw } from "lucide-react";
import { API_URL } from "../lib/api";

type ProviderConfig = {
  enabled: boolean;
  configured: boolean;
  status: string;
};

type ProvidersResponse = {
  providers: Record<string, ProviderConfig>;
};

type TestResult = {
  provider: string;
  status: string;
  latency: string;
  error?: string;
  details?: string;
};

export function BrandHeader() {
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState<TestResult[] | null>(null);

  useEffect(() => {
    fetch(`${API_URL}/config/providers`)
      .then(res => res.json())
      .then(data => setProviders(data))
      .catch(err => console.error("Failed to load providers", err));
  }, []);

  const handleTest = async () => {
    setTesting(true);
    setTestResults(null);
    try {
      const res = await fetch(`${API_URL}/config/providers/test`, { method: "POST" });
      const data = await res.json();
      setTestResults(data);
    } catch (err) {
      console.error(err);
    } finally {
      setTesting(false);
    }
  };

  const providerMap = [
    { key: "openphish", label: "OpenPhish" },
    { key: "urlhaus", label: "URLhaus" },
    { key: "google_safe_browsing", label: "Google Safe Browsing" },
    { key: "virustotal", label: "VirusTotal" }
  ];

  return (
    <header className="w-full flex items-center justify-between py-6 px-4 md:px-8 border-b border-white/5 bg-[#08090C]/80 backdrop-blur-md sticky top-0 z-40">
      
      {/* Top Left: Logo */}
      <div className="flex items-center gap-3">
        <div className="relative w-8 h-8 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-[#00F0FF]/30 animate-ping opacity-20" />
          <Activity className="absolute w-6 h-6 text-[#00F0FF] opacity-50" />
          <Search className="absolute w-5 h-5 text-[#F4F5F7]" />
        </div>
        <div className="flex flex-col">
          <span className="font-bold text-sm tracking-wider leading-none">SCAMSENTRY</span>
          <span className="text-[10px] font-mono text-[#00F0FF] tracking-widest mt-1">AI</span>
        </div>
      </div>

      {/* Top Right: Status */}
      <div className="flex items-center gap-6">
        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-[#969BA8]">
          <span className="w-2 h-2 rounded-full bg-[#00F0FF] animate-pulse" />
          LOCAL ANALYSIS <span className="opacity-50">|</span> MODEL READY
        </div>
        
        <div className="relative group">
          <button className="text-xs font-mono text-[#969BA8] hover:text-[#F4F5F7] transition-colors border border-white/10 px-3 py-1.5 rounded bg-[#101218]">
            SETTINGS
          </button>
          
          <div className="absolute right-0 top-full mt-2 w-72 bg-[#101218] border border-[#161922] rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 p-4">
            <h3 className="text-[10px] font-mono tracking-widest text-[#5E6370] mb-3 uppercase">Threat Intelligence</h3>
            
            <div className="space-y-3 mb-4">
              <p className="text-[9px] text-[#5E6370] mb-4 font-mono leading-tight">VirusTotal checks are optional and quota-limited.</p>              {providerMap.map(p => {
                const info = providers?.providers?.[p.key];
                const status = info?.status || "UNKNOWN";
                const isReady = status === "READY";
                const color = isReady ? "text-[#00F0FF]" : "text-[#5E6370]";
                return (
                  <div key={p.key} className="flex items-center justify-between">
                    <span className="text-xs font-mono text-[#F4F5F7]">{p.label}</span>
                    <span className={`text-[10px] font-mono tracking-wider flex items-center gap-1 ${color}`}>
                      {isReady ? 'â—' : 'â—‹'} {status}
                    </span>
                  </div>
                );
              })}
            </div>

            <button 
              onClick={handleTest}
              disabled={testing}
              className="w-full py-2 bg-[#161922] hover:bg-[#1a1e28] text-[#F4F5F7] text-[10px] font-mono font-bold tracking-widest rounded border border-white/10 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {testing && <RotateCcw className="w-3 h-3 animate-spin" />}
              {testing ? "CHECKING PROVIDERS..." : "[ TEST CONNECTIONS ]"}
            </button>

            {testResults && (
              <div className="mt-4 space-y-2 border-t border-[#161922] pt-3">
                {testResults.map((r, i) => (
                  <div key={i} className="flex flex-col gap-1">
                    <div className="flex justify-between items-center text-[10px] font-mono">
                      <span className="text-[#969BA8]">{r.provider}</span>
                      <div className="flex items-center gap-2">
                        <span className={r.status === "READY" ? "text-[#00FF66]" : (r.status.includes("ERROR") ? "text-[#FF3366]" : "text-[#5E6370]")}>
                          {r.status}
                        </span>
                        <span className="text-[#5E6370]">{r.latency}</span>
                      </div>
                    </div>
                    {r.error && <span className="text-[9px] text-[#FF3366] font-mono leading-tight">{r.error}</span>}
                    {r.details && <span className="text-[9px] text-[#969BA8] font-mono leading-tight">{r.details}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

    </header>
  );
}
