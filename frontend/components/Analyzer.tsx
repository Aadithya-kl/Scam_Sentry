"use client";

import React, { useState, useEffect } from "react";
import { Search, RotateCcw, Crosshair } from "lucide-react";
import { analyzeMessage, ApiError, API_URL } from "../lib/api";
import { EXAMPLES } from "../lib/examples";
import type { PredictResponse } from "../lib/types";
import { ResultCard } from "./ResultCard";
import { PageResultCard } from "./PageResultCard";

export function Analyzer() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [simStep, setSimStep] = useState(0);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const SIMULATION_STEPS = [
    "01 PARSING MESSAGE...",
    "02 EXTRACTING IOCS...",
    "03 INSPECTING URL...",
    "04 QUERYING THREAT INTEL...",
    "05 FUSING EVIDENCE...",
    "06 FINAL VERDICT..."
  ];

  const handleAnalyze = async (messageToAnalyze: string, isUrlOnly: boolean = false) => {
    const trimmed = messageToAnalyze.trim();
    if (!trimmed) {
      setError("Please enter a message to analyze.");
      return;
    }
    
    setLoading(true);
    setSimulating(true);
    setSimStep(0);
    setError(null);
    setResult(null);

    // Start simulation steps
    const stepInterval = setInterval(() => {
      setSimStep(s => Math.min(s + 1, SIMULATION_STEPS.length - 1));
    }, 400); // about 2 seconds total for 5 steps

    let res: any = null;
    let apiError: string | null = null;

    try {
      if (isUrlOnly) {
        // We need to import scanUrl from api.ts (already exported there)
        const { scanUrl } = require("../lib/api");
        res = await scanUrl(trimmed);
      } else {
        res = await analyzeMessage(trimmed);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        apiError = err.message;
      } else {
        apiError = "Analysis interrupted due to connection error.";
      }
    }

    if (res) {
      // Normalize missing fields to avoid crashes
      res.threats = res.threats || [];
      res.signals = res.signals || [];
      res.threat_intelligence = res.threat_intelligence || [];
      res.score_breakdown = res.score_breakdown || { tfidf: 0, rule_based: 0, threat_intel: 0 };
      res.explanation = res.explanation || [];
      res.url_analysis = res.url_analysis || [];
    }

    // Ensure simulation takes at least ~1.8s for UX
    setTimeout(() => {
      clearInterval(stepInterval);
      setSimulating(false);
      setLoading(false);
      if (apiError) {
        setError(apiError);
      } else if (res) {
        setResult(res);
      }
    }, 1800);
  };

  useEffect(() => {
    // Only run on client side
    if (typeof window !== 'undefined') {
      const searchParams = new URLSearchParams(window.location.search);
      const urlParam = searchParams.get('url');
      const textParam = searchParams.get('text');
      const scanIdParam = searchParams.get('scan_id');
      
      if (scanIdParam) {
        setText(`Fetching scan results...`);
        setLoading(true);
        setSimulating(true);
        fetch(`${API_URL}/scan-result/${scanIdParam}`)
          .then(r => {
            if (!r.ok) throw new Error("Analysis not found");
            return r.json();
          })
          .then(data => {
             data.threats = data.threats || [];
             data.signals = data.signals || [];
             data.threat_intelligence = data.threat_intelligence || [];
             data.score_breakdown = data.score_breakdown || { tfidf: 0, rule_based: 0, threat_intel: 0 };
             data.explanation = data.explanation || [];
             data.url_analysis = data.url_analysis || [];
             if (data.total_links_found !== undefined) {
                // Page result
                data.summary = data.summary || { clean: 0, suspicious: 0, threats: 0 };
                data.notable_links = data.notable_links || [];
             }
             setResult(data);
             setText(data.page_url || data.text || "Scan loaded.");
             setSimulating(false);
             setLoading(false);
          })
          .catch(err => {
             setError("ANALYSIS NOT FOUND. That scan is no longer available.");
             setSimulating(false);
             setLoading(false);
          });
        window.history.replaceState({}, '', '/');
      } else if (urlParam) {
        setText(urlParam);
        handleAnalyze(urlParam, true);
        window.history.replaceState({}, '', '/');
      } else if (textParam) {
        setText(textParam);
        handleAnalyze(textParam, false);
        window.history.replaceState({}, '', '/');
      }
    }
  }, []);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleAnalyze(text, false);
  };

  const loadExample = (exampleText: string) => {
    setText(exampleText);
    setResult(null);
    setError(null);
  };

  return (
    <div className="w-full h-full flex flex-col xl:flex-row gap-8">
      
      {/* Left Column: Input Workspace */}
      <div className="flex-1 flex flex-col gap-6 w-full">
        
        {/* Workspace Header */}
        <div className="flex items-end justify-between border-b border-[#161922] pb-2">
          <h2 className="text-sm font-mono tracking-widest text-[#969BA8]">MESSAGE UNDER INVESTIGATION</h2>
          <div className="text-[10px] font-mono tracking-widest text-[#00F0FF]">TEXT ANALYSIS <span className="opacity-50 mx-1">|</span> READY</div>
        </div>

        {/* Input Form */}
        <div className="bg-[#101218] border border-[#161922] rounded-lg p-1 shadow-lg relative group focus-within:border-white/10 transition-colors">
          <form onSubmit={onSubmit} className="relative h-full flex flex-col">
            <div className="relative">
              <textarea
                rows={7}
                className="w-full bg-transparent border-0 p-5 text-[#F4F5F7] placeholder:text-[#5E6370] focus:ring-0 resize-none font-sans leading-relaxed text-sm"
                placeholder="Paste the message you're unsure about..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                disabled={loading}
              />
              {/* Fake scanning line during simulation */}
              {simulating && (
                <div className="absolute top-0 left-0 w-full h-[2px] bg-[#00F0FF] opacity-70 shadow-[0_0_15px_#00F0FF] animate-[scan_1.5s_linear_infinite]" />
              )}
            </div>

            {/* Bottom Bar inside input */}
            <div className="flex items-center justify-between p-3 border-t border-[#161922]">
              <div className="flex items-center gap-4 text-[10px] font-mono text-[#5E6370] tracking-widest">
                <span>CHARS: {text.length}</span>
                <span>WORDS: {text.trim() === "" ? 0 : text.trim().split(/\s+/).length}</span>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setText("")}
                  disabled={loading || !text}
                  className="px-3 py-2 text-xs font-mono text-[#5E6370] hover:text-[#F4F5F7] transition-colors disabled:opacity-30 uppercase"
                >
                  Clear
                </button>
                <button
                  type="submit"
                  disabled={loading || !text.trim()}
                  className="px-5 py-2 bg-[#00F0FF]/10 text-[#00F0FF] border border-[#00F0FF]/30 hover:bg-[#00F0FF]/20 text-xs font-mono font-bold tracking-widest rounded transition-all disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2 group-hover:shadow-[0_0_15px_rgba(0,240,255,0.1)]"
                >
                  <Crosshair className="w-3 h-3" />
                  INTERROGATE MESSAGE &rarr;
                </button>
              </div>
            </div>
          </form>
        </div>
        <div className="text-[10px] text-[#5E6370] leading-relaxed max-w-sm">
          Message text stays local. Only extracted public indicators may be checked against enabled threat-intelligence services.
        </div>

        {/* Examples Chips */}
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.id}
              onClick={() => loadExample(ex.text)}
              disabled={loading}
              className="px-3 py-1.5 text-[10px] font-mono tracking-wider text-[#969BA8] border border-[#161922] bg-[#101218] hover:bg-[#161922] hover:text-[#F4F5F7] rounded transition-all disabled:opacity-50 uppercase"
            >
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* Right Column: Analysis / Result */}
      <div className="flex-1 w-full min-h-[400px] flex flex-col justify-start">
        
        {/* Empty State */}
        {!loading && !result && !error && (
          <div className="h-full border border-dashed border-[#161922] rounded-lg flex flex-col items-center justify-center text-center p-8 opacity-60">
            <Search className="w-10 h-10 text-[#5E6370] mb-4" />
            <h3 className="text-sm font-mono tracking-widest text-[#969BA8] mb-2 uppercase">Nothing suspicious yet</h3>
            <p className="text-xs text-[#5E6370] max-w-xs leading-relaxed">Paste a message above and let us take a closer look.</p>
          </div>
        )}

        {/* Loading State */}
        {simulating && (
          <div className="h-full border border-[#00F0FF]/20 bg-[#00F0FF]/5 rounded-lg flex flex-col items-center justify-center p-8 animate-in fade-in duration-300 relative overflow-hidden">
             {/* Large scanning radar effect */}
             <div className="absolute inset-0 flex items-center justify-center opacity-10">
               <div className="w-64 h-64 border border-[#00F0FF] rounded-full animate-ping" />
             </div>
             <Search className="w-8 h-8 text-[#00F0FF] animate-pulse mb-6 relative z-10" />
             <div className="text-xs font-mono tracking-widest text-[#00F0FF] relative z-10 uppercase h-4">
                {SIMULATION_STEPS[simStep]}
             </div>
          </div>
        )}

        {/* Error State */}
        {error && !simulating && (
          <div className="border border-[#FF3366]/30 bg-[#FF3366]/5 rounded-lg p-8 flex flex-col items-center text-center animate-in fade-in">
            <RotateCcw className="w-8 h-8 text-[#FF3366] mb-4" />
            <h3 className="text-sm font-bold tracking-widest text-[#FF3366] mb-2">ANALYSIS INTERRUPTED</h3>
            <p className="text-xs text-[#969BA8] mb-6">{error}</p>
            <button
              onClick={() => handleAnalyze(text)}
              className="px-4 py-2 bg-[#161922] hover:bg-[#101218] border border-white/10 text-xs font-mono text-[#F4F5F7] rounded transition-colors"
            >
              RETRY ANALYSIS
            </button>
          </div>
        )}

        {/* Result State */}
        {result && !simulating && (
          result.scan_id ? <PageResultCard result={result} /> : <ResultCard result={result} />
        )}

      </div>

      <style dangerouslySetInnerHTML={{__html: `
        @keyframes scan {
          0% { transform: translateY(0); opacity: 0; }
          10% { opacity: 0.8; }
          90% { opacity: 0.8; }
          100% { transform: translateY(150px); opacity: 0; }
        }
      `}} />
    </div>
  );
}
