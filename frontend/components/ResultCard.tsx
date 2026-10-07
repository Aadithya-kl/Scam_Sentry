"use client";

import React, { useEffect, useState } from "react";
import { Search, AlertCircle, CheckCircle2, ChevronDown, Binary, ShieldAlert, AlertTriangle, Info, Zap } from "lucide-react";
import type { PredictResponse } from "../lib/types";
import { RiskMeter } from "./RiskMeter";
import { IndicatorsPanel } from "./IndicatorsPanel";

export function ResultCard({ result }: { result: PredictResponse }) {
  const [showTech, setShowTech] = useState(false);

  // Safe normalizations
  const flags = result.flags || [];
  const explanation = result.explanation || [];
  const top_terms = result.top_terms || [];
  const score_breakdown = result.score_breakdown || { tfidf: 0, rule_based: 0, threat_intel: 0 };
  const url_analysis = result.url_analysis || [];
  const threat_intelligence = result.threat_intelligence || [];
  const iocs = result.iocs || { urls: [], domains: [], ips: [], emails: [] };

  // Reveal animation sequencing for evidence rows
  const [revealedEvidence, setRevealedEvidence] = useState<number>(-1);
  useEffect(() => {
    if (flags.length === 0) return;
    const interval = setInterval(() => {
      setRevealedEvidence((prev) => {
        if (prev >= flags.length - 1) {
          clearInterval(interval);
          return prev;
        }
        return prev + 1;
      });
    }, 200);
    return () => clearInterval(interval);
  }, [result]);

  const isScam = result.prediction === "SCAM";
  const isSpam = result.prediction === "SPAM";
  const isSuspicious = result.prediction === "SUSPICIOUS";
  const isSafe = result.prediction === "SAFE";

  let headerColor = "text-[#00F0FF] border-[#00F0FF]/30 bg-[#00F0FF]/5";
  let icon = <CheckCircle2 className="w-6 h-6 text-[#00F0FF]" />;
  let title = "SAFE";

  if (isScam) {
    headerColor = "text-[#FF3366] border-[#FF3366]/30 bg-[#FF3366]/5 shadow-[0_0_15px_rgba(255,51,102,0.1)]";
    icon = <ShieldAlert className="w-6 h-6 text-[#FF3366]" />;
    title = "SCAM DETECTED";
  } else if (isSpam) {
    headerColor = "text-[#FF7B00] border-[#FF7B00]/30 bg-[#FF7B00]/5";
    icon = <AlertTriangle className="w-6 h-6 text-[#FF7B00]" />;
    title = "SPAM DETECTED";
  } else if (isSuspicious) {
    headerColor = "text-[#FFB800] border-[#FFB800]/30 bg-[#FFB800]/5";
    icon = <AlertCircle className="w-6 h-6 text-[#FFB800] animate-pulse" />;
    title = "SUSPICIOUS";
  }

  const rawRuleScore = Object.entries(score_breakdown || {})
    .filter(([k]) => k !== "spam_probability_score")
    .reduce((acc, [_, v]) => acc + (v as number), 0);

  return (
    <div className="w-full flex flex-col gap-4 animate-in fade-in slide-in-from-right-8 duration-700 font-sans">
      
      {/* Verdict Header */}
      <div className={`p-5 rounded-lg border flex items-center justify-between ${headerColor}`}>
        <div className="flex items-center gap-4">
          {icon}
          <div>
            <div className="text-[10px] font-mono tracking-widest opacity-60 mb-1">03 / VERDICT</div>
            <h2 className="text-xl font-bold tracking-wide">{title}</h2>
          </div>
        </div>
        <div className="flex flex-col items-end">
           <div className="text-[10px] font-mono tracking-widest opacity-60 mb-1">RISK LEVEL</div>
           <div className="font-mono font-bold tracking-wider">{result.risk_level}</div>
        </div>
      </div>

      {/* Main Analysis Block */}
      <div className="bg-[#101218] border border-[#161922] rounded-lg p-6 relative overflow-hidden">
        
        <div className="flex flex-col md:flex-row gap-8">
          
          {/* Left: Risk Meter */}
          <div className="flex flex-col items-center justify-center shrink-0">
            <RiskMeter score={result.risk_score} />
            <div className="mt-4 text-xs font-mono text-[#5E6370] tracking-widest text-center">
              RISK SCORE
            </div>
          </div>

          {/* Right: Forensic Evidence */}
          <div className="flex-1 border-l border-[#161922] pl-8">
            <h3 className="text-xs font-bold text-[#969BA8] tracking-widest mb-4">WHY WE PAUSED ON THIS</h3>
            
            {flags.length > 0 ? (
              <div className="space-y-3">
                {flags.map((flag, i) => (
                  <div 
                    key={i} 
                    className={`flex items-start gap-3 p-3 rounded bg-[#161922]/50 border border-white/5 transition-all duration-300 ${i <= revealedEvidence ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'}`}
                  >
                    <div className="text-[10px] font-mono text-[#5E6370] mt-0.5">{(i + 1).toString().padStart(2, '0')}</div>
                    <div>
                      <div className="text-xs font-bold text-[#F4F5F7] uppercase tracking-wide mb-1">{flag}</div>
                      {explanation[i] && (
                         <div className="text-xs text-[#969BA8] leading-relaxed">
                           "{explanation[i].replace(/^- /, '')}"
                         </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-[#00F0FF] p-4 bg-[#00F0FF]/5 rounded border border-[#00F0FF]/10">
                <CheckCircle2 className="w-4 h-4" /> No specific threat patterns detected.
              </div>
            )}
          </div>
        </div>

        <hr className="border-[#161922] my-6" />

        {/* The Read */}
        <div>
          <h3 className="text-xs font-bold text-[#969BA8] tracking-widest mb-3 flex items-center gap-2">
            <Info className="w-4 h-4" /> THE READ
          </h3>
          <p className="text-sm text-[#F4F5F7] leading-relaxed">
            {explanation.length > 0 ? (
              result.prediction === "SAFE" 
                ? "This message doesn't contain any recognizable malicious patterns, urgency, or suspicious requests. It appears to be standard communication."
                : `This message presents as ${result.prediction.toLowerCase()} because it relies on ${flags.length > 1 ? 'a combination of ' : ''}${flags.map(f => f.toLowerCase()).join(", ")}.`
            ) : (
              "Analysis complete. No significant signals found."
            )}
          </p>
        </div>

      </div>

      <IndicatorsPanel result={result} />

      {/* Technical Analysis Accordion */}
      <div className="bg-[#101218] border border-[#161922] rounded-lg overflow-hidden mt-4">
        <button 
          onClick={() => setShowTech(!showTech)}
          className="w-full flex items-center justify-between p-4 text-xs font-mono text-[#969BA8] hover:text-[#F4F5F7] hover:bg-[#161922] transition-colors"
        >
          <div className="flex items-center gap-2">
            <Binary className="w-4 h-4" />
            TECHNICAL ANALYSIS
          </div>
          <ChevronDown className={`w-4 h-4 transition-transform duration-300 ${showTech ? 'rotate-180' : ''}`} />
        </button>
        
        {showTech && (
          <div className="p-6 border-t border-[#161922] bg-[#08090C] animate-in slide-in-from-top-2 duration-300">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              
              {/* Left Tech: Models */}
              <div className="space-y-4">
                <div>
                  <div className="text-[10px] text-[#5E6370] mb-1">ML CLASSIFIER</div>
                  <div className="text-xs font-mono text-[#F4F5F7]">Logistic Regression</div>
                </div>
                <div>
                  <div className="text-[10px] text-[#5E6370] mb-1">FEATURE EXTRACTION</div>
                  <div className="text-xs font-mono text-[#F4F5F7]">TF-IDF</div>
                </div>
                <div>
                  <div className="text-[10px] text-[#5E6370] mb-1">SPAM PROBABILITY</div>
                  <div className="text-xs font-mono text-[#00F0FF]">{(result.spam_probability * 100).toFixed(2)}%</div>
                </div>
                {top_terms && top_terms.length > 0 && (
                  <div>
                     <div className="text-[10px] text-[#5E6370] mb-2">ML FEATURE CONTRIBUTIONS</div>
                     <div className="flex flex-wrap gap-2">
                       {top_terms.map((t, i) => (
                         <div key={i} className="text-[10px] font-mono bg-[#161922] border border-white/5 px-2 py-1 rounded text-[#969BA8]">
                           {t.term} <span className="text-[#FFB800]">{t.weight > 0 ? '+' : ''}{t.weight.toFixed(2)}</span>
                         </div>
                       ))}
                     </div>
                  </div>
                )}
              </div>

              {/* Right Tech: Breakdown */}
              <div className="font-mono text-xs">
                <div className="text-[10px] text-[#5E6370] mb-3">RISK SCORE BREAKDOWN</div>
                <div className="space-y-2">
                  <div className="flex justify-between text-[#969BA8]">
                    <span>Spam signal</span>
                    <span className="text-[#00F0FF]">+{score_breakdown.spam_probability_score || 0}</span>
                  </div>
                  {Object.entries(score_breakdown).filter(([k]) => k !== "spam_probability_score" && k !== "combination_bonus").map(([k, v]) => (
                    <div key={k} className="flex justify-between text-[#969BA8]">
                      <span>{k.replace(/_/g, ' ')}</span>
                      <span className="text-[#FFB800]">+{v as number}</span>
                    </div>
                  ))}
                  {(score_breakdown.combination_bonus as number) > 0 && (
                    <div className="flex justify-between text-[#969BA8]">
                      <span>Context combination</span>
                      <span className="text-[#FF3366]">+{score_breakdown.combination_bonus}</span>
                    </div>
                  )}
                  <div className="border-t border-[#161922] pt-2 mt-2 flex justify-between font-bold text-[#F4F5F7]">
                    <span>Final risk (capped at 100)</span>
                    <span>{result.risk_score}</span>
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}
      </div>
    </div>
  );
}
