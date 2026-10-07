"use client";

import React, { useState } from "react";
import { Globe, AlertTriangle, ShieldCheck, Search, Link as LinkIcon, ChevronDown, Activity, ShieldAlert } from "lucide-react";
import type { PredictResponse } from "../lib/types";

export function IndicatorsPanel({ result }: { result: PredictResponse }) {
  const { iocs, url_analysis, threat_intelligence } = result;
  const [selectedUrl, setSelectedUrl] = useState<string | null>(null);

  if (!iocs || iocs.urls.length === 0) {
    return null;
  }

  const handleUrlClick = (url: string) => {
    setSelectedUrl(prev => prev === url ? null : url);
  };

  return (
    <div className="mt-8 border-t border-[#161922] pt-6 animate-in fade-in duration-500">
      <div className="text-[10px] font-mono tracking-widest opacity-60 mb-4">04 / INDICATORS</div>
      
      <div className="grid grid-cols-1 gap-4">
        {iocs.urls.map((url, i) => {
          const analysis = url_analysis?.find(u => u.url === url);
          const intel = threat_intelligence?.filter(t => t.url === url) || [];
          
          const isExpanded = selectedUrl === url;
          
          // Determine if any intel matched
          const anyIntelMatch = intel.some(t => t.status === "MATCH");
          const anySuspicious = analysis?.suspicious_structure || anyIntelMatch;
          
          return (
            <div key={i} className="bg-[#101218] border border-[#161922] rounded-lg overflow-hidden">
              <div 
                className="p-4 flex items-center justify-between cursor-pointer hover:bg-[#161922] transition-colors"
                onClick={() => handleUrlClick(url)}
              >
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className={`p-2 rounded ${anySuspicious ? 'bg-[#FF3366]/10 text-[#FF3366]' : 'bg-[#00F0FF]/10 text-[#00F0FF]'}`}>
                    <LinkIcon className="w-4 h-4" />
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-xs font-mono text-[#F4F5F7] truncate">{url}</div>
                    <div className="text-[10px] font-mono text-[#969BA8]">{analysis?.domain || "Unknown Domain"}</div>
                  </div>
                </div>
                
                <div className="flex items-center gap-4 shrink-0">
                  {anyIntelMatch && (
                    <span className="text-[10px] font-bold text-[#FF3366] bg-[#FF3366]/10 px-2 py-1 rounded tracking-widest">THREAT DETECTED</span>
                  )}
                  <ChevronDown className={`w-4 h-4 text-[#5E6370] transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                </div>
              </div>
              
              {isExpanded && analysis && (
                <div className="p-4 border-t border-[#161922] bg-[#08090C] animate-in slide-in-from-top-2 duration-300">
                  
                  {/* Local Structure */}
                  <div className="mb-6">
                    <div className="text-[10px] font-bold text-[#969BA8] tracking-widest mb-3">LOCAL STRUCTURE</div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div>
                        <div className="text-[10px] text-[#5E6370]">HTTPS</div>
                        <div className={`text-xs font-mono ${analysis.https ? 'text-[#00F0FF]' : 'text-[#FFB800]'}`}>{analysis.https ? 'YES' : 'NO'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[#5E6370]">SHORTENER</div>
                        <div className={`text-xs font-mono ${analysis.shortened ? 'text-[#FFB800]' : 'text-[#969BA8]'}`}>{analysis.shortened ? 'YES' : 'NO'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[#5E6370]">RAW IP</div>
                        <div className={`text-xs font-mono ${analysis.raw_ip ? 'text-[#FF3366]' : 'text-[#969BA8]'}`}>{analysis.raw_ip ? 'YES' : 'NO'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[#5E6370]">SUSPICIOUS STRUCTURE</div>
                        <div className={`text-xs font-mono ${analysis.suspicious_structure ? 'text-[#FF3366]' : 'text-[#00F0FF]'}`}>{analysis.suspicious_structure ? 'YES' : 'NO'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Threat Intelligence */}
                  <div className="mb-4">
                    <div className="text-[10px] font-bold text-[#969BA8] tracking-widest mb-3">THREAT INTELLIGENCE</div>
                    <div className="space-y-2 bg-[#101218] rounded border border-[#161922] p-3">
                      {intel.length > 0 ? intel.map((t, idx) => {
                        let dotColor = "bg-[#5E6370]";
                        if (t.status === "MATCH") dotColor = "bg-[#FF3366] shadow-[0_0_8px_#FF3366]";
                        else if (t.status === "NO_MATCH") dotColor = "bg-[#D9FF00]";
                        else if (t.status === "CHECKED" || t.status === "RATE_LIMITED" || t.status.includes("ERROR")) dotColor = "bg-[#FFB800]";
                        
                        return (
                          <div key={idx} className="flex items-center justify-between">
                            <span className="text-xs font-mono text-[#F4F5F7]">{t.provider}</span>
                            <div className="flex items-center gap-2">
                              {t.provider === "VirusTotal" && t.malicious_votes !== undefined && (
                                <span className="text-[10px] font-mono text-[#5E6370]">
                                  {t.malicious_votes} malicious / {(t.malicious_votes || 0) + (t.suspicious_votes || 0) + (t.harmless_votes || 0)} engines
                                </span>
                              )}
                              <span className={`text-[10px] font-mono tracking-wider ${t.status === 'MATCH' ? 'text-[#FF3366] font-bold' : 'text-[#969BA8]'}`}>
                                {t.status.replace(/_/g, ' ')}
                              </span>
                              <div className={`w-2 h-2 rounded-full ${dotColor}`} />
                            </div>
                          </div>
                        );
                      }) : (
                        <div className="text-xs text-[#5E6370] font-mono">No threat intelligence configured or available.</div>
                      )}
                    </div>
                  </div>
                  
                  {/* Why it matters */}
                  {(analysis.signals.length > 0 || anyIntelMatch) && (
                    <div className="mt-6 border-t border-[#161922] pt-4">
                      <div className="text-[10px] font-bold text-[#969BA8] tracking-widest mb-2">WHY IT MATTERS</div>
                      <ul className="space-y-1">
                        {analysis.signals.map((sig, idx) => (
                          <li key={idx} className="text-xs text-[#969BA8] flex items-start gap-2">
                            <span className="text-[#FFB800]">-</span> {sig}
                          </li>
                        ))}
                        {anyIntelMatch && (
                          <li className="text-xs text-[#FF3366] flex items-start gap-2 mt-2">
                            <ShieldAlert className="w-4 h-4 shrink-0" /> 
                            This URL is recognized by threat intelligence sources as malicious. Do not interact with it.
                          </li>
                        )}
                      </ul>
                    </div>
                  )}

                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
