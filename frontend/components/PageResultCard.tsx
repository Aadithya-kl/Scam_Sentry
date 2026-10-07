import React from 'react';
import { ShieldAlert, CheckCircle2, AlertTriangle, Link as LinkIcon, Crosshair } from 'lucide-react';

export function PageResultCard({ result }: { result: any }) {
  const isCritical = result.risk_level === "CRITICAL";
  const isHigh = result.risk_level === "HIGH";
  const isMedium = result.risk_level === "MEDIUM";
  const isLow = result.risk_level === "LOW";

  const colorPrimary = isCritical ? "#FF3366" : isHigh ? "#FF7B00" : isMedium ? "#FFB800" : "#00FF66";
  const colorBg = isCritical ? "bg-[#FF3366]/5 border-[#FF3366]/20" : isHigh ? "bg-[#FF7B00]/5 border-[#FF7B00]/20" : isMedium ? "bg-[#FFB800]/5 border-[#FFB800]/20" : "bg-[#00FF66]/5 border-[#00FF66]/20";
  const Icon = isCritical || isHigh ? AlertTriangle : isMedium ? ShieldAlert : CheckCircle2;

  const headerTitle = result.prediction === "SAFE" ? "CLEAN PAGE" : result.prediction === "SUSPICIOUS" ? "SUSPICIOUS PAGE" : "THREAT DETECTED";

  const summary = result.summary || { clean: 0, suspicious: 0, threats: 0 };
  const notable_links = result.notable_links || [];

  return (
    <div className={`w-full rounded-lg border p-6 flex flex-col gap-6 animate-in slide-in-from-bottom-4 duration-500 ${colorBg}`}>
      
      {/* Top Banner */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded flex items-center justify-center bg-[#08090C] border border-white/10 shrink-0">
            <Icon className="w-6 h-6" style={{ color: colorPrimary }} />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight uppercase" style={{ color: colorPrimary }}>
              {headerTitle}
            </h2>
            <div className="text-[10px] font-mono tracking-widest text-[#969BA8] mt-1 flex items-center gap-2">
              <span>{result.risk_level} RISK</span>
              <span className="opacity-30">•</span>
              <span>SCORE {result.risk_score} / 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#101218] border border-[#161922] p-4 rounded-lg">
          <div className="text-[10px] font-mono tracking-widest text-[#5E6370] mb-2">LINKS</div>
          <div className="text-xl font-mono text-[#F4F5F7]">{result.total_links_found}</div>
        </div>
        <div className="bg-[#101218] border border-[#161922] p-4 rounded-lg">
          <div className="text-[10px] font-mono tracking-widest text-[#5E6370] mb-2">EXTERNAL</div>
          <div className="text-xl font-mono text-[#F4F5F7]">{result.external_links}</div>
        </div>
        <div className="bg-[#101218] border border-[#161922] p-4 rounded-lg">
          <div className="text-[10px] font-mono tracking-widest text-[#5E6370] mb-2">THREATS</div>
          <div className="text-xl font-mono text-[#FF3366] font-bold">{summary.threats}</div>
        </div>
        <div className="bg-[#101218] border border-[#161922] p-4 rounded-lg">
          <div className="text-[10px] font-mono tracking-widest text-[#5E6370] mb-2">SUSPICIOUS</div>
          <div className="text-xl font-mono text-[#FFB800]">{summary.suspicious}</div>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        <div className="text-[10px] font-mono tracking-widest text-[#969BA8] uppercase border-b border-white/5 pb-2">
          PAGE URL
        </div>
        <div className="text-xs font-mono text-[#F4F5F7] break-all p-3 bg-[#08090C] rounded border border-[#161922]">
          {result.page_url}
        </div>
      </div>

      {/* Notable Links */}
      {notable_links && notable_links.length > 0 && (
        <div className="flex flex-col gap-3">
          <div className="text-[10px] font-mono tracking-widest text-[#969BA8] uppercase border-b border-white/5 pb-2">
            NOTABLE THREATS & LINKS
          </div>
          
          <div className="flex flex-col gap-2">
            {notable_links.map((link: any, idx: number) => {
              const linkIsScam = link.prediction === "SCAM";
              const linkIsSuspicious = link.prediction === "SUSPICIOUS";
              const linkColor = linkIsScam ? "text-[#FF3366]" : linkIsSuspicious ? "text-[#FFB800]" : "text-[#00FF66]";
              
              return (
                <div key={idx} className="flex flex-col gap-2 p-3 bg-[#101218] border border-[#161922] rounded hover:border-white/10 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="text-xs font-mono text-[#F4F5F7] break-all line-clamp-2 leading-relaxed">
                      {link.url}
                    </div>
                    <div className={`text-[10px] font-mono font-bold tracking-widest whitespace-nowrap shrink-0 ${linkColor}`}>
                      {link.prediction}
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between text-[9px] font-mono text-[#5E6370]">
                    <span className="truncate pr-4 uppercase">{link.reason}</span>
                    <span className="shrink-0 text-white/40">{link.risk_score} / 100</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

    </div>
  );
}
