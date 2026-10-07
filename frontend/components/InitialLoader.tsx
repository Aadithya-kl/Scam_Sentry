"use client";

import React, { useEffect, useState } from "react";
import { Search } from "lucide-react";

export function InitialLoader() {
  const [show, setShow] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const hasSeen = localStorage.getItem("scamsentry_intro_seen");
    if (!hasSeen) {
      setShow(true);
      
      const timings = [0, 500, 1000, 1500, 2000, 2500];
      timings.forEach((time, index) => {
        setTimeout(() => setStep(index), time);
      });

      setTimeout(() => {
        setShow(false);
        localStorage.setItem("scamsentry_intro_seen", "true");
      }, 3000);
    }
  }, []);

  if (!show) return null;

  const messages = [
    "INITIALIZING ENGINE...",
    "MAPPING THREAT SIGNALS...",
    "CHECKING INTENT...",
    "BUILDING RISK PROFILE...",
    "SYSTEM READY."
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#08090C] text-[#F4F5F7] overflow-hidden">
      <div className="relative flex flex-col items-center max-w-lg w-full px-8">
        
        {/* Abstract scanning text background */}
        <div className="absolute inset-0 flex flex-col items-center justify-center opacity-10 blur-[2px] font-mono text-[10px] leading-tight select-none">
          <p>01000111 01010100 01001111 01010000</p>
          <p>SIG_DETECT: 0x4A29B THREAT_VEC: NULL</p>
          <p>ANALYSIS_ROUTINE_START_T0</p>
          <p>0x00FF 0x00AA 0x002B 0x01FF</p>
          <p>AWAITING_INPUT_STREAM...</p>
        </div>

        {/* Scanner line passing over */}
        <div className="absolute top-1/2 left-0 w-full h-[1px] bg-[#00F0FF] opacity-50 shadow-[0_0_10px_#00F0FF] animate-[scan_1.5s_ease-in-out_infinite_alternate]" />

        {/* Magnifying Glass icon pulsing */}
        <div className="mb-6 relative z-10">
          <Search className="w-12 h-12 text-[#00F0FF] animate-pulse" />
        </div>

        {/* Typographic steps */}
        <div className="h-6 relative z-10 w-full text-center">
           <p className="font-mono text-sm tracking-widest text-[#00F0FF] animate-in fade-in duration-300">
              {messages[Math.min(step, messages.length - 1)]}
           </p>
        </div>

        {/* Progress bar */}
        <div className="w-48 h-1 bg-[#161922] mt-8 rounded overflow-hidden relative z-10">
          <div 
            className="h-full bg-[#00F0FF] transition-all duration-500 ease-out"
            style={{ width: `${(step / (messages.length - 1)) * 100}%` }}
          />
        </div>

      </div>

      <style dangerouslySetInnerHTML={{__html: `
        @keyframes scan {
          0% { transform: translateY(-50px); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(50px); opacity: 0; }
        }
      `}} />
    </div>
  );
}
