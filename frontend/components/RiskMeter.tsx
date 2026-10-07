"use client";

import React, { useEffect, useState } from "react";

interface RiskMeterProps {
  score: number;
}

export function RiskMeter({ score }: RiskMeterProps) {
  const [displayedScore, setDisplayedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = Math.min(100, Math.max(0, score));
    const duration = 1000;
    const startTime = performance.now();

    const animate = (time: number) => {
      const elapsed = time - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // easeOutQuart
      const ease = 1 - Math.pow(1 - progress, 4);
      setDisplayedScore(Math.round(end * ease));

      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        setDisplayedScore(end);
      }
    };

    requestAnimationFrame(animate);
  }, [score]);

  // Determine colors based on score
  let strokeColor = "#00F0FF"; // SAFE / LOW
  if (score >= 75) strokeColor = "#FF3366"; // SCAM / CRITICAL
  else if (score >= 50) strokeColor = "#FF7B00"; // SPAM / HIGH
  else if (score >= 25) strokeColor = "#FFB800"; // SUSPICIOUS / MEDIUM

  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (displayedScore / 100) * circumference;

  return (
    <div className="relative w-32 h-32 flex items-center justify-center">
      {/* Background ring */}
      <svg className="absolute inset-0 w-full h-full transform -rotate-90">
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="transparent"
          stroke="#161922"
          strokeWidth="8"
          strokeDasharray="4 4" // Segmented look
        />
        {/* Foreground animated ring */}
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="transparent"
          stroke={strokeColor}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-100 ease-out"
          style={{
            filter: `drop-shadow(0 0 4px ${strokeColor}40)`
          }}
        />
      </svg>

      <div className="flex flex-col items-center justify-center relative z-10">
        <span className="text-3xl font-mono font-bold tracking-tighter" style={{ color: strokeColor }}>
          {displayedScore}
        </span>
        <span className="text-[10px] font-mono text-[#5E6370] tracking-widest">/100</span>
      </div>
    </div>
  );
}
