import { Analyzer } from "@/components/Analyzer";
import { BrandHeader } from "@/components/BrandHeader";
import { InitialLoader } from "@/components/InitialLoader";

export default function Home() {
  return (
    <>
      <InitialLoader />
      
      <div className="min-h-screen flex flex-col font-sans relative z-10">
        <BrandHeader />
        
        <main className="flex-1 w-full max-w-7xl mx-auto px-4 md:px-8 py-10 flex flex-col">
          
          {/* Main Hero */}
          <div className="mb-12 max-w-xl">
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-[#F4F5F7] mb-4">
              Don't trust the message.<br/>
              <span className="text-[#00F0FF]">Interrogate it.</span>
            </h1>
            <p className="text-sm md:text-base text-[#969BA8] leading-relaxed">
              Paste a message. ScamSentry looks for the little things that usually get missed.
            </p>
          </div>

          <Analyzer />

          {/* Footer / Disclaimer */}
          <footer className="mt-20 pt-8 border-t border-white/5 text-xs font-mono text-[#5E6370] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <p className="max-w-xl">
              <span className="text-[#969BA8] uppercase">Notice:</span> This is a portfolio/research project demonstrating machine learning and heuristic risk analysis. It should not be treated as a definitive security verdict.
            </p>
            <div className="flex gap-4">
               <span className="uppercase tracking-widest">V 2.0.4</span>
               <span className="uppercase tracking-widest">ENV: LOCAL</span>
            </div>
          </footer>
        </main>
      </div>
    </>
  );
}
