"use client";

import { useEffect, useState } from "react";
import { StepState } from "@/types/analysis";

interface AnalysisProgressProps {
  step: StepState;
  statusText: string;
}

export function AnalysisProgress({ step, statusText }: AnalysisProgressProps) {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const steps = [
    { key: "validating", label: "Inspeção MIME" },
    { key: "checking_cache", label: "Hash-First Lookup" },
    { key: "scanning", label: "Varredura de Motores" },
    { key: "completed", label: "Veredito Tático" },
  ];

  const getStepStatus = (stepKey: string) => {
    if (step === "completed") return "done";
    if (step === stepKey) return "active";

    const order = ["validating", "checking_cache", "scanning", "completed"];
    const currentIndex = order.indexOf(step);
    const targetIndex = order.indexOf(stepKey);

    if (currentIndex > targetIndex) return "done";
    return "pending";
  };

  return (
    <div className="border border-[var(--border)] bg-[#14161a] p-6 flex flex-col gap-6">
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-2.5 h-2.5 bg-amber-400 rounded-none animate-ping" />
          <span className="font-mono text-xs uppercase tracking-wider text-amber-400 font-bold">
            Varredura em Execução
          </span>
        </div>
        <span className="font-mono text-xs text-zinc-500">
          TEMPO DECORRIDO: {seconds}s
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {steps.map((s, idx) => {
          const status = getStepStatus(s.key);
          return (
            <div
              key={s.key}
              className={`p-3 border font-mono text-xs flex flex-col gap-1 transition-all ${
                status === "done"
                  ? "border-emerald-800 bg-emerald-950/20 text-emerald-300"
                  : status === "active"
                  ? "border-amber-600 bg-amber-950/30 text-amber-200 animate-pulse"
                  : "border-zinc-800 bg-zinc-900/40 text-zinc-600"
              }`}
            >
              <span className="text-[10px] text-zinc-500">FASE 0{idx + 1}</span>
              <span className="font-semibold">{s.label}</span>
              <span className="text-[10px] uppercase">
                {status === "done" ? "[OK]" : status === "active" ? "[PROCESSANDO...]" : "[AGUARDO]"}
              </span>
            </div>
          );
        })}
      </div>

      <div className="font-mono text-xs text-zinc-300 bg-black/40 border border-zinc-800 p-3 flex items-center justify-between">
        <span className="text-amber-400">&gt; {statusText}</span>
        <span className="text-[10px] text-zinc-500 hidden sm:inline">POLL: 15s RATE GUARD</span>
      </div>
    </div>
  );
}
