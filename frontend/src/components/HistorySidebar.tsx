"use client";

import { AnalysisReport } from "@/types/analysis";

interface HistorySidebarProps {
  history: AnalysisReport[];
  onSelectReport: (report: AnalysisReport) => void;
  onClearHistory: () => void;
  onClose: () => void;
}

export function HistorySidebar({
  history,
  onSelectReport,
  onClearHistory,
  onClose,
}: HistorySidebarProps) {
  return (
    <aside className="border border-[var(--border)] bg-[#14161a] p-6 flex flex-col gap-4 font-mono text-xs">
      <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
        <span className="font-bold uppercase tracking-wider text-zinc-300">
          Histórico Operacional ({history.length})
        </span>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onClearHistory}
            className="text-[10px] text-zinc-500 hover:text-red-400 uppercase transition-colors"
          >
            Limpar
          </button>
          <button
            type="button"
            onClick={onClose}
            className="text-zinc-400 hover:text-white"
          >
            [&times;]
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-2 max-h-72 overflow-y-auto">
        {history.map((item, index) => {
          const isDanger = item.malicious > 0;
          const isWarning = !isDanger && item.suspicious > 0;

          return (
            <button
              key={`${item.sha256}_${index}`}
              type="button"
              onClick={() => onSelectReport(item)}
              className="p-3 border border-zinc-800 bg-[#16181d] hover:border-zinc-600 hover:bg-zinc-800/40 text-left flex flex-col gap-1.5 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-zinc-200 truncate max-w-[200px]">
                  {item.filename}
                </span>
                <span
                  className={`px-1.5 py-0.5 text-[9px] uppercase font-bold ${
                    isDanger
                      ? "text-red-400 bg-red-950/60"
                      : isWarning
                      ? "text-amber-400 bg-amber-950/60"
                      : "text-emerald-400 bg-emerald-950/60"
                  }`}
                >
                  {isDanger ? "DANGER" : isWarning ? "WARNING" : "CLEAN"}
                </span>
              </div>
              <span className="text-[10px] text-zinc-500 truncate">
                {item.sha256}
              </span>
              {item.analyzed_at && (
                <span className="text-[9px] text-zinc-600">
                  {new Date(item.analyzed_at).toLocaleString("pt-BR")}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </aside>
  );
}
