interface HeaderProps {
  hasHistory: boolean;
  onToggleHistory: () => void;
  isHistoryOpen: boolean;
}

export function Header({ hasHistory, onToggleHistory, isHistoryOpen }: HeaderProps) {
  return (
    <header className="border-b border-[var(--border)] pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="h-3 w-3 bg-emerald-500 rounded-none animate-pulse" />
          <h1 className="text-xl md:text-2xl font-bold uppercase tracking-widest text-zinc-100 font-mono">
            VT Doc Guardian
          </h1>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 bg-zinc-800 text-zinc-400 border border-zinc-700">
            v2.0
          </span>
        </div>
        <p className="text-xs text-zinc-400 font-mono">
          Security Analysis Engine // Hash-First Threat Intelligence & Static Quarantining
        </p>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-xs font-mono text-zinc-500 hidden sm:inline">
          ENGINE: VIRUSTOTAL V3
        </span>
        {hasHistory && (
          <button
            type="button"
            onClick={onToggleHistory}
            className={`text-xs font-mono px-3 py-1.5 border transition-colors uppercase tracking-wider ${
              isHistoryOpen
                ? "bg-zinc-800 text-zinc-200 border-zinc-600"
                : "bg-transparent text-zinc-400 border-zinc-700 hover:border-zinc-500 hover:text-zinc-200"
            }`}
          >
            {isHistoryOpen ? "Fechar Histórico" : "Histórico Recente"}
          </button>
        )}
      </div>
    </header>
  );
}
