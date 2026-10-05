"use client";

import { useState } from "react";
import { AnalysisReport } from "@/types/analysis";

interface ReportCardProps {
  report: AnalysisReport;
  onReset: () => void;
}

function formatBytes(bytes: number): string {
  if (!bytes) return "N/A";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function ReportCard({ report, onReset }: ReportCardProps) {
  const [copied, setCopied] = useState(false);
  const [showDetections, setShowDetections] = useState(true);

  const copyHash = async () => {
    if (report.sha256) {
      await navigator.clipboard.writeText(report.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vt_report_${report.filename}_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const isDanger = report.malicious > 0;
  const isWarning = !isDanger && report.suspicious > 0;

  return (
    <section className="border border-[var(--border)] bg-[#14161a] flex flex-col">
      {/* Header do Laudo */}
      <div className="border-b border-zinc-800 p-6 bg-[#1a1d24] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] uppercase font-mono tracking-widest text-zinc-500">
              LAUDO TÉCNICO {"//"}
            </span>
            <span className="text-xs font-mono font-bold text-zinc-200">
              {report.filename}
            </span>
            {report.is_cached && (
              <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-950/60 border border-emerald-700 text-emerald-300">
                CACHE THREAT INTEL {"//"} RESPOSTA INSTANTÂNEA
              </span>
            )}
          </div>
          <p className="text-xs font-mono text-zinc-400">
            Tamanho: {formatBytes(report.file_size)} {"//"} Análise concluída
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={exportJSON}
            className="text-xs font-mono text-zinc-300 hover:text-white border border-zinc-700 hover:border-zinc-500 px-3 py-1.5 transition-colors uppercase tracking-wider"
          >
            Exportar JSON
          </button>
          <button
            type="button"
            onClick={onReset}
            className="text-xs font-mono bg-zinc-200 text-zinc-900 hover:bg-white px-4 py-1.5 font-bold transition-colors uppercase tracking-wider cursor-pointer"
          >
            Nova Análise
          </button>
        </div>
      </div>

      {/* Veredito e Métricas */}
      <div className="p-6 md:p-8 flex flex-col gap-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="border border-zinc-800 p-4 bg-[#111317]">
            <span className="text-[11px] font-mono text-zinc-500 uppercase block mb-1">
              Malicious
            </span>
            <span className={`text-3xl font-mono font-bold ${isDanger ? "text-red-500" : "text-zinc-100"}`}>
              {report.malicious}
            </span>
          </div>

          <div className="border border-zinc-800 p-4 bg-[#111317]">
            <span className="text-[11px] font-mono text-zinc-500 uppercase block mb-1">
              Suspicious
            </span>
            <span className={`text-3xl font-mono font-bold ${isWarning ? "text-amber-400" : "text-zinc-100"}`}>
              {report.suspicious}
            </span>
          </div>

          <div className="border border-zinc-800 p-4 bg-[#111317]">
            <span className="text-[11px] font-mono text-zinc-500 uppercase block mb-1">
              Motores Avaliados
            </span>
            <span className="text-3xl font-mono font-bold text-zinc-100">
              {report.total_engines}
            </span>
          </div>

          <div className="border border-zinc-800 p-4 bg-[#111317]">
            <span className="text-[11px] font-mono text-zinc-500 uppercase block mb-1">
              Veredito Final
            </span>
            <div className="flex items-center gap-2 mt-1">
              <div
                className={`w-3 h-3 rounded-none ${
                  isDanger ? "bg-red-500" : isWarning ? "bg-amber-400" : "bg-emerald-500"
                }`}
              />
              <span
                className={`text-lg font-mono font-bold ${
                  isDanger ? "text-red-500" : isWarning ? "text-amber-400" : "text-emerald-400"
                }`}
              >
                {isDanger ? "DANGER" : isWarning ? "WARNING" : "CLEAN"}
              </span>
            </div>
          </div>
        </div>

        {/* SHA-256 Hash Box */}
        <div className="border border-zinc-800 bg-[#0d0f12] p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono">
          <div className="overflow-hidden">
            <span className="text-[10px] text-zinc-500 uppercase block">
              SHA-256 Checksum (IOC)
            </span>
            <span className="text-xs text-zinc-300 break-all select-all">
              {report.sha256}
            </span>
          </div>
          <button
            type="button"
            onClick={copyHash}
            className="self-start md:self-auto text-xs border border-zinc-700 hover:border-zinc-500 text-zinc-300 hover:text-white px-3 py-1.5 transition-colors uppercase tracking-wider shrink-0 cursor-pointer"
          >
            {copied ? "[ COPIADO! ]" : "Copiar Hash"}
          </button>
        </div>

        {/* Detalhes de Motores / Detecções */}
        {report.detections && report.detections.length > 0 ? (
          <div className="border border-zinc-800 bg-[#111317]">
            <button
              type="button"
              onClick={() => setShowDetections(!showDetections)}
              className="w-full p-4 border-b border-zinc-800 flex items-center justify-between text-left font-mono text-xs uppercase tracking-wider text-zinc-300 hover:bg-zinc-800/40 transition-colors"
            >
              <span className="flex items-center gap-2">
                <span className="text-red-400 font-bold">[{report.detections.length}]</span>
                Motores com Detecção Positiva
              </span>
              <span className="text-zinc-500">{showDetections ? "[-]" : "[+]"}</span>
            </button>

            {showDetections && (
              <div className="p-4 overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-zinc-800 text-zinc-500 uppercase text-[10px]">
                      <th className="py-2 pr-4">Motor Antivírus</th>
                      <th className="py-2 pr-4">Categoria</th>
                      <th className="py-2">Assinatura / Ameaça</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {report.detections.map((det) => (
                      <tr key={det.engine_name} className="hover:bg-zinc-800/30">
                        <td className="py-2 pr-4 font-semibold text-zinc-200">
                          {det.engine_name}
                        </td>
                        <td className="py-2 pr-4">
                          <span
                            className={`px-1.5 py-0.5 text-[10px] uppercase ${
                              det.category === "malicious"
                                ? "bg-red-950/60 text-red-400 border border-red-800"
                                : "bg-amber-950/60 text-amber-400 border border-amber-800"
                            }`}
                          >
                            {det.category}
                          </span>
                        </td>
                        <td className="py-2 text-zinc-300 font-semibold break-all">
                          {det.result || "Threat.Generic"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : (
          <div className="p-4 border border-emerald-900/60 bg-emerald-950/20 text-emerald-400 font-mono text-xs flex items-center gap-3">
            <span className="font-bold">[INTEGRIDADE CONFIRMADA]</span>
            <span>Nenhum malware ou assinatura suspeita detectada entre os motores de varredura.</span>
          </div>
        )}
      </div>
    </section>
  );
}
