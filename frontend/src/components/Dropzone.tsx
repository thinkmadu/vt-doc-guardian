"use client";

import { useRef, useState } from "react";

interface DropzoneProps {
  onFileSelect: (file: File) => void;
  selectedFile: File | null;
  onClearFile: () => void;
  onSubmit: () => void;
  isUploading: boolean;
  disabled: boolean;
}

const SUPPORTED_EXTS = [
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".ppt", ".pptx", ".pps", ".ppsx",
  ".odt", ".ods", ".odp", ".rtf"
];

const MAX_BYTES = 32 * 1024 * 1024; // 32 MB

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function Dropzone({
  onFileSelect,
  selectedFile,
  onClearFile,
  onSubmit,
  isUploading,
  disabled,
}: DropzoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndHandle = (file: File) => {
    setValidationError(null);
    const ext = "." + file.name.split(".").pop()?.toLowerCase();

    if (!SUPPORTED_EXTS.includes(ext)) {
      setValidationError(
        `Extensão '${ext}' não é suportada. Formatos aceitos: ${SUPPORTED_EXTS.join(", ")}`
      );
      return;
    }

    if (file.size > MAX_BYTES) {
      setValidationError(
        `O arquivo (${formatBytes(file.size)}) ultrapassa o limite de 32 MB.`
      );
      return;
    }

    onFileSelect(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled && !isUploading) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (disabled || isUploading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndHandle(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndHandle(e.target.files[0]);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !selectedFile && !isUploading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed p-8 md:p-12 transition-all flex flex-col items-center justify-center text-center cursor-pointer select-none ${
          isDragging
            ? "border-emerald-500 bg-emerald-950/20"
            : selectedFile
            ? "border-zinc-700 bg-[#16181d] cursor-default"
            : "border-zinc-800 bg-[#14161a] hover:border-zinc-600 hover:bg-[#181a1f]"
        } ${disabled || isUploading ? "opacity-50 pointer-events-none" : ""}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileInput}
          disabled={disabled || isUploading}
          accept={SUPPORTED_EXTS.join(",")}
          className="hidden"
        />

        {!selectedFile ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded border border-zinc-700 flex items-center justify-center bg-zinc-900 text-zinc-400">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-6 h-6"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
            </div>
            <div>
              <p className="font-mono text-sm font-semibold text-zinc-200">
                Arraste o documento aqui ou clique para selecionar
              </p>
              <p className="text-xs text-zinc-500 mt-1 font-mono">
                Formatos: PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, ODT, RTF (Max: 32 MB)
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 w-full max-w-xl">
            <div className="flex items-center gap-4 text-left">
              <div className="w-10 h-10 border border-zinc-700 bg-zinc-900 flex items-center justify-center text-zinc-300 font-mono text-xs uppercase">
                {selectedFile.name.split(".").pop()?.toUpperCase()}
              </div>
              <div className="overflow-hidden">
                <p className="font-mono text-sm font-semibold text-zinc-200 truncate max-w-xs md:max-w-md">
                  {selectedFile.name}
                </p>
                <p className="text-xs font-mono text-zinc-500">
                  {formatBytes(selectedFile.size)} {"//"} Assinatura estática pronta
                </p>
              </div>
            </div>

            {!isUploading && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onClearFile();
                  if (fileInputRef.current) fileInputRef.current.value = "";
                }}
                className="text-xs font-mono text-zinc-400 hover:text-red-400 border border-zinc-800 hover:border-red-900 px-3 py-1.5 transition-colors uppercase tracking-wider"
              >
                Trocar Arquivo
              </button>
            )}
          </div>
        )}
      </div>

      {validationError && (
        <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs font-mono">
          [AVISO] {validationError}
        </div>
      )}

      {selectedFile && !isUploading && (
        <button
          type="button"
          onClick={onSubmit}
          className="self-start bg-zinc-100 text-zinc-900 font-bold px-6 py-2.5 text-sm uppercase tracking-wider hover:bg-white transition-colors font-mono cursor-pointer flex items-center gap-2"
        >
          <span>Analisar Documento</span>
          <span className="text-xs">&rarr;</span>
        </button>
      )}
    </div>
  );
}
