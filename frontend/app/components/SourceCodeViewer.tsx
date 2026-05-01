"use client";
import { useMemo } from "react";
import { ChevronDown, Code2 } from "lucide-react";

interface Props {
  code: string;
  highlightLines: Set<number>;
  isOpen: boolean;
  onToggle: () => void;
}

export default function SourceCodeViewer({ code, highlightLines, isOpen, onToggle }: Props) {
  const lines = useMemo(() => code.split("\n"), [code]);
  if (!code) return null;
  const pad = String(lines.length).length;

  return (
    <div className="card overflow-hidden">
      <button onClick={onToggle} className="w-full px-5 py-3 flex items-center justify-between hover:bg-[var(--accent-subtle)] transition-colors">
        <h3 className="font-semibold text-accent flex items-center gap-2 text-sm tracking-wide">
          <Code2 className="w-4 h-4" /> SOURCE CODE
          <span className="text-[11px] bg-[var(--accent-subtle)] text-accent px-2 py-0.5 rounded font-medium">{lines.length} lines</span>
          {highlightLines.size > 0 && (
            <span className="text-[11px] bg-[var(--vuln-bg)] px-2 py-0.5 rounded font-bold" style={{ color: "var(--vuln-text)" }}>{highlightLines.size} flagged</span>
          )}
        </h3>
        <ChevronDown className={`w-4 h-4 text-on-surface-muted transition-transform duration-200 ${isOpen ? "rotate-180" : ""}`} />
      </button>
      {isOpen && (
        <div className="overflow-x-auto max-h-[480px] overflow-y-auto border-t border-[var(--outline)]" style={{ background: "var(--code-bg)" }}>
          <pre className="text-[12.5px] font-mono leading-[1.75]">
            {lines.map((line, i) => {
              const num = i + 1;
              const hl = highlightLines.has(num);
              return (
                <div key={i} className="flex" style={hl ? { background: "var(--code-hl-bg)", borderLeft: "3px solid var(--code-hl-border)" } : { borderLeft: "3px solid transparent" }}>
                  <span className="select-none text-on-surface-muted text-right pr-4 pl-4 py-px shrink-0 text-[11px] leading-[1.75] opacity-50">
                    {hl ? "\u25B6" : " "} {String(num).padStart(pad)}
                  </span>
                  <code className={`py-px pr-4 whitespace-pre ${hl ? "font-semibold" : ""}`} style={{ color: hl ? "var(--vuln-text)" : "var(--on-surface-sec)" }}>
                    {line || " "}
                  </code>
                </div>
              );
            })}
          </pre>
        </div>
      )}
    </div>
  );
}
