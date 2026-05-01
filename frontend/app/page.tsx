"use client";
import { useState, useEffect, useCallback } from "react";
import {
  Upload, FileCode, ShieldAlert, ShieldCheck, CheckCircle, Activity,
  Terminal, AlertTriangle, ChevronDown, Crosshair, Info,
  Search, Database, Sun, Moon, Download, Clipboard, Clock, Trash2, Printer,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import SourceCodeViewer from "./components/SourceCodeViewer";
import AuditReport from "./components/AuditReport";
import FloatingCoins from "./components/FloatingCoins";

/* ================================================================ */
/*  TYPES                                                           */
/* ================================================================ */
interface HistoryEntry {
  id: string; filename: string; verdict: string;
  timestamp: string; result: any; sourceCode: string;
}

/* ================================================================ */
/*  HOOKS                                                           */
/* ================================================================ */
function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  useEffect(() => { const s = localStorage.getItem("dh-theme") as "dark" | "light" | null; if (s) setTheme(s); }, []);
  const toggle = useCallback(() => {
    setTheme((p) => { const n = p === "dark" ? "light" : "dark"; document.documentElement.classList.remove("dark", "light"); document.documentElement.classList.add(n); localStorage.setItem("dh-theme", n); return n; });
  }, []);
  return { theme, toggle };
}

function useFontSize() {
  const sizes = ["font-sm", "font-md", "font-lg"] as const;
  type S = (typeof sizes)[number];
  const [size, setSize] = useState<S>("font-md");
  useEffect(() => { const s = localStorage.getItem("dh-font") as S | null; if (s && sizes.includes(s)) setSize(s); }, []);
  const change = useCallback((s: S) => { setSize(s); document.documentElement.classList.remove("font-sm", "font-md", "font-lg"); document.documentElement.classList.add(s); localStorage.setItem("dh-font", s); }, []);
  return { size, change, sizes };
}

function useHistory() {
  const [list, setList] = useState<HistoryEntry[]>([]);
  useEffect(() => { try { const r = localStorage.getItem("dh-history"); if (r) setList(JSON.parse(r)); } catch {} }, []);
  const add = useCallback((e: HistoryEntry) => { setList((p) => { const n = [e, ...p].slice(0, 10); localStorage.setItem("dh-history", JSON.stringify(n)); return n; }); }, []);
  const clear = useCallback(() => { setList([]); localStorage.removeItem("dh-history"); }, []);
  return { list, add, clear };
}

/* ================================================================ */
/*  HELPERS                                                         */
/* ================================================================ */
function sevBadge(severity: string) {
  const s = severity?.toLowerCase() || "";
  if (s === "critical") return "bg-red-600 text-white sev-critical";
  if (s === "high") return "bg-red-600 text-white sev-high";
  if (s === "medium") return "bg-amber-500 text-white";
  if (s === "low") return "bg-sky-500 text-white";
  return "bg-slate-500 text-white";
}

function slitherSeverity(w: string): { level: string; style: string; tagStyle: string } {
  const l = w.toLowerCase();
  if (l.startsWith("[high]")) return {
    level: "HIGH",
    style: "border-l-4 border-red-500 bg-red-50 dark:bg-red-500/10 text-red-900 dark:text-red-200",
    tagStyle: "bg-red-600 text-white sev-high",
  };
  if (l.startsWith("[medium]")) return {
    level: "MEDIUM",
    style: "border-l-4 border-amber-500 bg-amber-50 dark:bg-amber-500/8 text-amber-900 dark:text-amber-200",
    tagStyle: "bg-amber-500 text-white",
  };
  if (l.startsWith("[low]")) return {
    level: "LOW",
    style: "border-l-4 border-sky-500 bg-sky-50 dark:bg-sky-500/8 text-sky-900 dark:text-sky-200",
    tagStyle: "bg-sky-500 text-white",
  };
  return {
    level: "INFO",
    style: "border-l-4 border-slate-400 bg-slate-50 dark:bg-slate-500/8 text-slate-700 dark:text-slate-300",
    tagStyle: "bg-slate-500 text-white",
  };
}

function slitherClean(text: string): string {
  return text
    // Full path with line ref: (C:/.../file.sol#23-32) → (line 23-32)
    .replace(/\([A-Za-z]:[\s\S]*?#(\d+(?:-\d+)?)\)/g, "(line $1)")
    // Full path without line ref: (C:/...) → remove
    .replace(/\([A-Za-z]:[^)]*\)/g, "")
    // Truncated path (no closing paren): C:/Users/anything...
    .replace(/[A-Za-z]:[\\/][^\n]*/g, "")
    // Remove empty parens () only when standalone (not part of function calls)
    .replace(/\(\s*\)(?!\s*[{(])/g, "")
    // Remove dangling ( at very end of string
    .replace(/\s*\(\s*$/gm, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

interface SlitherParsed {
  detector: string | null;
  line: string | null;
  functionName: string | null;
  externalCalls: string[];
  stateWrites: string[];
  eventsEmitted: string[];
  rawDesc: string;
}

function slitherParse(w: string): SlitherParsed {
  const cleaned = slitherClean(w);
  const match = cleaned.match(/^\[(\w+)\]\s*([\w-]+)(?:\s*\(line\s*(\d+)\))?[:\s]*([\s\S]*)/);
  if (!match) return { detector: null, line: null, functionName: null, externalCalls: [], stateWrites: [], eventsEmitted: [], rawDesc: cleaned };

  const detector = match[2];
  const line = match[3] || null;
  const body = slitherClean(match[4]?.trim() || "");

  // Extract function name: "Reentrancy in Contract.func() ..."
  const funcMatch = body.match(/in\s+([\w.]+\(\)|\w+\.\w+\([^)]*\))/);
  const functionName = funcMatch ? funcMatch[1] : null;

  // Extract external calls
  const extCalls: string[] = [];
  const extSection = body.match(/External calls?:\s*([\s\S]*?)(?:State variables|Event emitted|$)/i);
  if (extSection) {
    for (const m of extSection[1].matchAll(/- (.+?)(?=\n- |\n|$)/g)) {
      const call = m[1].trim();
      if (call) extCalls.push(call);
    }
  }

  // Extract state variables written
  const stateWrites: string[] = [];
  const stateSection = body.match(/State variables written after.*?:\s*([\s\S]*?)(?:Event emitted|$)/i);
  if (stateSection) {
    for (const m of stateSection[1].matchAll(/- (.+?)(?=\n- |\n|$)/g)) {
      const sv = m[1].trim();
      if (sv) stateWrites.push(sv);
    }
  }

  // Extract events emitted
  const eventsEmitted: string[] = [];
  const eventSection = body.match(/Event emitted after.*?:\s*([\s\S]*?)$/i);
  if (eventSection) {
    for (const m of eventSection[1].matchAll(/- (.+?)(?=\n- |\n|$)/g)) {
      const ev = m[1].trim();
      if (ev) eventsEmitted.push(ev);
    }
  }

  // If no structured data extracted, use raw desc
  const rawDesc = (!functionName && extCalls.length === 0 && eventsEmitted.length === 0) ? body : "";

  return { detector, line, functionName, externalCalls: extCalls, stateWrites, eventsEmitted, rawDesc };
}

function parseVulnLines(result: any): Set<number> {
  const lines = new Set<number>();
  const st = result?.ai_analysis_structured;
  if (!st) return lines;
  const ex = (loc: string) => { for (const m of loc.matchAll(/(?:line\s*|L)(\d+)/gi)) lines.add(parseInt(m[1])); };
  if (st.primary_vulnerability?.location) ex(st.primary_vulnerability.location);
  for (const s of st.secondary_warnings || []) if (s.location) ex(s.location);
  for (const v of st.vulnerabilities || []) if (v.location) ex(v.location);
  return lines;
}

/* ================================================================ */
/*  PANEL                                                           */
/* ================================================================ */
function Panel({ title, icon, badge, color, open, onToggle, children }: {
  title: string; icon: React.ReactNode; badge?: string; color: string;
  open: boolean; onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div className="card overflow-hidden">
      <button onClick={onToggle} className="w-full px-5 py-3 flex items-center justify-between hover:bg-[var(--accent-subtle)] transition-colors">
        <h3 className={`font-semibold flex items-center gap-2 text-sm tracking-wide ${color}`}>
          {icon} {title}
          {badge && <span className="text-[11px] bg-[var(--accent-subtle)] text-accent px-2 py-0.5 rounded font-medium">{badge}</span>}
        </h3>
        <ChevronDown className={`w-4 h-4 text-on-surface-muted transition-transform duration-200 ${open ? "rotate-180" : ""}`} />
      </button>
      {open && <div className="px-5 pb-5 pt-2 border-t border-[var(--outline)]">{children}</div>}
    </div>
  );
}

/* ================================================================ */
/*  MAIN                                                            */
/* ================================================================ */
export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [sourceCode, setSourceCode] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [elapsedTime, setElapsedTime] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [copied, setCopied] = useState(false);
  const [steps, setSteps] = useState<{ label: string; status: "pending" | "running" | "done" | "error" }[]>([]);
  const [showCode, setShowCode] = useState(false);
  const [showSlither, setShowSlither] = useState(false);
  const [showRag, setShowRag] = useState(false);
  const [showReasoning, setShowReasoning] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showReport, setShowReport] = useState(false);

  const { theme, toggle: toggleTheme } = useTheme();
  const { size: fontSize, change: changeFontSize, sizes: fontSizes } = useFontSize();
  const { list: history, add: addHistory, clear: clearHistory } = useHistory();

  const PIPELINE = [
    "Upload & Parse Contract",
    "AST Function Extraction (tree-sitter)",
    "Slither Static Analysis",
    "RAG Search (voyage-code-3 + Qdrant)",
    "Voyage Reranking + CRAG Gate",
    "LLM Analysis (Gemini 2.5 Pro)",
  ];

  useEffect(() => { if (file) file.text().then(setSourceCode).catch(() => setSourceCode("")); }, [file]);
  const onDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); }, []);
  const onDragLeave = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(false); }, []);
  const onDrop = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(false); const f = e.dataTransfer.files[0]; if (f?.name.endsWith(".sol")) setFile(f); }, []);

  const handleAnalyze = async () => {
    if (!file) return;
    if (!file.name.endsWith(".sol")) return alert("Only .sol files accepted.");
    if (file.size > 5 * 1024 * 1024) return alert("File too large (max 5MB).");
    setLoading(true); setResult(null); setError(null); setElapsedTime(null);
    setShowCode(false); setShowSlither(false); setShowRag(false); setShowReasoning(false);
    setSteps(PIPELINE.map((label, i) => ({ label, status: (i === 0 ? "running" : "pending") as any })));
    const formData = new FormData(); formData.append("file", file); const start = Date.now();
    const dur = [1000, 2000, 8000, 5000, 3000, 20000]; let idx = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const adv = () => { idx++; if (idx < PIPELINE.length) { setSteps((p) => p.map((s, i) => i < idx ? { ...s, status: "done" } : i === idx ? { ...s, status: "running" } : s)); timer = setTimeout(adv, dur[idx] || 5000); } };
    timer = setTimeout(adv, dur[0]);
    try {
      const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
      const res = await fetch(`${api}/analyze`, { method: "POST", body: formData });
      if (timer) clearTimeout(timer);
      if (!res.ok) { const e = await res.json().catch(() => ({ detail: `Error ${res.status}` })); throw new Error(e.detail); }
      const data = await res.json();
      setElapsedTime(Math.round((Date.now() - start) / 1000));
      setSteps((p) => p.map((s) => ({ ...s, status: "done" as const })));
      setResult(data);
      const v = data.ai_analysis_structured?.verdict || data.llm_analysis?.verdict || "UNKNOWN";
      addHistory({ id: Date.now().toString(), filename: file.name, verdict: v, timestamp: new Date().toLocaleString(), result: data, sourceCode });
    } catch (err: any) {
      if (timer) clearTimeout(timer);
      setError(err.message === "Failed to fetch" ? `Cannot connect to backend at ${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}` : err.message);
      setElapsedTime(Math.round((Date.now() - start) / 1000));
      setSteps((p) => p.map((s) => s.status === "running" ? { ...s, status: "error" as const } : s));
    } finally { setLoading(false); }
  };

  const exportJSON = () => { if (!result) return; const b = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = `darkhotel-${result.filename || "report"}.json`; a.click(); URL.revokeObjectURL(a.href); };
  const copyJSON = () => { if (!result) return; navigator.clipboard.writeText(JSON.stringify(result, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const loadEntry = (e: HistoryEntry) => { setResult(e.result); setSourceCode(e.sourceCode); setSteps(PIPELINE.map((l) => ({ label: l, status: "done" as const }))); setError(null); setShowHistory(false); };

  const st = result?.ai_analysis_structured;
  const verdict = st?.verdict || result?.llm_analysis?.verdict || "UNKNOWN";
  const confidence = st?.confidence || "N/A";
  const primary = st?.primary_vulnerability || null;
  const secondaries: any[] = st?.secondary_warnings || [];
  const reasoning = st?.reasoning || "";
  const isSafe = verdict === "SAFE";
  const vulnLines = parseVulnLines(result);

  return (
    <div id="main-app" className="min-h-screen p-4 md:p-6 relative">
      <FloatingCoins />
      <div className="max-w-7xl mx-auto relative z-10">

        {/* ===== HEADER ===== */}
        <header className="mb-6 flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[var(--outline)]">
          <h1 className="text-xl md:text-2xl font-bold flex items-center gap-2.5 tracking-tight">
            <ShieldAlert className="w-7 h-7 text-accent" />
            <span className="text-accent">DarkHotel</span>
            <span className="text-on-surface-muted font-normal text-sm hidden sm:inline ml-1">Security Auditor</span>
          </h1>
          <div className="flex items-center gap-1.5">
            <div className="flex rounded-lg overflow-hidden border border-[var(--outline)]">
              {fontSizes.map((s, i) => (
                <button key={s} onClick={() => changeFontSize(s)}
                  className={`px-2.5 py-1 text-xs font-bold transition-colors ${fontSize === s ? "bg-accent text-white" : "text-on-surface-muted hover:bg-[var(--accent-subtle)]"}`}>
                  {["S", "M", "L"][i]}
                </button>
              ))}
            </div>
            <button onClick={toggleTheme} className="p-2 rounded-lg border border-[var(--outline)] hover:bg-[var(--accent-subtle)] transition-colors">
              {theme === "dark" ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-indigo-500" />}
            </button>
            <span className="text-[11px] bg-accent/10 text-accent px-2.5 py-1 rounded font-bold hidden sm:block">v7.0</span>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">

          {/* ===== LEFT ===== */}
          <div className="lg:col-span-4 space-y-4">

            {/* Upload */}
            <div className="card p-5">
              <h2 className="text-xs font-bold mb-3 flex items-center gap-2 text-on-surface-muted uppercase tracking-widest">
                <Upload className="w-4 h-4 text-accent" /> Upload Contract
              </h2>
              <div onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}
                className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer group
                  ${isDragging ? "border-accent bg-[var(--accent-subtle)]" : "border-[var(--outline)] hover:border-accent/50 hover:bg-[var(--accent-subtle)]"}`}>
                <input type="file" accept=".sol" onChange={(e) => setFile(e.target.files?.[0] || null)} className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
                <FileCode className={`w-10 h-10 mx-auto mb-2 transition-colors ${isDragging ? "text-accent" : "text-on-surface-muted group-hover:text-accent"}`} />
                <p className="text-sm text-on-surface-sec">
                  {file ? <span className="text-emerald-600 dark:text-emerald-400 font-bold">{file.name}</span>
                    : isDragging ? <span className="text-accent font-semibold">Drop here</span>
                    : "Drag & drop or click to select .sol"}
                </p>
              </div>
              <button onClick={handleAnalyze} disabled={loading || !file}
                className="btn-primary mt-3 w-full py-2.5 flex items-center justify-center gap-2 text-sm">
                {loading ? <Activity className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {loading ? "Analyzing..." : "Scan Vulnerabilities"}
              </button>
            </div>

            {/* Pipeline */}
            <div className="card-alt p-4">
              <div className="flex items-center justify-between text-on-surface-muted mb-3 pb-2 border-b border-[var(--outline-dim)]">
                <span className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest"><Terminal className="w-3 h-3" /> Pipeline</span>
                {elapsedTime !== null && <span className="text-[11px] font-mono">{elapsedTime}s</span>}
              </div>
              {steps.length === 0
                ? <span className="text-on-surface-muted italic text-xs">Waiting for input...</span>
                : <div className="space-y-0.5">{steps.map((step, i) => (
                    <div key={i} className="flex items-center gap-2.5 py-1">
                      {step.status === "done" && <CheckCircle className="w-3.5 h-3.5 text-emerald-500 shrink-0" />}
                      {step.status === "running" && <Activity className="w-3.5 h-3.5 text-accent animate-spin shrink-0" />}
                      {step.status === "pending" && <div className="w-3.5 h-3.5 rounded-full border border-[var(--outline)] shrink-0" />}
                      {step.status === "error" && <AlertTriangle className="w-3.5 h-3.5 text-red-500 shrink-0" />}
                      <span className={`text-[11.5px] ${step.status === "done" ? "text-emerald-600 dark:text-emerald-400" : step.status === "running" ? "text-accent font-semibold" : step.status === "error" ? "text-red-500" : "text-on-surface-muted"}`}>{step.label}</span>
                    </div>
                  ))}</div>
              }
            </div>

            {/* Info */}
            {result?.summary && (
              <div className="card p-4 text-xs space-y-1.5">
                <h3 className="text-[11px] font-bold text-on-surface-muted uppercase tracking-widest mb-2">Contract Info</h3>
                {([["File", result.filename], ["Solidity", result.summary.solidity_version], ["Lines", result.summary.total_lines], ["Functions", result.summary.total_functions], ["Model", result.llm_analysis?.model]] as [string, any][]).map(([l, v]) => (
                  <div key={l} className="flex justify-between"><span className="text-on-surface-muted">{l}</span><span className="font-semibold">{v}</span></div>
                ))}
              </div>
            )}

            {/* Export */}
            {result && (
              <div className="space-y-2">
                <button onClick={() => setShowReport(true)}
                  className="w-full card flex items-center justify-center gap-2 py-2.5 text-xs font-bold text-accent hover:bg-[var(--accent-subtle)] transition-colors border-accent/30">
                  <Printer className="w-4 h-4" /> Generate Audit Report
                </button>
                <div className="flex gap-2">
                  <button onClick={exportJSON} className="flex-1 card flex items-center justify-center gap-2 py-2 text-xs font-semibold hover:bg-[var(--accent-subtle)] transition-colors">
                    <Download className="w-3.5 h-3.5 text-accent" /> JSON
                  </button>
                  <button onClick={copyJSON} className="flex-1 card flex items-center justify-center gap-2 py-2 text-xs font-semibold hover:bg-[var(--accent-subtle)] transition-colors">
                    <Clipboard className="w-3.5 h-3.5 text-accent" /> {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
            )}

            {/* History */}
            <div className="card overflow-hidden">
              <button onClick={() => setShowHistory(!showHistory)} className="w-full px-4 py-3 flex items-center justify-between hover:bg-[var(--accent-subtle)] transition-colors">
                <span className="flex items-center gap-2 text-[11px] font-bold text-on-surface-muted uppercase tracking-widest">
                  <Clock className="w-3.5 h-3.5" /> History
                  {history.length > 0 && <span className="bg-accent/15 text-accent px-1.5 py-0.5 rounded text-[10px] font-bold">{history.length}</span>}
                </span>
                <ChevronDown className={`w-4 h-4 text-on-surface-muted transition-transform duration-200 ${showHistory ? "rotate-180" : ""}`} />
              </button>
              {showHistory && (
                <div className="px-4 pb-3 pt-1 border-t border-[var(--outline)] space-y-1">
                  {history.length === 0 ? <p className="text-xs text-on-surface-muted italic">No scans yet</p> : (<>
                    {history.map((e) => (
                      <button key={e.id} onClick={() => loadEntry(e)} className="w-full text-left p-2 rounded-lg hover:bg-[var(--accent-subtle)] transition-colors flex items-center justify-between gap-2">
                        <div className="min-w-0"><p className="text-xs font-semibold truncate">{e.filename}</p><p className="text-[10px] text-on-surface-muted">{e.timestamp}</p></div>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded shrink-0 ${e.verdict === "SAFE" ? "bg-emerald-100 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400" : "bg-red-100 dark:bg-red-500/15 text-red-700 dark:text-red-400"}`}>{e.verdict}</span>
                      </button>
                    ))}
                    <button onClick={clearHistory} className="flex items-center gap-1 text-[10px] text-red-500 hover:text-red-400 mt-1"><Trash2 className="w-3 h-3" /> Clear all</button>
                  </>)}
                </div>
              )}
            </div>
          </div>

          {/* ===== RIGHT ===== */}
          <div className="lg:col-span-8 space-y-4">

            {/* Error */}
            {error && (
              <div className="card p-5 flex items-start gap-3" style={{ borderColor: "var(--vuln-border)", background: "var(--vuln-bg)" }}>
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" style={{ color: "var(--vuln-text)" }} />
                <div><h3 className="font-bold text-sm" style={{ color: "var(--vuln-text)" }}>Analysis Failed</h3><p className="text-sm mt-1 text-on-surface-sec">{error}</p></div>
              </div>
            )}

            {result ? (<>
              {/* VERDICT */}
              <div className="card overflow-hidden" style={{ borderColor: isSafe ? "var(--safe-border)" : "var(--vuln-border)" }}>
                <div className="p-5 flex flex-wrap items-center justify-between gap-4" style={{ background: isSafe ? "var(--safe-bg)" : "var(--vuln-bg)" }}>
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 rounded-2xl flex items-center justify-center" style={{ background: isSafe ? "var(--safe-icon-bg)" : "var(--vuln-icon-bg)" }}>
                      {isSafe ? <ShieldCheck className="w-8 h-8" style={{ color: "var(--safe-text)" }} /> : <ShieldAlert className="w-8 h-8" style={{ color: "var(--vuln-text)" }} />}
                    </div>
                    <div>
                      <h2 className="text-2xl md:text-3xl font-black tracking-tight" style={{ color: isSafe ? "var(--safe-text)" : "var(--vuln-text)" }}>{verdict}</h2>
                      <p className="text-sm text-on-surface-sec mt-0.5">
                        Confidence: <strong className="text-on-surface">{confidence}</strong>
                        {primary && <span className="ml-2 opacity-70">| {primary.type} ({primary.swc_id})</span>}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5 items-end text-[11px]">
                    <span className="bg-accent/10 text-accent px-2.5 py-1 rounded font-bold">{result.llm_analysis?.model}</span>
                    <span className="bg-purple-500/10 text-purple-600 dark:text-purple-400 px-2.5 py-1 rounded font-bold">RAG: {result.rag_findings?.top_k_ranked || 0} cases</span>
                  </div>
                </div>
              </div>

              {/* PRIMARY */}
              {primary && (
                <div className="card overflow-hidden" style={{ borderColor: "var(--vuln-border)" }}>
                  <div className="px-5 py-3 flex items-center justify-between border-b" style={{ background: "var(--vuln-bg)", borderColor: "var(--vuln-border)" }}>
                    <h3 className="font-bold flex items-center gap-2 text-xs uppercase tracking-widest" style={{ color: "var(--vuln-text)" }}>
                      <Crosshair className="w-4 h-4" /> Primary Vulnerability
                    </h3>
                    <div className="flex gap-2 items-center">
                      <span className={`px-3 py-1 rounded-lg text-xs font-bold ${sevBadge(primary.severity)}`}>{primary.severity}</span>
                      <span className="px-3 py-1 rounded-lg text-xs font-bold font-mono bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300">{primary.swc_id}</span>
                    </div>
                  </div>
                  <div className="p-5 space-y-4">
                    <div><h4 className="text-lg font-bold">{primary.type}</h4></div>
                    <p className="text-sm text-on-surface-sec leading-relaxed">{primary.description}</p>
                    {primary.exploit_scenario && (
                      <div className="p-4 rounded-xl border" style={{ background: "var(--vuln-bg)", borderColor: "var(--vuln-border)" }}>
                        <h5 className="text-[11px] font-bold uppercase mb-2 tracking-widest" style={{ color: "var(--vuln-text)" }}>Exploit Scenario</h5>
                        <p className="text-sm text-on-surface-sec leading-relaxed">{primary.exploit_scenario}</p>
                      </div>
                    )}
                    {primary.recommendation && (
                      <div className="p-4 rounded-xl border" style={{ background: "var(--safe-bg)", borderColor: "var(--safe-border)" }}>
                        <h5 className="text-[11px] font-bold uppercase mb-2 tracking-widest" style={{ color: "var(--safe-text)" }}>Recommendation</h5>
                        <p className="text-sm text-on-surface-sec leading-relaxed">{primary.recommendation}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* SECONDARY */}
              {secondaries.length > 0 && (
                <div className="card overflow-hidden border-amber-300 dark:border-amber-700/50">
                  <div className="px-5 py-3 bg-amber-50 dark:bg-amber-500/8 border-b border-amber-200 dark:border-amber-700/40">
                    <h3 className="font-bold text-amber-700 dark:text-amber-400 flex items-center gap-2 text-xs uppercase tracking-widest">
                      <AlertTriangle className="w-4 h-4" /> Secondary Warnings ({secondaries.length})
                    </h3>
                  </div>
                  <div className="divide-y divide-[var(--outline-dim)]">
                    {secondaries.map((sec: any, idx: number) => (
                      <div key={idx} className="p-4 flex items-start gap-3">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold mt-0.5 shrink-0 ${sevBadge(sec.severity)}`}>{sec.severity}</span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-bold">{sec.type}</span>
                            <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-slate-100 dark:bg-slate-700/40 text-slate-600 dark:text-slate-300">{sec.swc_id}</span>
                          </div>
                          <p className="text-xs text-on-surface-sec mt-1 leading-relaxed">{sec.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* SAFE */}
              {isSafe && !primary && (
                <div className="card p-8 text-center" style={{ borderColor: "var(--safe-border)", background: "var(--safe-bg)" }}>
                  <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-3" style={{ background: "var(--safe-icon-bg)" }}>
                    <CheckCircle className="w-9 h-9" style={{ color: "var(--safe-text)" }} />
                  </div>
                  <p className="font-bold text-lg" style={{ color: "var(--safe-text)" }}>No vulnerabilities detected</p>
                  <p className="text-xs text-on-surface-muted mt-2">Checked: Reentrancy (SWC-107) | Integer Overflow (SWC-101) | Unchecked Return Value (SWC-104)</p>
                </div>
              )}

              {/* SOURCE CODE */}
              <SourceCodeViewer code={sourceCode} highlightLines={new Set()} isOpen={showCode} onToggle={() => setShowCode(!showCode)} />

              {/* SLITHER */}
              {result.slither_analysis?.total_warnings > 0 && (
                <Panel title="SLITHER ANALYSIS" icon={<AlertTriangle className="w-4 h-4" />} badge={String(result.slither_analysis.total_warnings)}
                  color="text-orange-600 dark:text-orange-400" open={showSlither} onToggle={() => setShowSlither(!showSlither)}>
                  <div className="space-y-3">{result.slither_analysis.warnings.map((w: string, i: number) => {
                    const sev = slitherSeverity(w);
                    const p = slitherParse(w);
                    return (
                      <div key={i} className={`p-4 rounded-lg ${sev.style}`}>
                        {/* Header: severity + detector */}
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${sev.tagStyle}`}>{sev.level}</span>
                          {p.detector && <span className="text-xs font-mono font-bold">{p.detector}</span>}
                        </div>

                        {/* Function name */}
                        {p.functionName && (
                          <p className="text-sm font-semibold mb-2">{p.functionName}</p>
                        )}

                        {/* External calls */}
                        {p.externalCalls.length > 0 && (
                          <div className="mb-2">
                            <p className="text-[11px] font-bold uppercase tracking-wider opacity-60 mb-1">External Calls</p>
                            {p.externalCalls.map((c, j) => (
                              <p key={j} className="text-xs font-mono pl-3 opacity-80">{c}</p>
                            ))}
                          </div>
                        )}

                        {/* State variables written */}
                        {p.stateWrites.length > 0 && (
                          <div className="mb-2">
                            <p className="text-[11px] font-bold uppercase tracking-wider opacity-60 mb-1">State Changed After Call</p>
                            {p.stateWrites.map((s, j) => (
                              <p key={j} className="text-xs font-mono pl-3 opacity-80">{s}</p>
                            ))}
                          </div>
                        )}

                        {/* Events emitted */}
                        {p.eventsEmitted.length > 0 && (
                          <div>
                            <p className="text-[11px] font-bold uppercase tracking-wider opacity-60 mb-1">Event Emitted After Call</p>
                            {p.eventsEmitted.map((e, j) => (
                              <p key={j} className="text-xs font-mono pl-3 opacity-80">{e}</p>
                            ))}
                          </div>
                        )}

                        {/* Fallback: raw description if no structured data */}
                        {p.rawDesc && (
                          <p className="text-xs leading-relaxed opacity-90">{p.rawDesc}</p>
                        )}
                      </div>
                    );
                  })}</div>
                </Panel>
              )}

              {/* RAG */}
              {result.rag_findings?.vuln_type && (
                <Panel title="RAG KNOWLEDGE BASE" icon={<Database className="w-4 h-4" />} badge={result.rag_findings?.version}
                  color="text-violet-600 dark:text-violet-400" open={showRag} onToggle={() => setShowRag(!showRag)}>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold ${result.rag_findings?.found ? "bg-red-100 dark:bg-red-500/12 text-red-700 dark:text-red-400" : "bg-emerald-100 dark:bg-emerald-500/12 text-emerald-700 dark:text-emerald-400"}`}>{result.rag_findings.vuln_type}</span>
                      <span className="text-[11px] text-on-surface-muted">{result.rag_findings.total_candidates} candidates, {result.rag_findings.top_k_ranked} ranked</span>
                    </div>
                    {result.rag_findings.crag_action && (
                      <span className={`inline-block px-2.5 py-0.5 rounded text-[11px] font-bold ${
                        result.rag_findings.crag_action === "CORRECT" ? "bg-emerald-100 dark:bg-emerald-500/12 text-emerald-700 dark:text-emerald-400"
                        : result.rag_findings.crag_action === "AMBIGUOUS" ? "bg-amber-100 dark:bg-amber-500/12 text-amber-700 dark:text-amber-400"
                        : "bg-slate-100 dark:bg-slate-700/40 text-on-surface-muted"}`}>
                        CRAG: {result.rag_findings.crag_action}
                      </span>
                    )}
                  </div>
                </Panel>
              )}

              {/* REASONING */}
              {(reasoning || result.ai_analysis) && (
                <Panel title="AI REASONING" icon={<Info className="w-4 h-4" />} color="text-cyan-600 dark:text-cyan-400" open={showReasoning} onToggle={() => setShowReasoning(!showReasoning)}>
                  <div className="p-4 rounded-xl border border-[var(--outline)] text-sm leading-relaxed prose dark:prose-invert prose-sm max-w-none" style={{ background: "var(--code-bg)" }}>
                    <ReactMarkdown>{reasoning || result.ai_analysis}</ReactMarkdown>
                  </div>
                </Panel>
              )}
            </>) : (
              <div className="h-full flex flex-col items-center justify-center border border-[var(--outline)] rounded-2xl min-h-[500px] card">
                <div className="empty-icon mb-6">
                  <div className="w-20 h-20 rounded-2xl flex items-center justify-center" style={{ background: "var(--accent-subtle)", border: "1px solid var(--outline)" }}>
                    <ShieldAlert className="w-10 h-10 text-accent opacity-40" />
                  </div>
                </div>
                <p className="text-on-surface-sec text-sm font-medium">Upload a .sol file and click Scan to begin</p>
                <p className="text-[11px] text-on-surface-muted mt-2">Detects: Reentrancy | Integer Overflow | Unchecked Return Value</p>
                <div className="flex gap-3 mt-6">
                  {["SWC-107", "SWC-101", "SWC-104"].map(s => (
                    <span key={s} className="text-[10px] font-mono px-2.5 py-1 rounded border border-[var(--outline)] text-on-surface-muted">{s}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ===== AUDIT REPORT OVERLAY ===== */}
      {showReport && result && (
        <AuditReport result={result} sourceCode={sourceCode} onClose={() => setShowReport(false)} />
      )}
    </div>
  );
}
