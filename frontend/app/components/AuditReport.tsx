"use client";
import { Printer, X } from "lucide-react";

interface Finding {
  id: string; type: string; swc_id: string; severity: string;
  location: string; description: string;
  exploit_scenario?: string; recommendation?: string;
}
interface ReportProps { result: any; sourceCode: string; onClose: () => void; }

/* ---- helpers ---- */
function buildFindings(result: any): Finding[] {
  const st = result?.ai_analysis_structured; if (!st) return [];
  const out: Finding[] = []; let idx = 1;
  const push = (v: any, prefix: string) => {
    if (!v) return;
    out.push({ id: `${prefix}-${String(idx).padStart(2, "0")}`, type: v.type || "Unknown", swc_id: v.swc_id || "N/A", severity: v.severity || "Unknown", location: v.location || "N/A", description: v.description || "", exploit_scenario: v.exploit_scenario, recommendation: v.recommendation });
    idx++;
  };
  push(st.primary_vulnerability, severityPrefix(st.primary_vulnerability?.severity));
  for (const s of st.secondary_warnings || []) {
    if (out.length > 0 && s.swc_id === out[0].swc_id && s.location === out[0].location) continue;
    push(s, severityPrefix(s.severity));
  }
  return out;
}
function severityPrefix(s: string | undefined) {
  const l = (s || "").toLowerCase();
  if (l === "critical") return "C";
  if (l === "high") return "H";
  if (l === "medium") return "M";
  return "L";
}
function countSev(findings: Finding[]) {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of findings) { const k = f.severity as keyof typeof c; if (k in c) c[k]++; }
  return c;
}
function today() { return new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }); }

/* ---- styles (inline for print) ---- */
const SERIF = "'Georgia', 'Times New Roman', 'Noto Serif', serif";
const MONO = "'Fira Code', 'Consolas', 'Monaco', monospace";

const P = {
  page: { background: "#fff", color: "#1a1a1a", fontFamily: SERIF, maxWidth: 800, margin: "0 auto", padding: "40px 48px", lineHeight: 1.7, fontSize: 14.5 } as React.CSSProperties,
  mono: { fontFamily: MONO, fontSize: 12.5 } as React.CSSProperties,

  // headings — all serif
  h1: { fontSize: 32, fontWeight: 800, margin: "0 0 4px", letterSpacing: -0.5, fontFamily: SERIF } as React.CSSProperties,
  h2: { fontSize: 24, fontWeight: 800, margin: "36px 0 12px", paddingBottom: 8, borderBottom: "3px solid #1a1a1a", fontFamily: SERIF, pageBreakAfter: "avoid" as const } as React.CSSProperties,
  h3: { fontSize: 20, fontWeight: 800, margin: "24px 0 8px", paddingBottom: 6, borderBottom: "2px solid #1a1a1a", fontFamily: SERIF, pageBreakAfter: "avoid" as const } as React.CSSProperties,
  h4: { fontSize: 17, fontWeight: 700, margin: "24px 0 8px", fontFamily: SERIF } as React.CSSProperties,

  // table — serif
  table: { width: "100%", borderCollapse: "collapse" as const, fontSize: 14, margin: "12px 0", fontFamily: SERIF } as React.CSSProperties,
  th: { textAlign: "left" as const, padding: "8px 12px", borderBottom: "2px solid #1a1a1a", fontWeight: 700, fontFamily: SERIF } as React.CSSProperties,
  td: { padding: "8px 12px", borderBottom: "1px solid #ddd", verticalAlign: "top" as const, fontFamily: SERIF } as React.CSSProperties,
  tdBold: { padding: "8px 12px", borderBottom: "1px solid #ddd", fontWeight: 700, fontFamily: SERIF } as React.CSSProperties,

  // matrix cell — serif
  matrix: (bg: string) => ({ padding: "6px 12px", border: "1px solid #ccc", textAlign: "center" as const, fontWeight: 600, background: bg, fontSize: 13, fontFamily: SERIF } as React.CSSProperties),

  // code block — mono only
  code: { background: "#f6f6f6", border: "1px solid #e0e0e0", borderRadius: 4, padding: "14px 18px", fontFamily: MONO, fontSize: 12, lineHeight: 1.65, overflowX: "auto" as const, whiteSpace: "pre" as const, display: "block", margin: "8px 0", color: "#333" } as React.CSSProperties,

  // inline code — mono only
  inlineCode: { background: "#f0e6e6", color: "#c0392b", padding: "1px 6px", borderRadius: 3, fontFamily: MONO, fontSize: 13 } as React.CSSProperties,

  // severity badge — serif bold
  sevBadge: (_s: string) => {
    return { display: "inline-block", fontSize: 14, fontWeight: 800, color: "#1a1a1a", fontFamily: SERIF } as React.CSSProperties;
  },

  // finding box
  findingSection: { margin: "32px 0", pageBreakInside: "avoid" as const, pageBreakBefore: "auto" as const } as React.CSSProperties,

  // recommendation diff
  diffOld: { color: "#c0392b", fontFamily: "'Fira Code', monospace", fontSize: 12 } as React.CSSProperties,
  diffNew: { color: "#27ae60", fontFamily: "'Fira Code', monospace", fontSize: 12 } as React.CSSProperties,

  // bullet
  bullet: { marginLeft: 24, marginTop: 4, marginBottom: 4 } as React.CSSProperties,

  // toolbar
  toolbar: { position: "sticky" as const, top: 0, zIndex: 50, background: "#1a1a2e", padding: "12px 24px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid #2d2d4e" } as React.CSSProperties,
  toolBtn: (bg: string) => ({ display: "inline-flex", alignItems: "center", gap: 8, padding: "8px 24px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 700, fontFamily: "sans-serif", background: bg, color: "#fff" } as React.CSSProperties),
};

/* ================================================================ */
/*  COMPONENT                                                       */
/* ================================================================ */
export default function AuditReport({ result, sourceCode, onClose }: ReportProps) {
  const st = result?.ai_analysis_structured;
  const verdict = st?.verdict || "UNKNOWN";
  const confidence = st?.confidence || "N/A";
  const findings = buildFindings(result);
  const counts = countSev(findings);
  const summary = result?.summary || {};
  const slither = result?.slither_analysis || {};
  const rag = result?.rag_findings || {};
  const llm = result?.llm_analysis || {};
  const funcAnalysis = result?.function_analysis || {};
  const reasoning = st?.reasoning || "";

  // group findings by severity
  const bySev: Record<string, Finding[]> = {};
  for (const f of findings) {
    if (!bySev[f.severity]) bySev[f.severity] = [];
    bySev[f.severity].push(f);
  }
  const sevOrder = ["Critical", "High", "Medium", "Low"];

  const handlePrint = () => {
    const el = document.getElementById("report-content");
    if (!el) return;
    const title = `Audit Report - ${result?.filename || "contract.sol"}`;

    // Remove old iframe if exists
    const old = document.getElementById("print-frame");
    if (old) old.remove();

    const iframe = document.createElement("iframe");
    iframe.id = "print-frame";
    iframe.style.cssText = "position:fixed;top:0;left:0;width:0;height:0;border:none;visibility:hidden;";
    document.body.appendChild(iframe);

    const doc = iframe.contentDocument || iframe.contentWindow?.document;
    if (!doc) return;

    doc.open();
    doc.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title>
<style>
  @page { margin: 18mm 15mm 20mm 15mm; size: A4 portrait; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0; }
  h2 { page-break-after: avoid; }
  h3 { page-break-after: avoid; }
  h4 { page-break-after: avoid; }
  table { page-break-inside: avoid; }
  pre { page-break-inside: avoid; white-space: pre-wrap !important; word-wrap: break-word !important; overflow-wrap: break-word !important; max-width: 100% !important; }
  img { max-width: 100%; }
</style>
</head><body>${el.innerHTML}</body></html>`);
    doc.close();

    iframe.onload = () => {
      setTimeout(() => {
        iframe.contentWindow?.print();
      }, 300);
    };
    // Fallback: if onload doesn't fire (already loaded)
    setTimeout(() => {
      iframe.contentWindow?.print();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-[100] overflow-auto bg-white" id="audit-report">
      {/* Toolbar */}
      <div style={P.toolbar}>
        <span style={{ color: "#e2e8f0", fontSize: 14, fontWeight: 700, fontFamily: "sans-serif" }}>Audit Report Preview</span>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={handlePrint} style={P.toolBtn("#4f46e5")}><Printer size={16} /> Print / Save PDF</button>
          <button onClick={onClose} style={P.toolBtn("#334155")}><X size={16} /> Close</button>
        </div>
      </div>

      <div id="report-content" style={P.page}>

        {/* ===================== COVER ===================== */}
        <div style={{ textAlign: "center", padding: "120px 0 80px", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", pageBreakAfter: "always" }}>
          <h1 style={{ fontSize: 36, fontWeight: 800, lineHeight: 1.2 }}>Smart Contract Security<br />Review</h1>
          <div style={{ width: 80, height: 3, background: "#1a1a1a", margin: "24px auto" }} />
          <p style={{ fontSize: 22, fontWeight: 700, marginTop: 8 }}>DarkHotel Security Auditor</p>
          <p style={{ color: "#666", marginTop: 12, fontSize: 15 }}>
            Conducted by: DarkHotel Automated Pipeline v7.0
          </p>
          <p style={{ color: "#666", marginTop: 4, fontSize: 15 }}>{today()}</p>
          <div style={{ marginTop: 40, padding: "12px 32px", border: "2px solid #1a1a1a", display: "inline-block" }}>
            <span style={{ fontSize: 14, fontWeight: 700 }}>{result?.filename || "contract.sol"}</span>
          </div>
        </div>

        {/* ===================== CONTENTS ===================== */}
        <h2 style={P.h2}>Contents</h2>
        <div style={{ fontSize: 14, lineHeight: 2.2 }}>
          {[
            "1. About DarkHotel",
            "2. Disclaimer",
            "3. Introduction",
            `4. About ${result?.filename || "Contract"}`,
            "5. Risk Classification",
            "6. Security Assessment Summary",
            "7. Executive Summary",
            ...(findings.length > 0 ? ["8. Findings"] : []),
            `${findings.length > 0 ? "9" : "8"}. Static Analysis (Slither)`,
            `${findings.length > 0 ? "10" : "9"}. AI Analysis Details`,
            "Appendix A: Source Code",
          ].map((item, i) => (
            <div key={i} style={{ borderBottom: "1px dotted #ccc", display: "flex", justifyContent: "space-between" }}>
              <span>{item}</span>
            </div>
          ))}
        </div>

        {/* ===================== 1. ABOUT ===================== */}
        <h2 style={P.h2}>1. About DarkHotel</h2>
        <p>
          DarkHotel is an AI-powered smart contract vulnerability detection system developed as a capstone project.
          It employs a 6-step sequential pipeline combining static analysis, knowledge base retrieval, and large language
          model reasoning to identify security vulnerabilities in Solidity smart contracts.
        </p>
        <p style={{ marginTop: 8 }}>
          The system focuses on three critical vulnerability categories: <strong>Reentrancy (SWC-107)</strong>,{" "}
          <strong>Integer Overflow/Underflow (SWC-101)</strong>, and <strong>Unchecked Return Value (SWC-104)</strong>.
        </p>

        {/* ===================== 2. DISCLAIMER ===================== */}
        <h2 style={P.h2}>2. Disclaimer</h2>
        <p>
          An automated smart contract security review can never verify the complete absence of vulnerabilities.
          This is an automated analysis using static analysis tools, knowledge base retrieval, and AI reasoning
          where we try to find as many vulnerabilities as possible within the 3 target categories.
          We can not guarantee 100% security after the review or even if the review will find all problems
          with your smart contracts. Subsequent manual security reviews, bug bounty programs and on-chain
          monitoring are strongly recommended.
        </p>

        {/* ===================== 3. INTRODUCTION ===================== */}
        <h2 style={P.h2}>3. Introduction</h2>
        <p>
          An automated security review of the <strong>{result?.filename || "contract.sol"}</strong> file was performed
          by <strong>DarkHotel Security Auditor</strong>, with a focus on the security aspects of the smart contract
          implementation. The analysis was conducted using the DarkHotel v7.0 pipeline on {today()}.
        </p>

        {/* ===================== 4. ABOUT CONTRACT ===================== */}
        <h2 style={P.h2}>4. About {result?.filename?.replace(".sol", "") || "Contract"}</h2>
        <p>
          The analyzed contract is written in Solidity {summary.solidity_version || "N/A"} and consists
          of {summary.total_lines || "N/A"} lines of code with {summary.total_functions || "N/A"} functions.
          {(funcAnalysis.risky_functions || 0) > 0 && ` Of these, ${funcAnalysis.risky_functions} functions were identified as potentially risky based on AST analysis (containing external calls, state changes, or missing reentrancy guards).`}
        </p>

        {/* ===================== 5. RISK CLASSIFICATION ===================== */}
        <h2 style={P.h2}>5. Risk Classification</h2>
        <p>
          DarkHotel assigns severity levels based on calibration rules derived from 21,032 real audit cases
          in the knowledge base (FORGE-Curated + audits-with-reasons). The LLM applies these rules during
          Chain-of-Thought reasoning to determine the appropriate severity for each finding.
        </p>

        <h3 style={P.h3}>5.1. Severity Calibration Rules</h3>
        <p>The following rules are applied per vulnerability type:</p>
        <table style={P.table}>
          <thead>
            <tr>
              <th style={P.th}>Vulnerability</th>
              <th style={P.th}>Condition</th>
              <th style={P.th}>Severity</th>
            </tr>
          </thead>
          <tbody>
            <tr><td style={P.td}>Reentrancy (SWC-107)</td><td style={P.td}>Full fund drain via unprotected external call before state update</td><td style={P.td}><span style={P.sevBadge("Critical")}>Critical</span></td></tr>
            <tr><td style={P.td}>Reentrancy (SWC-107)</td><td style={P.td}>Reentrancy with capped or limited re-enterable amount</td><td style={P.td}><span style={P.sevBadge("Medium")}>Medium</span></td></tr>
            <tr><td style={P.td}>Integer Overflow (SWC-101)</td><td style={P.td}>Overflow affecting balances, token supply, or authorization</td><td style={P.td}><span style={P.sevBadge("High")}>High</span></td></tr>
            <tr><td style={P.td}>Integer Overflow (SWC-101)</td><td style={P.td}>Overflow on bounded arithmetic (e.g., price * small quantity)</td><td style={P.td}><span style={P.sevBadge("Medium")}>Medium</span></td></tr>
            <tr><td style={P.td}>Unchecked Return (SWC-104)</td><td style={P.td}>Unchecked <code style={P.inlineCode}>.send()</code> / <code style={P.inlineCode}>.call()</code> on main withdrawal path</td><td style={P.td}><span style={P.sevBadge("High")}>High</span></td></tr>
            <tr><td style={P.td}>Unchecked Return (SWC-104)</td><td style={P.td}>Unchecked <code style={P.inlineCode}>.send()</code> on refund of excess only</td><td style={P.td}><span style={P.sevBadge("Medium")}>Medium</span></td></tr>
          </tbody>
        </table>

        <h3 style={P.h3}>5.2. Safe Pattern Recognition</h3>
        <p>The system does <strong>not</strong> report a vulnerability if any of the following protections are detected:</p>
        <ul style={P.bullet}>
          <li><strong>SWC-107:</strong> ReentrancyGuard / <code style={P.inlineCode}>nonReentrant</code> modifier, CEI pattern (state updated before external call), <code style={P.inlineCode}>.send()</code> / <code style={P.inlineCode}>.transfer()</code> (2300 gas limit), mutex/lock pattern, ERC20 high-level calls.</li>
          <li><strong>SWC-101:</strong> Solidity &ge; 0.8.0 (built-in overflow protection), SafeMath library, arithmetic on non-critical values (loop counters, timestamps).</li>
          <li><strong>SWC-104:</strong> <code style={P.inlineCode}>.transfer()</code> (auto-reverts on failure), return value captured and checked with <code style={P.inlineCode}>require()</code>, ERC20 high-level calls.</li>
        </ul>

        <h3 style={P.h3}>5.3. Post-Processing Filters</h3>
        <ul style={P.bullet}>
          <li><strong>Pragma filter:</strong> SWC-101 findings are automatically removed if Solidity version &ge; 0.8.0 (built-in overflow protection makes SWC-101 impossible).</li>
          <li><strong>Scope filter:</strong> Any finding outside SWC-107, SWC-101, SWC-104 is automatically removed.</li>
          <li><strong>Verdict adjustment:</strong> If all findings are removed by filters, verdict is changed from VULNERABLE to SAFE.</li>
        </ul>

        {/* ===================== 6. SECURITY ASSESSMENT SUMMARY ===================== */}
        <h2 style={P.h2}>6. Security Assessment Summary</h2>

        <h4 style={P.h4}>Scope</h4>
        <p>The following smart contract was in scope of the analysis:</p>
        <ul style={P.bullet}>
          <li><code style={P.inlineCode}>{result?.filename || "contract.sol"}</code></li>
        </ul>

        <h4 style={P.h4}>Analysis Pipeline</h4>
        <table style={P.table}>
          <thead><tr><th style={P.th}>Step</th><th style={P.th}>Component</th><th style={P.th}>Technology</th></tr></thead>
          <tbody>
            <tr><td style={P.td}>1</td><td style={P.td}>AST Chunking</td><td style={P.td}>tree-sitter-solidity + regex fallback</td></tr>
            <tr><td style={P.td}>2</td><td style={P.td}>Static Analysis</td><td style={P.td}>Slither (auto solc version detection)</td></tr>
            <tr><td style={P.td}>3</td><td style={P.td}>Knowledge Base Search</td><td style={P.td}>Qdrant + voyage-code-3 (1024d)</td></tr>
            <tr><td style={P.td}>4</td><td style={P.td}>Reranking + Quality Gate</td><td style={P.td}>voyage-rerank-2.5 + CRAG evaluator</td></tr>
            <tr><td style={P.td}>5</td><td style={P.td}>LLM Reasoning</td><td style={P.td}>{llm.model || "Gemini 2.5 Pro"} (Chain-of-Thought)</td></tr>
            <tr><td style={P.td}>6</td><td style={P.td}>Report Generation</td><td style={P.td}>Structured JSON output</td></tr>
          </tbody>
        </table>

        {/* ===================== 7. EXECUTIVE SUMMARY ===================== */}
        <h2 style={P.h2}>7. Executive Summary</h2>
        <p>
          Over the course of the automated security review, DarkHotel analyzed{" "}
          <strong>{result?.filename || "the contract"}</strong> using a 6-step pipeline
          ({llm.model || "Gemini 2.5 Pro"} + Slither + RAG).
          {findings.length > 0
            ? ` A total of ${findings.length} issue${findings.length > 1 ? "s were" : " was"} uncovered.`
            : " No vulnerabilities were detected in the 3 target categories."}
        </p>

        <h4 style={{ ...P.h4, textAlign: "center" }}>Contract Summary</h4>
        <table style={{ ...P.table, maxWidth: 500, margin: "12px auto" }}>
          <tbody>
            <tr><td style={P.tdBold}>Contract Name</td><td style={P.td}>{result?.filename || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Solidity Version</td><td style={P.td}>{summary.solidity_version || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Lines of Code</td><td style={P.td}>{summary.total_lines || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Functions</td><td style={P.td}>{summary.total_functions || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Analysis Date</td><td style={P.td}>{today()}</td></tr>
            <tr><td style={P.tdBold}>Pipeline Version</td><td style={P.td}>{result?.pipeline_version || "7.0"}</td></tr>
            <tr><td style={P.tdBold}>LLM Model</td><td style={P.td}>{llm.model || "N/A"}</td></tr>
            <tr>
              <td style={P.tdBold}>Verdict</td>
              <td style={P.td}>
                <span style={P.sevBadge(verdict === "SAFE" ? "Low" : "Critical")}>{verdict}</span>
                {" "}<span style={{ color: "#666", fontSize: 13 }}>Confidence: {confidence}</span>
              </td>
            </tr>
          </tbody>
        </table>

        <h4 style={{ ...P.h4, textAlign: "center" }}>Findings Count</h4>
        <table style={{ ...P.table, maxWidth: 320, margin: "12px auto" }}>
          <thead><tr><th style={{ ...P.th, textAlign: "center" }}>Severity</th><th style={{ ...P.th, textAlign: "center" }}>Amount</th></tr></thead>
          <tbody>
            {sevOrder.map((s) => (
              <tr key={s}><td style={{ ...P.td, textAlign: "center" }}>{s}</td><td style={{ ...P.td, textAlign: "center", fontWeight: 700 }}>{counts[s as keyof typeof counts]}</td></tr>
            ))}
            <tr><td style={{ ...P.tdBold, textAlign: "center" }}>Total Findings</td><td style={{ ...P.tdBold, textAlign: "center" }}>{findings.length}</td></tr>
          </tbody>
        </table>

        {/* Summary of Findings table */}
        {findings.length > 0 && (
          <>
            <h4 style={{ ...P.h4, textAlign: "center" }}>Summary of Findings</h4>
            <table style={P.table}>
              <thead>
                <tr>
                  <th style={P.th}>ID</th>
                  <th style={P.th}>Title</th>
                  <th style={P.th}>Severity</th>
                  <th style={P.th}>Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td style={{ ...P.td, fontWeight: 700 }}>[{f.id}]</td>
                    <td style={P.td}>{f.type} — {f.location}</td>
                    <td style={P.td}><span style={P.sevBadge(f.severity)}>{f.severity}</span></td>
                    <td style={{ ...P.td, fontSize: 13 }}>Open</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {/* ===================== 8. FINDINGS ===================== */}
        {findings.length > 0 && (
          <>
            <h2 style={P.h2}>8. Findings</h2>

            {sevOrder.map((sev) => {
              const group = bySev[sev];
              if (!group || group.length === 0) return null;
              return (
                <div key={sev}>
                  <h3 style={P.h3}>8.{sevOrder.indexOf(sev) + 1}. {sev} Findings</h3>

                  {group.map((f) => (
                    <div key={f.id} style={P.findingSection}>
                      <h3 style={{ ...P.h3, borderBottom: "2px solid #c0392b" }}>
                        [{f.id}] {f.type}
                      </h3>

                      <h4 style={P.h4}>Severity</h4>
                      <div style={{ marginLeft: 24 }}>
                        <p><strong>Severity:</strong> <span style={P.sevBadge(f.severity)}>{f.severity}</span></p>
                        <p><strong>SWC ID:</strong> <code style={P.inlineCode}>{f.swc_id}</code></p>
                        <p><strong>Location:</strong> <code style={P.inlineCode}>{f.location}</code></p>
                      </div>

                      <h4 style={P.h4}>Description</h4>
                      <p style={{ whiteSpace: "pre-wrap" }}>{f.description}</p>

                      {f.exploit_scenario && (
                        <>
                          <h4 style={P.h4}>Exploit Scenario</h4>
                          <p style={{ whiteSpace: "pre-wrap" }}>{f.exploit_scenario}</p>
                        </>
                      )}

                      {f.recommendation && (
                        <>
                          <h4 style={P.h4}>Recommendations</h4>
                          <p style={{ whiteSpace: "pre-wrap" }}>{f.recommendation}</p>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
          </>
        )}

        {/* ===================== 9. SLITHER ===================== */}
        <h2 style={P.h2}>{findings.length > 0 ? "9" : "8"}. Static Analysis (Slither)</h2>
        {(slither.warnings || []).length === 0 ? (
          <p>No Slither warnings reported.</p>
        ) : (
          <>
            <p>Slither identified {slither.total_warnings} warning(s){slither.hints_used?.length > 0 ? ` (detectors triggered: ${slither.hints_used.join(", ")})` : ""}:</p>
            {slither.warnings.map((w: string, i: number) => (
              <pre key={i} style={P.code}>{w}</pre>
            ))}
          </>
        )}

        {/* ===================== 10. AI DETAILS ===================== */}
        <h2 style={P.h2}>{findings.length > 0 ? "10" : "9"}. AI Analysis Details</h2>

        <h4 style={P.h4}>Function Analysis</h4>
        <table style={P.table}>
          <thead>
            <tr>
              <th style={P.th}>Function</th>
              <th style={P.th}>Contract</th>
              <th style={P.th}>External Call</th>
              <th style={P.th}>State Change</th>
              <th style={P.th}>Risk Indicators</th>
            </tr>
          </thead>
          <tbody>
            {(funcAnalysis.functions_analyzed || []).map((fn: any, i: number) => (
              <tr key={i}>
                <td style={{ ...P.td, ...P.mono }}>{fn.name}()</td>
                <td style={P.td}>{fn.contract}</td>
                <td style={P.td}>{fn.has_external_call ? "Yes" : "No"}</td>
                <td style={P.td}>{fn.has_state_change ? "Yes" : "No"}</td>
                <td style={{ ...P.td, fontSize: 12 }}>{(fn.risk_indicators || []).join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h4 style={P.h4}>RAG Knowledge Base</h4>
        <table style={{ ...P.table, maxWidth: 550 }}>
          <tbody>
            <tr><td style={P.tdBold}>Candidates Retrieved</td><td style={P.td}>{rag.total_candidates || 0}</td></tr>
            <tr><td style={P.tdBold}>Top-K After Reranking</td><td style={P.td}>{rag.top_k_ranked || 0}</td></tr>
            <tr><td style={P.tdBold}>CRAG Gate</td><td style={P.td}>{rag.crag_action || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Max Relevance Score</td><td style={P.td}>{rag.score_distribution?.max_relevance?.toFixed(4) || "N/A"}</td></tr>
            <tr><td style={P.tdBold}>Knowledge Base</td><td style={P.td}>{rag.version || "N/A"}</td></tr>
          </tbody>
        </table>

        {(rag.similar_cases || []).length > 0 && (
          <table style={P.table}>
            <thead>
              <tr><th style={P.th}>#</th><th style={P.th}>Type</th><th style={P.th}>SWC</th><th style={P.th}>Relevance</th><th style={P.th}>Source</th></tr>
            </thead>
            <tbody>
              {rag.similar_cases.slice(0, 5).map((c: any, i: number) => (
                <tr key={i}>
                  <td style={P.td}>{i + 1}</td>
                  <td style={{ ...P.td, fontWeight: 600 }}>{c.type}</td>
                  <td style={{ ...P.td, ...P.mono }}>{c.swc_id}</td>
                  <td style={{ ...P.td, ...P.mono }}>{c.relevance_score?.toFixed(4)}</td>
                  <td style={{ ...P.td, fontSize: 12 }}>{c.audit_company || "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {reasoning && (
          <>
            <h4 style={P.h4}>Chain-of-Thought Reasoning</h4>
            <div style={{ ...P.code, whiteSpace: "pre-wrap", lineHeight: 1.75, fontSize: 13 }}>{reasoning}</div>
          </>
        )}

        {/* ===================== APPENDIX: SOURCE CODE ===================== */}
        {sourceCode && (
          <>
            <h2 style={P.h2}>Appendix A: Source Code</h2>
            <pre style={P.code}>
              {sourceCode.split("\n").map((line, i) => `${String(i + 1).padStart(4)}  ${line}`).join("\n")}
            </pre>
          </>
        )}

        {/* ===================== FOOTER ===================== */}
        <div style={{ marginTop: 64, paddingTop: 16, borderTop: "3px solid #1a1a1a", textAlign: "center" }}>
          <p style={{ color: "#666", fontSize: 12 }}>
            Generated by <strong>DarkHotel Security Auditor v7.0</strong> — {today()}
          </p>
          <p style={{ color: "#999", fontSize: 11, marginTop: 4 }}>
            Pipeline: AST (tree-sitter) → Slither → RAG (voyage-code-3 + Qdrant) → Voyage Rerank + CRAG → {llm.model || "Gemini 2.5 Pro"}
          </p>
        </div>

      </div>
    </div>
  );
}
