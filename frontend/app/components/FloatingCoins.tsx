"use client";

const COINS = [
  // Ethereum diamond
  { symbol: "\u25C8", color: "#627eea", bg: "rgba(98,126,234,0.12)", border: "rgba(98,126,234,0.25)", size: 72, top: "8%", left: "5%", delay: 0, dur: 7 },
  // Solidity S
  { symbol: "S", color: "#363636", bg: "rgba(100,100,100,0.1)", border: "rgba(100,100,100,0.2)", size: 56, top: "55%", left: "3%", delay: 2, dur: 9, font: "'Georgia', serif" },
  // Shield (security)
  { symbol: "\u25CA", color: "#22d3ee", bg: "rgba(34,211,238,0.08)", border: "rgba(34,211,238,0.2)", size: 48, top: "75%", left: "8%", delay: 4, dur: 8 },
  // BNB
  { symbol: "\u25C6", color: "#f0b90b", bg: "rgba(240,185,11,0.1)", border: "rgba(240,185,11,0.2)", size: 64, top: "15%", right: "4%", delay: 1, dur: 10 },
  // Polygon
  { symbol: "\u2B22", color: "#8247e5", bg: "rgba(130,71,229,0.1)", border: "rgba(130,71,229,0.25)", size: 52, top: "45%", right: "6%", delay: 3, dur: 7.5 },
  // Chain link
  { symbol: "\u26D3", color: "#2a5ada", bg: "rgba(42,90,218,0.08)", border: "rgba(42,90,218,0.2)", size: 44, top: "82%", right: "10%", delay: 5, dur: 9 },
  // Lock (security)
  { symbol: "\u{1F512}", color: "#10b981", bg: "rgba(16,185,129,0.08)", border: "rgba(16,185,129,0.2)", size: 40, top: "35%", left: "6%", delay: 6, dur: 11 },
  // Code block
  { symbol: "{}", color: "#818cf8", bg: "rgba(129,140,248,0.08)", border: "rgba(129,140,248,0.2)", size: 50, top: "90%", left: "15%", delay: 1.5, dur: 8.5, font: "'Fira Code', monospace" },
  // Bug
  { symbol: "\u{1F41B}", color: "#f87171", bg: "rgba(248,113,113,0.08)", border: "rgba(248,113,113,0.2)", size: 38, top: "65%", right: "3%", delay: 7, dur: 10 },
  // Star
  { symbol: "\u2726", color: "#fbbf24", bg: "rgba(251,191,36,0.08)", border: "rgba(251,191,36,0.2)", size: 36, top: "5%", right: "12%", delay: 3.5, dur: 6.5 },
];

export default function FloatingCoins() {
  return (
    <div className="floating-coins fixed inset-0 overflow-hidden pointer-events-none z-0" aria-hidden="true">
      {COINS.map((c, i) => (
        <div
          key={i}
          style={{
            position: "absolute",
            top: c.top,
            left: c.left,
            right: (c as any).right,
            width: c.size,
            height: c.size,
            borderRadius: "50%",
            background: c.bg,
            border: `1.5px solid ${c.border}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: c.size * 0.4,
            color: c.color,
            fontFamily: (c as any).font || "system-ui",
            fontWeight: 700,
            opacity: 0.5,
            animation: `coinFloat ${c.dur}s ease-in-out ${c.delay}s infinite`,
            filter: "blur(0.5px)",
          }}
        >
          {c.symbol}
        </div>
      ))}
    </div>
  );
}
