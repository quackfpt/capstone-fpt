import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "DarkHotel Security Auditor",
  description:
    "AI-powered Smart Contract vulnerability detection with Slither + RAG + Gemini 2.5 Pro",
};

/* Load theme + font-size BEFORE first paint to prevent flash */
const themeInitScript = `
(function(){
  var t=localStorage.getItem('dh-theme')||'dark';
  var f=localStorage.getItem('dh-font')||'font-md';
  document.documentElement.classList.add(t,f);
})();
`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
