import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "What the Hack - Attack Forecasting",
  description:
    "Explainable early-warning dashboard that forecasts network attacks from traffic behaviour (SIH26153).",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-slate-200 bg-white">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">SIH26153 · NTRO</p>
              <h1 className="text-lg font-bold">What the Hack — Network Attack Forecasting</h1>
            </div>
            <nav className="flex gap-4 text-sm text-slate-600">
              <span>Dashboard</span>
              <span>Alerts</span>
              <span>Upload</span>
              <span>Admin</span>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
