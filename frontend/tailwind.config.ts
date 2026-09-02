import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
  extend: {
    colors: {
      risk: {
        low: "#22c55e",      // green
        medium: "#eab308",   // yellow
        high: "#f97316",     // orange
        critical: "#ef4444", // red
      },
    },
  },
},
  plugins: [],
};

export default config;
