import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        bgPrimary: "var(--bg-primary)",
        bgSecondary: "var(--bg-secondary)",
        bgCard: "var(--bg-card)",
        accentBlue: "var(--accent-blue)",
        accentAmber: "var(--accent-amber)",
        accentRed: "var(--accent-red)",
        accentGreen: "var(--accent-green)",
        textPrimary: "var(--text-primary)",
        textSecondary: "var(--text-secondary)",
        borderTone: "var(--border)"
      },
      boxShadow: {
        glow: "0 0 40px rgba(59, 130, 246, 0.18)",
        amber: "0 0 32px rgba(245, 158, 11, 0.14)"
      },
      backgroundImage: {
        "grid-fade":
          "linear-gradient(rgba(148,163,184,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.08) 1px, transparent 1px)"
      },
      animation: {
        "pulse-soft": "pulseSoft 2.6s ease-in-out infinite",
        "scan-line": "scanLine 10s linear infinite",
        "float-slow": "floatSlow 8s ease-in-out infinite"
      },
      keyframes: {
        pulseSoft: {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(59,130,246,0.25)" },
          "50%": { boxShadow: "0 0 0 12px rgba(59,130,246,0.02)" }
        },
        scanLine: {
          "0%": { transform: "translateY(-10%)" },
          "100%": { transform: "translateY(110%)" }
        },
        floatSlow: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-10px)" }
        }
      }
    }
  },
  plugins: []
};

export default config;
