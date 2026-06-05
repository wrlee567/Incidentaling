import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        panel: "#0f172a",
        panelborder: "#1e293b",
      },
    },
  },
  plugins: [],
};

export default config;
