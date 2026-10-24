import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Interface servida apenas localmente; sem CDN nem recursos remotos.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", sourcemap: false, outDir: "dist", emptyOutDir: true },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
