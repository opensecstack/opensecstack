/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Resolve TypeScript sources ahead of any stale compiled .js artifacts that
  // may sit alongside them in src/, so a leftover Login.js can never shadow
  // the maintained Login.tsx (which offers the sinauth SSO flow).
  resolve: {
    extensions: [".tsx", ".ts", ".jsx", ".js", ".json"],
  },
  server: {
    port: 3009,
    host: true,
    proxy: {
      "/api": process.env.DEV_API_PROXY || "http://localhost:8091",
      "/metrics": process.env.DEV_API_PROXY || "http://localhost:8091",
    },
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    coverage: {
      reporter: ["text", "html"],
    },
  },
});
