import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 3085,
    host: true,
    proxy: {
      "/api": process.env.DEV_API_PROXY || "http://localhost:8085",
      "/health": process.env.DEV_API_PROXY || "http://localhost:8085",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["src/test/setup.ts"],
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
