import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "url";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5174,
    host: true,
    hmr: {
      protocol: "ws",
      host: "localhost",
      port: 5174,
    },
    proxy: {
      "/api": { target: process.env.DEV_API_PROXY || "http://127.0.0.1:8090", changeOrigin: true },
      "/uploads": { target: process.env.DEV_API_PROXY || "http://127.0.0.1:8090", changeOrigin: true },
    },
  },
});
