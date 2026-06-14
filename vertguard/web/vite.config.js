/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
    plugins: [react()],
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
