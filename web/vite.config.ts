import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const backend = "http://127.0.0.1:7070";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: backend, changeOrigin: true },
      "/openapi": { target: backend, changeOrigin: true },
      "/hubs": { target: backend, changeOrigin: true, ws: true },
    },
  },
  build: {
    outDir: "../src/Drederick.Web/wwwroot",
    emptyOutDir: true,
  },
});
