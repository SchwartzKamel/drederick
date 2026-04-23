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
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("@microsoft/signalr")) return "signalr";
          if (id.includes("@tanstack/")) return "query";
          if (
            id.includes("@radix-ui/") ||
            id.includes("lucide-react") ||
            id.includes("class-variance-authority") ||
            id.includes("tailwind-merge") ||
            id.includes("clsx") ||
            id.includes("sonner") ||
            id.includes("tailwindcss-animate")
          ) {
            return "ui";
          }
          if (
            id.includes("/react-dom/") ||
            id.includes("/react/") ||
            id.includes("/scheduler/") ||
            id.includes("react/jsx-runtime")
          ) {
            return "react-core";
          }
          return undefined;
        },
      },
    },
  },
});
