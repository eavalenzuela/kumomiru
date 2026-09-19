import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // Cytoscape + ELK are ~90% of the bundle and change only on upgrade;
        // isolating them keeps the app chunk small and lets the browser cache
        // the heavy vendor code across deploys.
        manualChunks(id) {
          if (id.includes("node_modules/elkjs")) return "elk";
          if (id.includes("node_modules/cytoscape")) return "cytoscape";
          if (id.includes("node_modules/react")) return "react";
          if (id.includes("node_modules/zod")) return "zod";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5173,
    // Talk to the kumomiru server in dev without CORS fuss.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
