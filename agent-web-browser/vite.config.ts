import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "python/src/agent_web_browser/static",
    emptyOutDir: true,
  },
});
