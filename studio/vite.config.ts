import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Tauri spawns Vite as its frontend. The defaults below are recommended
// by the Tauri team — see https://v2.tauri.app/start/frontend/vite/
export default defineConfig({
  plugins: [solid()],

  // Vite options tailored for Tauri
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    // Tauri uses the dev server in tauri.conf.json's build.devUrl
  },

  // Don't bundle process.env into the frontend — Studio is offline-only,
  // no env-var leakage paths.
  envPrefix: ["VITE_", "TAURI_"],

  build: {
    target: "esnext",
    minify: "esbuild",
    sourcemap: false, // never ship sourcemaps in a security tool
  },
});
