import { defineConfig } from "vite";

/**
 * Tauri's dev flow expects the frontend on a fixed port and does *not* cope with
 * Vite silently choosing another one, hence `strictPort`. The build target is
 * Chromium 110+ because the only runtime is WebView2, which is evergreen -- there
 * is no reason to down-level for older engines, and `emptyOutDir` keeps stale
 * bundles from being packaged into the binary.
 */
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: {
      // Rust sources are watched by cargo, not Vite.
      ignored: ["**/src-tauri/**", "**/target/**"],
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "chrome110",
    minify: "esbuild",
    // No sourcemaps in the shipped bundle: they would make the renderer's internals
    // (and therefore the UI's assumptions about vault state) easier to reverse.
    sourcemap: false,
    reportCompressedSize: false,
  },
});
