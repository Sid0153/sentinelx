import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    // In development the browser talks to Vite, which forwards /api to the backend
    // (default: the Docker Compose backend on 127.0.0.1:8001).
    proxy: {
      "/api": {
        target: process.env.VITE_PROXY_TARGET ?? "http://127.0.0.1:8001",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.{ts,tsx}"],
    // Tests render the whole app; with coverage on a loaded machine one can exceed the 5 s
    // default (measured in Phase 14: only timeouts, no assertion failures). The whole suite
    // takes about 3 s on an idle machine, so 20 s only absorbs slow runners.
    testTimeout: 20_000,
    // `npm run test:coverage` (CI): a floor, like the backend's 90 %, not the goal.
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/main.tsx", "src/vite-env.d.ts"],
      reporter: ["text-summary"],
      thresholds: { lines: 90, statements: 89, functions: 85, branches: 78 },
    },
  },
});
