import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { onSessionExpired, tokenStore } from "../src/services/http";

// The first test in a file also pays for compiling the app; give async queries enough time on
// a cold CI runner.
configure({ asyncUtilTimeout: 5000 });

// Vitest globals are off, so Testing Library cannot register its own cleanup.
afterEach(() => {
  cleanup();
  tokenStore.set(null);
  onSessionExpired(null);
  vi.unstubAllGlobals();
});
