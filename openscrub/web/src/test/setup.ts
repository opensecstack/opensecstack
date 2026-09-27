import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// @testing-library/react's automatic cleanup registers itself against the
// test framework's global afterEach, which vite.config.ts's test.globals:
// false disables -- so it never runs, and every test's rendered DOM
// accumulates across the rest of the file (surfaced by Button.test.tsx's
// second test seeing both its own button and the first test's).
afterEach(() => {
  cleanup();
});
