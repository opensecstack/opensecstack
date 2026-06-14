// Vitest global setup — runs once before any test file.
// Initialises i18n so components that call useTranslation() don't throw.
import "@testing-library/jest-dom";
import i18n from "@/i18n/index";

// Ensure i18n is initialised synchronously before assertions run.
// The module already calls i18n.init(); importing it here guarantees that
// the side-effect fires before the first test file is evaluated.
void i18n;
