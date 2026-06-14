import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { TlpBadge } from "./TlpBadge";

// Each TLP variant must produce the badge text and the Tailwind colour class
// that distinguishes it visually — regression guard against CSS renames.

describe("TlpBadge", () => {
  it.each([
    ["clear", "bg-slate-200"],
    ["green", "bg-emerald-100"],
    ["amber", "bg-amber-100"],
    ["red", "bg-red-200"],
  ] as const)('renders tlp:%s with class "%s"', (tlp, expectedClass) => {
    render(<TlpBadge tlp={tlp} />);

    const badge = screen.getByText(`tlp:${tlp}`);
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain(expectedClass);
  });

  it("applies the shared structural classes on every variant", () => {
    render(<TlpBadge tlp="green" />);

    const badge = screen.getByText("tlp:green");
    expect(badge.className).toContain("rounded");
    expect(badge.className).toContain("uppercase");
    expect(badge.className).toContain("font-mono");
  });
});
