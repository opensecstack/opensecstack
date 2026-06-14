import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import VerdictBadge from "./VerdictBadge";

describe("VerdictBadge", () => {
  it("renders the verdict text", () => {
    render(<VerdictBadge verdict="CLEAN" />);
    expect(screen.getByText("CLEAN")).toBeInTheDocument();
  });

  it("applies the BLOCKED variant styles", () => {
    render(<VerdictBadge verdict="BLOCKED" />);
    const badge = screen.getByText("BLOCKED");
    expect(badge.className).toMatch(/rose/);
  });

  it("applies the SUSPICIOUS variant styles", () => {
    render(<VerdictBadge verdict="SUSPICIOUS" />);
    const badge = screen.getByText("SUSPICIOUS");
    expect(badge.className).toMatch(/amber/);
  });
});
