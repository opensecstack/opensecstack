import { jsx as _jsx } from "react/jsx-runtime";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import VerdictBadge from "./VerdictBadge";
describe("VerdictBadge", () => {
    it("renders the verdict text", () => {
        render(_jsx(VerdictBadge, { verdict: "CLEAN" }));
        expect(screen.getByText("CLEAN")).toBeInTheDocument();
    });
    it("applies the BLOCKED variant styles", () => {
        render(_jsx(VerdictBadge, { verdict: "BLOCKED" }));
        const badge = screen.getByText("BLOCKED");
        expect(badge.className).toMatch(/rose/);
    });
    it("applies the SUSPICIOUS variant styles", () => {
        render(_jsx(VerdictBadge, { verdict: "SUSPICIOUS" }));
        const badge = screen.getByText("SUSPICIOUS");
        expect(badge.className).toMatch(/amber/);
    });
});
