import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { Layout } from "@/components/Layout";

describe("Layout", () => {
  it("renders the locale switcher", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter initialEntries={["/"]}>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<div>home</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </I18nextProvider>,
    );
    const select = screen.getByLabelText(/Gjuha|Language/i) as HTMLSelectElement;
    expect(select).toBeInTheDocument();
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toContain("sq");
    expect(options).toContain("en");
  });
});
