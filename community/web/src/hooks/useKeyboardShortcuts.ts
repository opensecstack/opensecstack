import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export function useGlobalKeyboardShortcuts() {
  const navigate = useNavigate();

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Don't fire when typing in an input, textarea, or contenteditable
      const tag = (e.target as HTMLElement).tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (e.target as HTMLElement).isContentEditable) return;
      // Don't fire with modifier keys (except for specific combos)
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      switch (e.key) {
        case "n":
          e.preventDefault();
          navigate("/new");
          break;
        case "/":
          e.preventDefault();
          // Focus the search input in the header if it exists
          const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]');
          if (searchInput) searchInput.focus();
          else navigate("/search");
          break;
        case "?":
          e.preventDefault();
          window.dispatchEvent(new CustomEvent("show-shortcuts-help"));
          break;
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [navigate]);
}
