import { useEffect, useRef, useState } from "react";
import { X } from "lucide-react";

interface ShortcutItem {
  keys: string[];
  description: string;
}

interface ShortcutSection {
  section: string;
  items: ShortcutItem[];
}

const shortcuts: ShortcutSection[] = [
  {
    section: "Navigation",
    items: [
      { keys: ["N"], description: "New post" },
      { keys: ["/"], description: "Focus search" },
    ],
  },
  {
    section: "General",
    items: [
      { keys: ["?"], description: "Show this help" },
      { keys: ["Esc"], description: "Close modal / cancel" },
    ],
  },
];

function KeyBadge({ label }: { label: string }) {
  return (
    <kbd className="inline-flex items-center justify-center bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded px-1.5 py-0.5 text-xs font-mono text-gray-700 dark:text-gray-200 leading-none">
      {label}
    </kbd>
  );
}

export default function KeyboardShortcutsModal() {
  const [open, setOpen] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  // Listen for the custom event dispatched by the keyboard shortcuts hook
  useEffect(() => {
    function handleShow() {
      setOpen(true);
    }
    window.addEventListener("show-shortcuts-help", handleShow);
    return () => window.removeEventListener("show-shortcuts-help", handleShow);
  }, []);

  // Close on Escape; trap focus inside the modal
  useEffect(() => {
    if (!open) return;

    // Move focus to the close button when the modal opens
    closeButtonRef.current?.focus();

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        setOpen(false);
        return;
      }

      // Basic focus trap: keep Tab / Shift+Tab inside the dialog
      if (e.key === "Tab" && dialogRef.current) {
        const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last?.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first?.focus();
          }
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open]);

  if (!open) return null;

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="shortcuts-modal-title"
      onClick={(e) => {
        // Close when clicking the backdrop (not the card)
        if (e.target === e.currentTarget) setOpen(false);
      }}
    >
      {/* Modal card */}
      <div
        ref={dialogRef}
        className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100 dark:border-gray-800">
          <h2
            id="shortcuts-modal-title"
            className="text-base font-semibold text-gray-900 dark:text-gray-100 tracking-tight"
          >
            Keyboard Shortcuts
          </h2>
          <button
            ref={closeButtonRef}
            onClick={() => setOpen(false)}
            aria-label="Close keyboard shortcuts"
            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Shortcuts list */}
        <div className="px-6 py-4 space-y-5 max-h-[70vh] overflow-y-auto">
          {shortcuts.map((group) => (
            <div key={group.section}>
              <h3 className="text-[0.65rem] font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-500 mb-2">
                {group.section}
              </h3>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2">
                {group.items.map((item, i) => (
                  <li key={i} className="flex items-center justify-between gap-3">
                    <span className="text-sm text-gray-700 dark:text-gray-300">{item.description}</span>
                    <span className="flex items-center gap-1 shrink-0">
                      {item.keys.map((k, ki) => (
                        <KeyBadge key={ki} label={k} />
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Footer hint */}
        <div className="px-6 py-3 border-t border-gray-100 dark:border-gray-800 text-center">
          <p className="text-xs text-gray-400 dark:text-gray-600">
            Shortcuts do not fire while typing in an input field.
          </p>
        </div>
      </div>
    </div>
  );
}
