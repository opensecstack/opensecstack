import clsx from "clsx";

interface ProgressBarProps {
  value: number;
  max?: number;
  className?: string;
  label?: string;
}

export function ProgressBar({
  value,
  max = 100,
  className,
  label,
}: ProgressBarProps): JSX.Element {
  const pct = Math.max(0, Math.min(100, max === 0 ? 0 : (value / max) * 100));
  return (
    <div className={clsx("w-full", className)}>
      {label !== undefined && (
        <div className="mb-1 flex justify-between text-xs text-slate-600">
          <span>{label}</span>
          <span>{Math.round(pct)}%</span>
        </div>
      )}
      <div
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        className="h-2 w-full overflow-hidden rounded-full bg-slate-200"
      >
        {/* Tailwind cannot express arbitrary runtime widths; the inline
            width here is the documented exception used across the codebase. */}
        <div
          className="h-full origin-left bg-brand transition-transform"
          style={{ transform: `scaleX(${pct / 100})`, width: "100%" }}
        />
      </div>
    </div>
  );
}
