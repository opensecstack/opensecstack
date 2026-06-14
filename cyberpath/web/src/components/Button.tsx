import clsx from "clsx";
import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const variants: Record<Variant, string> = {
  primary: "bg-brand text-white hover:bg-blue-700 disabled:bg-slate-300",
  secondary: "bg-white border border-slate-300 text-slate-800 hover:bg-slate-100",
  ghost: "bg-transparent text-slate-700 hover:bg-slate-100",
};

export function Button({
  variant = "primary",
  className,
  type = "button",
  ...rest
}: ButtonProps): JSX.Element {
  return (
    <button
      type={type}
      className={clsx(
        "inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition",
        variants[variant],
        className,
      )}
      {...rest}
    />
  );
}
