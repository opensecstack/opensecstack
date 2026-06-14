import type { Locale } from "@/state/locale";

const intlLocale = (l: Locale): string => (l === "sq" ? "sq-AL" : "en-GB");

export function formatDate(value: string | Date, locale: Locale): string {
  const d = typeof value === "string" ? new Date(value) : value;
  return new Intl.DateTimeFormat(intlLocale(locale), {
    year: "numeric",
    month: "short",
    day: "2-digit",
  }).format(d);
}

export function formatDateTime(value: string | Date, locale: Locale): string {
  const d = typeof value === "string" ? new Date(value) : value;
  return new Intl.DateTimeFormat(intlLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

export function formatDuration(minutes: number, locale: Locale): string {
  if (minutes < 60) {
    return locale === "sq" ? `${minutes} min` : `${minutes} min`;
  }
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  const hLabel = locale === "sq" ? "orë" : "h";
  if (rest === 0) return `${hours} ${hLabel}`;
  return `${hours} ${hLabel} ${rest} min`;
}
