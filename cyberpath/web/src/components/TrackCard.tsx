import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { Track } from "@/api/tracks";
import { Badge } from "./Badge";
import { useLocale } from "@/state/locale";
import { formatDuration } from "@/lib/format";

interface TrackCardProps {
  track: Track;
}

export function TrackCard({ track }: TrackCardProps): JSX.Element {
  const { t } = useTranslation(["tracks", "common"]);
  const { locale } = useLocale();

  // Localised title fall-back: API supplies a single `title` already negotiated
  // via Accept-Language. The slug-based override below lets the bilingual demo
  // (quick-start.md) flip strings without re-fetching.
  const localisedTitle = t(`tracks:titles.${track.slug}`, { defaultValue: track.title });

  return (
    <Link
      to={`/tracks/${track.slug}`}
      className="block rounded-lg border border-slate-200 bg-white p-4 shadow-sm transition hover:border-brand hover:shadow"
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-slate-900">{localisedTitle}</h3>
        {track.cert_offered && <Badge tone="success">{t("common:labels.certification")}</Badge>}
      </div>
      <p className="mb-3 text-sm text-slate-600">
        {t("common:labels.audience")}: <span className="font-medium">{track.audience}</span>
      </p>
      <div className="flex flex-wrap gap-2 text-xs">
        <Badge tone="info">
          {t("common:labels.duration")}: {formatDuration(track.estimated_minutes, locale)}
        </Badge>
        {track.lab_required && <Badge tone="warning">{t("common:labels.lab")}</Badge>}
        {track.nis2_measures.map((m) => (
          <Badge key={m} tone="neutral">
            {m}
          </Badge>
        ))}
      </div>
    </Link>
  );
}
