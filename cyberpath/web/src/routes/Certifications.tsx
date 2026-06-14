import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { getCertifications } from "@/api/users";
import { useAuth } from "@/state/auth";
import { useLocale } from "@/state/locale";
import { Spinner } from "@/components/Spinner";
import { Badge } from "@/components/Badge";
import { formatDate } from "@/lib/format";

export default function Certifications(): JSX.Element {
  const { t } = useTranslation(["common", "tracks"]);
  const { user } = useAuth();
  const { locale } = useLocale();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["certifications", user?.id],
    queryFn: () => getCertifications(user!.id),
    enabled: !!user,
  });

  if (!user) return <p>{t("common:errors.unauthorized")}</p>;
  if (isLoading) return <Spinner />;
  if (isError || !data) return <p className="text-red-600">{t("common:errors.generic")}</p>;

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">{t("common:nav.certifications")}</h1>
      {data.certifications.length === 0 && (
        <p className="text-slate-600">{t("common:labels.empty")}</p>
      )}
      <ul className="space-y-2">
        {data.certifications.map((c) => (
          <li
            key={c.id}
            className="flex items-center justify-between rounded-md border border-slate-200 bg-white p-3"
          >
            <div>
              <p className="font-medium">
                {t(`tracks:titles.${c.track_slug}`, { defaultValue: c.track_slug })}
              </p>
              <p className="text-xs text-slate-500">
                {formatDate(c.issued_at, locale)}
                {c.expires_at && ` — ${formatDate(c.expires_at, locale)}`}
              </p>
            </div>
            <Badge tone="success">v{c.track_version}</Badge>
          </li>
        ))}
      </ul>
    </section>
  );
}
