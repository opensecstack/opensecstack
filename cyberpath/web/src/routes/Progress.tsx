import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { getProgress } from "@/api/users";
import { useAuth } from "@/state/auth";
import { Spinner } from "@/components/Spinner";
import { ProgressBar } from "@/components/ProgressBar";

export default function Progress(): JSX.Element {
  const { t } = useTranslation(["common", "tracks"]);
  const { user } = useAuth();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["progress", user?.id],
    queryFn: () => getProgress(user!.id),
    enabled: !!user,
  });

  if (!user) return <p>{t("common:errors.unauthorized")}</p>;
  if (isLoading) return <Spinner />;
  if (isError || !data) return <p className="text-red-600">{t("common:errors.generic")}</p>;

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">{t("common:nav.progress")}</h1>
      {data.tracks.length === 0 && <p className="text-slate-600">{t("common:labels.empty")}</p>}
      <ul className="space-y-3">
        {data.tracks.map((tr) => (
          <li key={tr.track_id} className="rounded-md border border-slate-200 bg-white p-3">
            <p className="mb-2 font-medium">
              {t(`tracks:titles.${tr.track_slug}`, { defaultValue: tr.track_slug })}
            </p>
            <ProgressBar value={tr.lessons_done} max={tr.lessons_total} />
            <p className="mt-1 text-xs text-slate-500">
              {tr.lessons_done}/{tr.lessons_total} · quiz avg: {(tr.quiz_avg * 100).toFixed(0)}%
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
