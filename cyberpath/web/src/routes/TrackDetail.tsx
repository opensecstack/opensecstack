import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { getTrack, getTrackModules } from "@/api/tracks";
import { completeLesson } from "@/api/lessons";
import { getProgress } from "@/api/users";
import { Spinner } from "@/components/Spinner";
import { Button } from "@/components/Button";
import { Badge } from "@/components/Badge";
import { ProgressBar } from "@/components/ProgressBar";
import { useLocale } from "@/state/locale";
import { useAuth } from "@/state/auth";

export default function TrackDetail(): JSX.Element {
  const { id = "" } = useParams<{ id: string }>();
  const { t } = useTranslation(["tracks", "common"]);
  const { locale } = useLocale();
  const { user } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const trackQuery = useQuery({
    queryKey: ["track", id],
    queryFn: () => getTrack(id),
    enabled: id.length > 0,
  });
  const modulesQuery = useQuery({
    queryKey: ["track", id, "modules"],
    queryFn: () => getTrackModules(id),
    enabled: id.length > 0,
  });
  const progressQuery = useQuery({
    queryKey: ["progress", user?.id],
    queryFn: () => getProgress(user!.id),
    enabled: !!user,
  });

  const completeMutation = useMutation({
    mutationFn: (lessonId: string) =>
      completeLesson(lessonId, { time_spent_seconds: 0 }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["progress"] });
    },
  });

  if (trackQuery.isLoading) {
    return (
      <div className="flex justify-center p-10">
        <Spinner />
      </div>
    );
  }
  if (trackQuery.isError || !trackQuery.data) {
    return (
      <div className="space-y-2">
        <p className="text-red-600">{t("common:errors.generic")}</p>
        <Button variant="secondary" onClick={() => void trackQuery.refetch()}>
          {t("common:buttons.retry")}
        </Button>
      </div>
    );
  }

  const track = trackQuery.data;
  const title = locale === "sq" ? track.title_sq : track.title_en;
  const description = locale === "sq" ? track.description_sq : track.description_en;

  const trackProgress = progressQuery.data?.tracks.find((tr) => tr.track_id === track.id);
  const isStarted = !!trackProgress;
  const isComplete = !!trackProgress?.completed_at;
  const lessonsTotal = trackProgress?.lessons_total ?? 0;
  const lessonsDone = trackProgress?.lessons_done ?? 0;

  return (
    <section className="space-y-6">
      <header className="space-y-3">
        <h1 className="text-2xl font-bold">{title}</h1>
        <p className="text-slate-600">{description}</p>

        <div className="flex flex-wrap items-center gap-2">
          {track.cert_offered && (
            <Badge tone="success">{t("common:labels.certification")}</Badge>
          )}
          <Badge tone="neutral">v{track.track_version}</Badge>
          {isComplete && <Badge tone="success">{t("common:labels.completed")}</Badge>}
          {isStarted && !isComplete && (
            <Badge tone="info">{t("common:labels.inProgress")}</Badge>
          )}
        </div>

        {isStarted && lessonsTotal > 0 && (
          <ProgressBar
            value={lessonsDone}
            max={lessonsTotal}
            label={t("tracks:progress.lessonsDone")}
          />
        )}

        <div>
          {!isStarted && (
            <Button
              onClick={() => {
                const first = modulesQuery.data?.modules[0]?.lessons[0];
                if (first) navigate(`/lessons/${first.id}`);
              }}
              disabled={!modulesQuery.data?.modules.length}
            >
              {t("tracks:detail.startTrack")}
            </Button>
          )}
          {isStarted && !isComplete && (
            <Button
              onClick={() => {
                const first = modulesQuery.data?.modules[0]?.lessons[0];
                if (first) navigate(`/lessons/${first.id}`);
              }}
            >
              {t("tracks:detail.continueTrack")}
            </Button>
          )}
        </div>
      </header>

      <section>
        <h2 className="mb-2 text-lg font-semibold">{t("tracks:detail.modules")}</h2>
        {modulesQuery.isLoading && <Spinner />}
        {modulesQuery.data && modulesQuery.data.modules.length === 0 && (
          <p className="text-slate-600">{t("tracks:detail.noModules")}</p>
        )}
        <ul className="space-y-3">
          {modulesQuery.data?.modules.map((m) => (
            <li key={m.id} className="rounded-md border border-slate-200 bg-white p-3">
              <p className="mb-2 font-medium">
                {m.order}. {locale === "sq" && m.title_sq ? m.title_sq : m.title_en}
              </p>
              <ul className="space-y-1 text-sm">
                {m.lessons.map((l) => (
                  <li
                    key={l.id}
                    className="flex items-center justify-between rounded px-2 py-1 hover:bg-slate-50"
                  >
                    <Link to={`/lessons/${l.id}`} className="text-slate-700 hover:text-brand">
                      {l.order}. {locale === "sq" && l.title_sq ? l.title_sq : l.title_en}
                    </Link>
                    <div className="flex items-center gap-2">
                      {l.has_lab && <Badge tone="warning">{t("common:labels.lab")}</Badge>}
                      {user && (
                        <Button
                          variant="ghost"
                          onClick={() => completeMutation.mutate(l.id)}
                          disabled={completeMutation.isPending}
                          className="text-xs"
                        >
                          {t("common:buttons.markComplete")}
                        </Button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}
