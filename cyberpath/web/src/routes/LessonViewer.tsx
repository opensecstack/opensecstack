import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { getLesson } from "@/api/lessons";
import { Spinner } from "@/components/Spinner";
import { useLocale } from "@/state/locale";

export default function LessonViewer(): JSX.Element {
  const { id = "" } = useParams<{ id: string }>();
  const { t } = useTranslation(["common", "tracks"]);
  const { locale } = useLocale();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["lesson", id],
    queryFn: () => getLesson(id),
    enabled: id.length > 0,
  });

  if (isLoading) return <Spinner />;
  if (isError || !data) return <p className="text-red-600">{t("common:errors.generic")}</p>;

  const title = locale === "sq" ? data.title_sq : data.title_en;
  const body = locale === "sq" ? data.body_sq : data.body_en;

  return (
    <article className="space-y-4">
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="text-xs text-slate-500">
        {t("tracks:placeholder")} — content_version_id: {data.content_version_id}
      </p>
      <pre className="whitespace-pre-wrap rounded-md bg-white p-4 font-sans text-sm text-slate-800">
        {body}
      </pre>
    </article>
  );
}
