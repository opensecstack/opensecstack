import { NavLink } from "react-router-dom";
import clsx from "clsx";
import type { TrackLessonSummary } from "@/api/tracks";

interface LessonNavProps {
  lessons: TrackLessonSummary[];
  currentLessonId?: string;
}

export function LessonNav({ lessons, currentLessonId }: LessonNavProps): JSX.Element {
  return (
    <nav aria-label="Lessons" className="space-y-1">
      {lessons.map((l) => (
        <NavLink
          key={l.id}
          to={`/lessons/${l.id}`}
          className={({ isActive }) =>
            clsx(
              "block rounded-md px-3 py-2 text-sm transition",
              isActive || l.id === currentLessonId
                ? "bg-brand text-white"
                : "text-slate-700 hover:bg-slate-100",
            )
          }
        >
          <span className="mr-2 text-xs opacity-70">{l.order}.</span>
          {l.title_en}
        </NavLink>
      ))}
    </nav>
  );
}
