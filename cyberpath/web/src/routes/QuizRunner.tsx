import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { getQuiz, submitQuiz } from "@/api/quizzes";
import type { QuizResult } from "@/api/quizzes";
import { Button } from "@/components/Button";
import { ProgressBar } from "@/components/ProgressBar";
import { Spinner } from "@/components/Spinner";

export default function QuizRunner(): JSX.Element {
  const { quizId = "" } = useParams<{ quizId: string }>();
  const navigate = useNavigate();

  // answers keyed by question id; single-choice → string, multi-choice → string[]
  const [answers, setAnswers] = useState<Record<string, string | string[]>>({});
  const [currentIndex, setCurrentIndex] = useState(0);
  const [result, setResult] = useState<QuizResult | null>(null);

  const { data: quiz, isLoading, isError } = useQuery({
    queryKey: ["quiz", quizId],
    queryFn: () => getQuiz(quizId),
    enabled: quizId.length > 0,
  });

  const submit = useMutation({
    mutationFn: () => submitQuiz(quizId, answers),
    onSuccess: (data) => {
      setResult(data);
    },
  });

  function handleReset(): void {
    setAnswers({});
    setCurrentIndex(0);
    setResult(null);
    submit.reset();
  }

  if (isLoading) {
    return (
      <div className="flex justify-center p-10">
        <Spinner />
      </div>
    );
  }

  if (isError || !quiz) {
    return (
      <div className="space-y-2">
        <p className="text-red-600">Failed to load quiz. Please try again.</p>
        <Button variant="secondary" onClick={() => navigate(-1)}>
          Go Back
        </Button>
      </div>
    );
  }

  // Result screen
  if (result) {
    const scorePct = Math.round(result.score);
    return (
      <section className="mx-auto max-w-lg space-y-6">
        <h1 className="text-2xl font-bold">{quiz.title}</h1>

        <div
          className={`rounded-md border p-6 text-center ${
            result.passed
              ? "border-emerald-300 bg-emerald-50"
              : "border-red-300 bg-red-50"
          }`}
        >
          <p className="text-3xl font-bold">
            {result.passed ? "Passed!" : "Failed"}
          </p>
          <p className="mt-1 text-slate-600">
            {result.correct_count} / {result.total_count} correct
          </p>
        </div>

        <ProgressBar
          value={scorePct}
          max={100}
          label={`Score: ${scorePct}% (passing: ${quiz.passing_score}%)`}
        />

        <div className="flex flex-wrap gap-3">
          <Button onClick={handleReset}>Try Again</Button>
          <Link to="/tracks">
            <Button variant="secondary">Back to Tracks</Button>
          </Link>
        </div>
      </section>
    );
  }

  const question = quiz.questions[currentIndex];
  const isLast = currentIndex === quiz.questions.length - 1;
  const progressValue = currentIndex + 1;
  const progressMax = quiz.questions.length;

  function handleSingleChange(key: string): void {
    setAnswers((prev) => ({ ...prev, [question.id]: key }));
  }

  function handleMultiChange(key: string, checked: boolean): void {
    setAnswers((prev) => {
      const existing = (prev[question.id] as string[] | undefined) ?? [];
      const next = checked
        ? [...existing, key]
        : existing.filter((k) => k !== key);
      return { ...prev, [question.id]: next };
    });
  }

  const currentAnswer = answers[question.id];
  const hasAnswer =
    question.type === "single"
      ? typeof currentAnswer === "string" && currentAnswer.length > 0
      : Array.isArray(currentAnswer) && currentAnswer.length > 0;

  return (
    <section className="mx-auto max-w-lg space-y-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-bold">{quiz.title}</h1>
        <p className="text-sm text-slate-500">
          Question {progressValue} of {progressMax}
        </p>
        <ProgressBar value={progressValue} max={progressMax} />
      </header>

      <div className="rounded-md border border-slate-200 bg-white p-5 shadow-sm">
        <p className="mb-4 font-medium text-slate-800">{question.text}</p>

        {question.type === "single" && (
          <ul className="space-y-2">
            {question.options.map((opt) => (
              <li key={opt.key}>
                <label className="flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 hover:bg-slate-50">
                  <input
                    type="radio"
                    name={question.id}
                    value={opt.key}
                    checked={currentAnswer === opt.key}
                    onChange={() => handleSingleChange(opt.key)}
                    className="accent-brand"
                  />
                  <span className="text-sm text-slate-700">{opt.text}</span>
                </label>
              </li>
            ))}
          </ul>
        )}

        {question.type === "multi" && (
          <ul className="space-y-2">
            {question.options.map((opt) => {
              const checked =
                Array.isArray(currentAnswer) && currentAnswer.includes(opt.key);
              return (
                <li key={opt.key}>
                  <label className="flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 hover:bg-slate-50">
                    <input
                      type="checkbox"
                      value={opt.key}
                      checked={checked}
                      onChange={(e) => handleMultiChange(opt.key, e.target.checked)}
                      className="accent-brand"
                    />
                    <span className="text-sm text-slate-700">{opt.text}</span>
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="flex justify-between">
        <Button
          variant="secondary"
          onClick={() => setCurrentIndex((i) => Math.max(0, i - 1))}
          disabled={currentIndex === 0}
        >
          Back
        </Button>

        {isLast ? (
          <Button
            onClick={() => submit.mutate()}
            disabled={!hasAnswer || submit.isPending}
          >
            {submit.isPending ? <Spinner /> : "Submit"}
          </Button>
        ) : (
          <Button
            onClick={() => setCurrentIndex((i) => i + 1)}
            disabled={!hasAnswer}
          >
            Next
          </Button>
        )}
      </div>

      {submit.isError && (
        <p className="text-sm text-red-600">
          Submission failed. Please try again.
        </p>
      )}
    </section>
  );
}
