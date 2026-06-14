import type { DayCount } from "@/api/analytics";

interface Props {
  days: DayCount[];
  totalViews: number;
}

const SVG_WIDTH = 600;
const SVG_HEIGHT = 120;
const BAR_AREA_HEIGHT = 80;
const X_LABEL_Y = 112;
const BAR_GAP = 2;

// Indices of days to show x-axis labels for (0-based): 1st, 8th, 15th, 22nd, 29th
const LABEL_INDICES = new Set([0, 7, 14, 21, 28]);

export default function AnalyticsChart({ days, totalViews }: Props) {
  const allZero = days.every((d) => d.count === 0);

  return (
    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
      <div className="mb-2">
        <span className="font-bold text-sm text-gray-800">Total views: {totalViews.toLocaleString()}</span>
        <span className="ml-2 text-xs text-gray-400">Last 30 days</span>
      </div>

      {allZero ? (
        <p className="text-sm text-gray-400 py-4 text-center">No views yet in the last 30 days</p>
      ) : (
        <svg
          viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
          width="100%"
          aria-label="Daily views chart"
          role="img"
        >
          <Bars days={days} />
        </svg>
      )}
    </div>
  );
}

function Bars({ days }: { days: DayCount[] }) {
  const n = days.length;
  const maxCount = Math.max(...days.map((d) => d.count), 1);
  const totalWidth = SVG_WIDTH;
  const barWidth = (totalWidth - BAR_GAP * (n - 1)) / n;

  return (
    <>
      {days.map((d, i) => {
        const barHeight = Math.max((d.count / maxCount) * BAR_AREA_HEIGHT, d.count > 0 ? 2 : 0);
        const x = i * (barWidth + BAR_GAP);
        const y = BAR_AREA_HEIGHT - barHeight;
        // Use lighter color for bars that are much lower than the max
        const isLow = d.count < maxCount * 0.25;
        const fill = d.count === 0 ? "#e5e7eb" : isLow ? "#a5b4fc" : "#6366f1";
        const showLabel = LABEL_INDICES.has(i);

        return (
          <g key={d.date}>
            <rect
              x={x}
              y={y}
              width={barWidth}
              height={Math.max(barHeight, 1)}
              fill={fill}
              rx={2}
            >
              <title>{d.date}: {d.count} view{d.count !== 1 ? "s" : ""}</title>
            </rect>
            {showLabel && (
              <text
                x={x + barWidth / 2}
                y={X_LABEL_Y}
                textAnchor="middle"
                fontSize={9}
                fill="#9ca3af"
              >
                {formatShortDate(d.date)}
              </text>
            )}
          </g>
        );
      })}
    </>
  );
}

function formatShortDate(dateStr: string): string {
  const [, month, day] = dateStr.split("-");
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${months[parseInt(month, 10) - 1]} ${parseInt(day, 10)}`;
}
