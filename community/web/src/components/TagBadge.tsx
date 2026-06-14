import { Link } from "react-router-dom";

interface Props {
  name: string;
  href?: boolean;
}

export default function TagBadge({ name, href = true }: Props) {
  const slug = name.toLowerCase().replace(/\s+/g, "-");
  const cls = "text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-brand/10 hover:text-brand transition-colors";
  if (href) return <Link to={`/tags/${slug}`} className={cls}>#{name}</Link>;
  return <span className={cls}>#{name}</span>;
}
