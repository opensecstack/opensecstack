import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="text-center py-24">
      <p className="text-6xl font-bold text-gray-200 mb-4">404</p>
      <p className="text-gray-500 mb-6">Page not found.</p>
      <Link to="/" className="text-brand hover:underline">Go home</Link>
    </div>
  );
}
