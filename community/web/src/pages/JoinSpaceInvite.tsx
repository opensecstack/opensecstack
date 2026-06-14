import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { joinByInvite } from "@/api/spaces";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";

export default function JoinSpaceInvite() {
  const { code } = useParams<{ code: string }>();
  const { token } = useAuthStore();
  const navigate = useNavigate();
  const [error, setError] = useState("");

  useEffect(() => {
    if (!token) return;
    joinByInvite(code!)
      .then(({ space_slug }) => navigate(`/spaces/${space_slug}`, { replace: true }))
      .catch(() => setError("This invite link is invalid or has expired."));
  }, [code, token, navigate]);

  if (!token) {
    return (
      <div className="text-center py-20">
        <p className="text-gray-600 dark:text-gray-400 mb-4">You need to log in to join this space.</p>
        <Link
          to={`/login?redirect=/spaces/invite/${code}`}
          className="px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
        >
          Log in to join
        </Link>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-20">
        <p className="text-red-500 mb-4">{error}</p>
        <Link to="/spaces" className="text-brand hover:underline text-sm">← Browse Spaces</Link>
      </div>
    );
  }

  return <Spinner />;
}
