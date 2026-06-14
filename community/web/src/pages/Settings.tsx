import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getUser, updateProfile } from "@/api/users";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";
import ApiKeysPanel from "@/components/ApiKeysPanel";
import ProfileSection from "@/components/settings/ProfileSection";
import PasswordSection from "@/components/settings/PasswordSection";
import TOTPSection from "@/components/settings/TOTPSection";
import NotificationsSection from "@/components/settings/NotificationsSection";
import ActiveSessionsSection from "@/components/settings/ActiveSessionsSection";
import DangerZoneSection from "@/components/settings/DangerZoneSection";

export default function Settings() {
  const { token, username } = useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!token) {
      navigate("/login", { replace: true });
    }
  }, [token, navigate]);

  const { data: user, isLoading } = useQuery({
    queryKey: ["user", username],
    queryFn: () => getUser(username!),
    enabled: !!username,
  });

  const [form, setForm] = useState({
    display_name: "",
    bio: "",
    location: "",
    website: "",
    github_username: "",
    twitter_username: "",
    certifications: "",
    specialization: "",
    avatar_url: "" as string,
  });
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarUploading, setAvatarUploading] = useState(false);
  const [avatarUploadError, setAvatarUploadError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (user) {
      setForm({
        display_name: user.display_name ?? "",
        bio: user.bio ?? "",
        location: user.location ?? "",
        website: user.website ?? "",
        github_username: user.github_username ?? "",
        twitter_username: user.twitter_username ?? "",
        certifications: user.certifications ?? "",
        specialization: user.specialization ?? "",
        avatar_url: user.avatar_url ?? "",
      });
    }
  }, [user]);

  function handleChange(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  }

  function setFormField(key: keyof typeof form, value: string) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await updateProfile({
        ...form,
        avatar_url: form.avatar_url || null,
      });
      await queryClient.invalidateQueries({ queryKey: ["user", username] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save changes.");
    } finally {
      setSaving(false);
    }
  }

  if (!token) return null;
  if (isLoading) return <Spinner />;

  return (
    <div className="max-w-2xl mx-auto py-8 px-4">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Settings</h1>

      <ProfileSection
        form={form}
        onChange={handleChange}
        onSubmit={handleSubmit}
        saving={saving}
        saved={saved}
        error={error}
        avatarPreview={avatarPreview}
        setAvatarPreview={setAvatarPreview}
        avatarUploading={avatarUploading}
        setAvatarUploading={setAvatarUploading}
        avatarUploadError={avatarUploadError}
        setAvatarUploadError={setAvatarUploadError}
        setFormField={setFormField}
      />

      <NotificationsSection />

      <TOTPSection />

      <PasswordSection />

      <ActiveSessionsSection />

      {/* API Keys */}
      <div className="mt-10 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-1">API Keys</h2>
        <ApiKeysPanel />
      </div>

      <DangerZoneSection />
    </div>
  );
}
