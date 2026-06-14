import { useRef } from "react";
import { uploadImage } from "@/api/upload";

interface ProfileForm {
  display_name: string;
  bio: string;
  location: string;
  website: string;
  github_username: string;
  twitter_username: string;
  certifications: string;
  specialization: string;
  avatar_url: string;
}

interface ProfileSectionProps {
  form: ProfileForm;
  onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
  onSubmit: (e: React.FormEvent) => void;
  saving: boolean;
  saved: boolean;
  error: string | null;
  avatarPreview: string | null;
  setAvatarPreview: (url: string | null) => void;
  avatarUploading: boolean;
  setAvatarUploading: (v: boolean) => void;
  avatarUploadError: string | null;
  setAvatarUploadError: (msg: string | null) => void;
  setFormField: (key: keyof ProfileForm, value: string) => void;
}

export default function ProfileSection({
  form,
  onChange,
  onSubmit,
  saving,
  saved,
  error,
  avatarPreview,
  setAvatarPreview,
  avatarUploading,
  setAvatarUploading,
  avatarUploadError,
  setAvatarUploadError,
  setFormField,
}: ProfileSectionProps) {
  const avatarInputRef = useRef<HTMLInputElement>(null);

  async function handleAvatarFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const localUrl = URL.createObjectURL(file);
    setAvatarPreview(localUrl);
    setAvatarUploading(true);
    setAvatarUploadError(null);
    try {
      const url = await uploadImage(file);
      setFormField("avatar_url", url);
    } catch (err: unknown) {
      setAvatarUploadError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setAvatarUploading(false);
    }
  }

  const inputCls =
    "w-full border border-gray-300 dark:border-gray-700 rounded-md px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/50";

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      {/* Avatar */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-4">Avatar</h2>
        <div className="flex items-start gap-5">
          <button
            type="button"
            onClick={() => avatarInputRef.current?.click()}
            className="relative shrink-0 w-20 h-20 rounded-full overflow-hidden border-2 border-gray-200 hover:border-brand focus:outline-none focus:ring-2 focus:ring-brand/50 transition-colors"
            title="Change avatar"
          >
            {(avatarPreview || form.avatar_url) ? (
              <img
                src={avatarPreview ?? form.avatar_url}
                alt="Avatar preview"
                className="w-full h-full object-cover"
              />
            ) : (
              <span className="flex items-center justify-center w-full h-full bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-500 text-xs">
                No image
              </span>
            )}
            <span className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 hover:opacity-100 transition-opacity text-white text-xs font-medium">
              Change
            </span>
          </button>
          <div className="flex-1 space-y-2">
            <input
              ref={avatarInputRef}
              type="file"
              accept="image/jpeg,image/png,image/gif,image/webp"
              className="hidden"
              onChange={handleAvatarFile}
            />
            {avatarUploading && (
              <p className="text-xs text-gray-400">Uploading…</p>
            )}
            {avatarUploadError && (
              <p className="text-xs text-red-500">{avatarUploadError}</p>
            )}
            <div>
              <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1" htmlFor="avatar_url">
                Or paste URL
              </label>
              <input
                id="avatar_url"
                name="avatar_url"
                type="url"
                placeholder="https://example.com/avatar.png"
                value={form.avatar_url}
                onChange={onChange}
                className={inputCls}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Basic information */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-4">Basic information</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="display_name">
              Display name
            </label>
            <input id="display_name" name="display_name" type="text" value={form.display_name} onChange={onChange} className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="bio">
              Bio
            </label>
            <textarea id="bio" name="bio" rows={3} value={form.bio} onChange={onChange} className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="location">
              Location
            </label>
            <input id="location" name="location" type="text" value={form.location} onChange={onChange} className={inputCls} />
          </div>
        </div>
      </div>

      {/* Links */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-4">Links</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="website">
              Website
            </label>
            <input id="website" name="website" type="url" placeholder="https://your-blog.com" value={form.website} onChange={onChange} className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="github_username">
              GitHub username
            </label>
            <input id="github_username" name="github_username" type="text" placeholder="username" value={form.github_username} onChange={onChange} className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="twitter_username">
              Twitter username
            </label>
            <input id="twitter_username" name="twitter_username" type="text" placeholder="username" value={form.twitter_username} onChange={onChange} className={inputCls} />
          </div>
        </div>
      </div>

      {/* Security & Skills */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-4">Security &amp; Skills</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="certifications">
              Certifications
            </label>
            <input id="certifications" name="certifications" type="text" placeholder="OSCP, CEH, CISSP" value={form.certifications} onChange={onChange} className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="specialization">
              Specialization
            </label>
            <input id="specialization" name="specialization" type="text" placeholder="malware analysis, DFIR" value={form.specialization} onChange={onChange} className={inputCls} />
          </div>
        </div>
      </div>

      {error && <p className="text-sm text-red-500">{error}</p>}

      <div className="flex items-center gap-4">
        <button
          type="submit"
          disabled={saving}
          className="bg-brand text-white px-5 py-2 rounded-md text-sm font-medium hover:opacity-90 disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save changes"}
        </button>
        {saved && <span className="text-sm text-green-600">Saved ✓</span>}
      </div>
    </form>
  );
}
