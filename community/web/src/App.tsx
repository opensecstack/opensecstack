import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "@/components/Layout";
import Feed from "@/pages/Feed";
import FollowingFeed from "@/pages/FollowingFeed";
import TrendingFeed from "@/pages/TrendingFeed";
import PostDetail from "@/pages/PostDetail";
import NewPost from "@/pages/NewPost";
import EditPost from "@/pages/EditPost";
import MyPosts from "@/pages/MyPosts";
import Profile from "@/pages/Profile";
import TagFeed from "@/pages/TagFeed";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import ForgotPassword from "@/pages/ForgotPassword";
import ResetPassword from "@/pages/ResetPassword";
import VerifyEmail from "@/pages/VerifyEmail";
import NotFound from "@/pages/NotFound";
import Bookmarks from "@/pages/Bookmarks";
import SeriesDetail from "@/pages/SeriesDetail";
import MySeries from "@/pages/MySeries";
import NewSeries from "@/pages/NewSeries";
import AdminInvites from "@/pages/AdminInvites";
import AdminUsers from "@/pages/AdminUsers";
import AdminTags from "@/pages/AdminTags";
import PostRevisions from "@/pages/PostRevisions";
import AdminBroadcast from "@/pages/AdminBroadcast";
import AdminDeletions from "@/pages/AdminDeletions";
import AdminAudit from "@/pages/AdminAudit";
import AdminStats from "@/pages/AdminStats";
import ModQueue from "@/pages/ModQueue";
import Settings from "@/pages/Settings";
import Onboarding from "@/pages/Onboarding";
import Search from "@/pages/Search";
import ReadingHistory from "@/pages/ReadingHistory";
import ScheduledPosts from "@/pages/ScheduledPosts";
import UserDirectory from "@/pages/UserDirectory";
import Leaderboard from "@/pages/Leaderboard";
import OAuthCallback from "@/pages/OAuthCallback";
import Spaces from "@/pages/Spaces";
import NewSpace from "@/pages/NewSpace";
import SpaceDetail from "@/pages/SpaceDetail";
import SpaceSettings from "@/pages/SpaceSettings";
import SpacePostDetail from "@/pages/SpacePostDetail";
import JoinSpaceInvite from "@/pages/JoinSpaceInvite";
import { RequireAuth } from "@/components/auth/RequireAuth";
import { useGlobalKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";

export default function App() {
  useGlobalKeyboardShortcuts();
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Feed />} />
        <Route path="following" element={<FollowingFeed />} />
        <Route path="trending" element={<TrendingFeed />} />
        <Route path="search" element={<Search />} />
        <Route path="users" element={<UserDirectory />} />
        <Route path="leaderboard" element={<Leaderboard />} />
        <Route path="posts/:slug" element={<PostDetail />} />
        <Route path="tags/:slug" element={<TagFeed />} />
        <Route path="users/:username" element={<Profile />} />
        <Route path="login" element={<Login />} />
        <Route path="register" element={<Register />} />
        <Route path="forgot-password" element={<ForgotPassword />} />
        <Route path="reset-password" element={<ResetPassword />} />
        <Route path="verify-email" element={<VerifyEmail />} />
        <Route path="oauth/callback" element={<OAuthCallback />} />
        <Route path="series/:slug" element={<SeriesDetail />} />
        <Route path="spaces" element={<Spaces />} />
        <Route path="spaces/invite/:code" element={<JoinSpaceInvite />} />
        <Route path="spaces/:slug/channels/:channelSlug/posts/:postSlug" element={<SpacePostDetail />} />
        <Route path="spaces/:slug" element={<SpaceDetail />} />
        <Route element={<RequireAuth />}>
          <Route path="new" element={<NewPost />} />
          <Route path="posts/:slug/edit" element={<EditPost />} />
          <Route path="posts/:slug/revisions" element={<PostRevisions />} />
          <Route path="me/posts" element={<MyPosts />} />
          <Route path="me/history" element={<ReadingHistory />} />
          <Route path="me/scheduled" element={<ScheduledPosts />} />
          <Route path="bookmarks" element={<Bookmarks />} />
          <Route path="series/new" element={<NewSeries />} />
          <Route path="me/series" element={<MySeries />} />
          <Route path="spaces/new" element={<NewSpace />} />
          <Route path="spaces/:slug/settings" element={<SpaceSettings />} />
          <Route path="admin/invites" element={<AdminInvites />} />
          <Route path="admin/users" element={<AdminUsers />} />
          <Route path="admin/tags" element={<AdminTags />} />
          <Route path="admin/broadcast" element={<AdminBroadcast />} />
          <Route path="admin/deletions" element={<AdminDeletions />} />
          <Route path="admin/audit" element={<AdminAudit />} />
          <Route path="admin/stats" element={<AdminStats />} />
          <Route path="mod/queue" element={<ModQueue />} />
          <Route path="settings" element={<Settings />} />
          <Route path="onboarding" element={<Onboarding />} />
        </Route>
        <Route path="404" element={<NotFound />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Route>
    </Routes>
  );
}
