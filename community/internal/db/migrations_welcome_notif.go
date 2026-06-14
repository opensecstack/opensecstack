package db

const ddlWelcomeNotification = `
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_type_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_type_check
  CHECK (type = ANY (ARRAY[
    'comment_on_post',
    'reaction_on_post',
    'followed_by_user',
    'mentioned_in_comment',
    'welcome'
  ]));`
