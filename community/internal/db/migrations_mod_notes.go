package db

const ddlModeratorNotes = `
ALTER TABLE reports ADD COLUMN IF NOT EXISTS moderator_note TEXT;`
