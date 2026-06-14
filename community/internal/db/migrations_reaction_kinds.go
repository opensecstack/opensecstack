package db

// ddlReactionKindsUpdate drops the old kind check constraint and replaces it with
// one that covers all five reaction kinds used by the multi-emoji reaction bar.
const ddlReactionKindsUpdate = `
DO $$
BEGIN
  -- Drop the old constraint if it still has the narrow (3-kind) definition.
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'reactions_kind_check'
      AND conrelid = 'reactions'::regclass
  ) THEN
    ALTER TABLE reactions DROP CONSTRAINT reactions_kind_check;
  END IF;

  -- Add the new constraint only if it doesn't already exist.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'reactions_kind_check_v2'
      AND conrelid = 'reactions'::regclass
  ) THEN
    ALTER TABLE reactions
      ADD CONSTRAINT reactions_kind_check_v2
      CHECK (kind IN ('heart','unicorn','fire','like','insight','celebrate'));
  END IF;
END $$;
`
