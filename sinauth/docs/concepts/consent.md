# Consent

## What is the consent screen?

When a SIN platform requests access to a user's data for the first time, sinauth shows a consent screen. The screen lists:

- The name and logo of the platform requesting access
- The scopes being requested, in plain language (e.g., "Read your email address", "Read your profile name and avatar")
- Buttons to approve or deny

If the user approves, sinauth records the consent in the `oauth_consents` table and proceeds with the authorization flow. If the user denies, sinauth redirects back to the platform with `error=access_denied`.

## Consent storage

```sql
CREATE TABLE oauth_consents (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
```

One row per (user, client) pair. The `scopes` array records what was approved.

## When the consent screen is skipped

The consent screen is skipped when:

1. **All requested scopes were previously consented.** sinauth checks whether the current authorization request's scopes are a subset of the previously consented scopes. If so, the user has already approved and no re-confirmation is needed.

2. **The user has an active SSO session AND all scopes are consented.** The user flows directly from the platform redirect, through sinauth, back to the platform without seeing any UI at all.

## When the consent screen is shown

The consent screen is shown when:

1. **First-time authorization**: the user has never authorized this client before.
2. **New scopes**: the platform now requests a scope that was not in the original consent (e.g., adding `offline_access` after the user previously only consented to `openid profile email`). Only the newly requested scopes are shown for re-confirmation.

## Revoking consent

Users can revoke previously granted consent. In v1.0, this is done by deleting the row from `oauth_consents` (via admin API or direct database access). A user-facing "Manage connected applications" page is planned for v1.1.

After revocation, the next authorization request from that client will show the consent screen again.

When a client is deleted from sinauth, all consent records for that client are deleted via the `ON DELETE CASCADE` foreign key constraint.

## Consent vs re-authentication

Consent (`oauth_consents`) is separate from authentication (SSO sessions):

- **Revoking consent** means the user will see the consent screen again on next login. They do not need to re-enter their password (if the SSO session is still valid).
- **Logging out** (`/oauth/endsession`) ends the SSO session. The user must re-enter their password. Previously granted consents are not affected.
