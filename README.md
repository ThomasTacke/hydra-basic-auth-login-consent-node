# hydra-user-and-consent-provider-node

## Environment

| Variable | Purpose |
|---|---|
| `HYDRA_ADMIN_URL` | Hydra's admin API, e.g. `http://hydra:4445` |
| `MOCK_TLS_TERMINATION` | send `X-Forwarded-Proto: https` to Hydra (TLS ends at the reverse proxy) |
| `AUTH_HOSTNAME`, `AUTH_PORT`, `AUTH_PATH`, `AUTH_METHOD` | poste.io endpoint that checks the password with basic auth (method defaults to `GET`); 401 = wrong password |
| `PROFILE_DB` | profile store, default `/data/profiles.db` (mount a volume at `/data`) |
| `POSTE_USERS_FILE` | poste.io export (name, admin flag), default `/claims/poste-users.json` |
| `URLS_SELF_ISSUER`, `URLS_LOGIN` | Hydra's public URL and this app's login URL (shared with Hydra's env) |
| `HYDRA_PUBLIC_URL` | Hydra's public API inside the Docker network, default `http://hydra:4444` |
| `ACCOUNT_CLIENT_ID`, `ACCOUNT_CLIENT_SECRET` | Hydra client of the account page, redirect URI `<login origin>/account/callback` |
| `SECRETS_SYSTEM` | Hydra's system secret; the key for signed cookies is derived from it |
| `DASHBOARD_URL` | "Back to the dashboard" and "Stay signed in" on the logout page |
| `PASSWORD_URL` | password change, default `https://<AUTH_HOSTNAME>/admin/my/edit` |

## Account page

`/account` signs in through Hydra like any other app and shows the user's address, a
display name they can change (empty = the name from poste.io), a link to change the
password in poste.io and "Sign out everywhere": that ends the account session and
Hydra's login session; Hydra then sends the browser to its `urls.post_logout_redirect`.

## Organizations

poste.io's super admins manage organizations at `/account/admin`. An organization has an
ID (use the same as in the app that reads it, e.g. Pangolin), a name and mail domains
whose mailboxes are members by default. Explicit entries per user override that:
*Admin*, *Member* or *Not a member*. With the `profile` scope the ID token carries
`orgs` (IDs) and `groups` (`admin` for super admins, plus `<org>:admin` / `<org>:member`).
