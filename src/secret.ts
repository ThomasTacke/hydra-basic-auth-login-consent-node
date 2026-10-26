// Keys for signed cookies and for encrypting TOTP secrets. Derived from Hydra's
// SECRETS_SYSTEM, which the login app gets from the same env file, so there is no extra
// secret to manage. Changing SECRETS_SYSTEM ends sessions and invalidates two-factor setups.

import crypto from "crypto"

// Without SECRETS_SYSTEM, sessions end on restart and two-factor login can't be set up
export const secretConfigured = Boolean(process.env.SECRETS_SYSTEM)
if (!secretConfigured) {
  console.warn("SECRETS_SYSTEM is not set: account sessions end when the login app restarts.")
}
const secret = process.env.SECRETS_SYSTEM || crypto.randomBytes(32).toString("hex")

// One key per purpose, all derived from the same secret
export const deriveKey = (purpose: string) => crypto.createHmac("sha256", secret).update(purpose).digest()

export const cookieSecret = deriveKey("login-app cookies").toString("hex")

// secure on https (production); plain http only in local tests
export const secureCookies = (process.env.URLS_LOGIN || "").startsWith("https:")
