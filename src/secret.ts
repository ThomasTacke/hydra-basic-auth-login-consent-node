// Key for signed cookies (account session). Derived from Hydra's SECRETS_SYSTEM, which
// the login app gets from the same env file, so there is no extra secret to manage.

import crypto from "crypto"

let secret = process.env.SECRETS_SYSTEM
if (!secret) {
  console.warn("SECRETS_SYSTEM is not set: account sessions end when the login app restarts.")
  secret = crypto.randomBytes(32).toString("hex")
}

export const cookieSecret = crypto.createHmac("sha256", secret).update("login-app cookies").digest("hex")
