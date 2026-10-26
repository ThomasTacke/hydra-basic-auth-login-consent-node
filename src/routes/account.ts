// Account page: the user's own profile (name), links to the password change and
// "sign out everywhere". It signs in through Hydra like any other app (authorization
// code with PKCE) and keeps the result in a signed cookie.

import crypto from "crypto"
import express from "express"
import csrf from "csurf"
import QRCode from "qrcode"
import { disableTotp, enableTotp, getProfile, hasTotp, orgsOf, recoveryCodesLeft, replaceRecoveryCodes, setName } from "../store"
import { secretConfigured } from "../secret"
import { currentStep, encryptSecret, generateRecoveryCodes, generateSecret, hashRecoveryCode, otpauthUrl, verifyCode } from "../totp"
import { checkSecondFactor, secondFactorError } from "../twofactor"
import { posteUser } from "../poste"

const router = express.Router()
const csrfProtection = csrf({ cookie: { sameSite: "lax" } })

const clientId = process.env.ACCOUNT_CLIENT_ID || ""
const clientSecret = process.env.ACCOUNT_CLIENT_SECRET || ""
// Browser side: Hydra's public URL. Server side: Hydra inside the Docker network.
const issuer = (process.env.URLS_SELF_ISSUER || "").replace(/\/?$/, "/")
const hydraPublicInternal = (process.env.HYDRA_PUBLIC_URL || "http://hydra:4444").replace(/\/?$/, "/")
const loginOrigin = process.env.URLS_LOGIN ? new URL(process.env.URLS_LOGIN).origin : ""
const redirectUri = `${loginOrigin}/account/callback`
const dashboardUrl = process.env.DASHBOARD_URL || "/"
const passwordUrl = process.env.PASSWORD_URL || `https://${process.env.AUTH_HOSTNAME}/admin/my/edit`

// Name of the account in authenticator apps, e.g. "s3r3nity.org"
const totpIssuer = process.env.TOTP_ISSUER || (issuer ? new URL(issuer).hostname.replace(/^auth\./, "") : "SSO")

const SESSION = "account_session"
const SETUP = "account_totp_setup"
const LOGIN = "account_login"
// secure on https (production); plain http only in local tests
const cookieBase = { httpOnly: true, secure: loginOrigin.startsWith("https:"), sameSite: "lax" as const, path: "/account", signed: true }

const base64url = (buf: Buffer) => buf.toString("base64url")
const localPart = (sub: string) => (sub.includes("@") ? sub.split("@")[0] : sub)

// Returns the signed-in subject, or undefined
export const sessionSub = (req: express.Request): string | undefined => {
  try {
    const session = JSON.parse(req.signedCookies[SESSION] || "null")
    if (session && typeof session.sub === "string" && session.exp > Date.now()) {
      return session.sub
    }
  } catch {
    // tampered or old cookie: treat as signed out
  }
  return undefined
}

router.use((req, res, next) => {
  if (!clientId || !clientSecret || !issuer || !loginOrigin) {
    next(new Error("The account page is not configured (ACCOUNT_CLIENT_ID, ACCOUNT_CLIENT_SECRET, URLS_SELF_ISSUER, URLS_LOGIN)."))
    return
  }
  next()
})

router.get("/", csrfProtection, (req, res) => {
  const sub = sessionSub(req)
  if (!sub) {
    // Not signed in: start the authorization code flow with PKCE
    const state = base64url(crypto.randomBytes(24))
    const verifier = base64url(crypto.randomBytes(32))
    const challenge = base64url(crypto.createHash("sha256").update(verifier).digest())
    res.cookie(LOGIN, JSON.stringify({ state, verifier }), { ...cookieBase, maxAge: 10 * 60 * 1000 })
    const url = new URL("oauth2/auth", issuer)
    url.search = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      scope: "openid email profile",
      redirect_uri: redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString()
    res.redirect(url.toString())
    return
  }

  const profile = getProfile(sub)
  const poste = posteUser(sub)
  const defaultName = poste?.name || localPart(sub)
  res.render("account", {
    title: "Your account",
    csrfToken: req.csrfToken(),
    email: sub,
    ownName: profile?.name || "",
    defaultName,
    isAdmin: Boolean(poste?.admin),
    orgs: orgsOf(sub),
    saved: req.query.saved === "1",
    done: typeof req.query.done === "string" ? req.query.done : "",
    totp: hasTotp(sub),
    codesLeft: recoveryCodesLeft(sub),
    passwordUrl,
    dashboardUrl,
  })
})

router.get("/callback", async (req, res, next) => {
  try {
    let login: { state?: string; verifier?: string } = {}
    try {
      login = JSON.parse(req.signedCookies[LOGIN] || "{}")
    } catch {
      // handled below
    }
    res.clearCookie(LOGIN, cookieBase)
    if (typeof req.query.error === "string") {
      res.redirect(dashboardUrl) // e.g. "Cancel" on the login page
      return
    }
    if (!login.state || req.query.state !== login.state || typeof req.query.code !== "string") {
      res.redirect("/account") // expired or foreign request: start over
      return
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64"),
    }
    if (process.env.MOCK_TLS_TERMINATION) {
      headers["X-Forwarded-Proto"] = "https"
    }
    const response = await fetch(new URL("oauth2/token", hydraPublicInternal), {
      method: "POST",
      headers,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: req.query.code,
        redirect_uri: redirectUri,
        code_verifier: String(login.verifier),
      }),
    })
    if (!response.ok) {
      throw new Error(`Token request failed: ${response.status} ${await response.text()}`)
    }
    const tokens = (await response.json()) as { id_token?: string }

    // The ID token comes straight from Hydra's token endpoint inside the Docker network,
    // so its claims are read without checking the signature (OpenID Connect Core 3.1.3.7).
    const claims = JSON.parse(Buffer.from(String(tokens.id_token).split(".")[1] || "", "base64url").toString())
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (!audience.includes(clientId) || typeof claims.sub !== "string") {
      throw new Error("Unexpected ID token from Hydra")
    }

    res.cookie(SESSION, JSON.stringify({ sub: claims.sub, exp: Date.now() + 60 * 60 * 1000 }), {
      ...cookieBase,
      maxAge: 60 * 60 * 1000,
    })
    res.redirect("/account")
  } catch (err) {
    next(err)
  }
})

router.post("/", csrfProtection, (req, res) => {
  const sub = sessionSub(req)
  if (!sub) {
    res.redirect("/account")
    return
  }
  // Empty: go back to poste.io's name
  const name = String(req.body.name || "").trim().slice(0, 100)
  setName(sub, name || null)
  res.redirect("/account?saved=1")
})

// Ends the account session, then Hydra's login session. Hydra shows the logout page and
// afterwards sends the browser to URLS_POST_LOGOUT_REDIRECT (Homepage's sign-out).
router.post("/signout", csrfProtection, (req, res) => {
  res.clearCookie(SESSION, cookieBase)
  res.redirect(new URL("oauth2/sessions/logout", issuer).toString())
})

// ---- Two-factor login

const requireSession = (req: express.Request, res: express.Response) => {
  const sub = sessionSub(req)
  if (!sub) res.redirect("/account")
  return sub
}

const renderSetup = async (req: express.Request, res: express.Response, sub: string, secret: string, error: string) =>
  res.render("account-totp", {
    title: "Set up two-factor login",
    csrfToken: req.csrfToken(),
    qr: await QRCode.toDataURL(otpauthUrl(secret, sub, totpIssuer), { margin: 1, width: 220 }),
    key: secret.match(/.{1,4}/g)?.join(" "),
    error,
  })

const renderCodes = (req: express.Request, res: express.Response, codes: string[]) =>
  res.render("account-codes", { title: "Recovery codes", codes })

router.get("/totp", csrfProtection, async (req, res, next) => {
  try {
    const sub = requireSession(req, res)
    if (!sub) return
    if (!secretConfigured) throw new Error("SECRETS_SYSTEM is not set, so two-factor login can't be set up.")
    if (hasTotp(sub)) return res.redirect("/account")
    // The new secret stays in a signed cookie until the user has confirmed a code
    const secret = generateSecret()
    res.cookie(SETUP, secret, { ...cookieBase, maxAge: 10 * 60 * 1000 })
    await renderSetup(req, res, sub, secret, "")
  } catch (err) {
    next(err)
  }
})

router.post("/totp", csrfProtection, async (req, res, next) => {
  try {
    const sub = requireSession(req, res)
    if (!sub) return
    const secret = req.signedCookies[SETUP]
    if (typeof secret !== "string" || !secret) return res.redirect("/account/totp")
    const step = verifyCode(secret, String(req.body.code || ""))
    if (step === null) return renderSetup(req, res, sub, secret, "The code is not correct. Check the time on your phone and try again.")

    const codes = generateRecoveryCodes()
    enableTotp(sub, encryptSecret(secret), step, codes.map((code) => hashRecoveryCode(sub, code)))
    res.clearCookie(SETUP, cookieBase)
    renderCodes(req, res, codes)
  } catch (err) {
    next(err)
  }
})

// New recovery codes and turning it off both need a current code
router.post("/totp/codes", csrfProtection, (req, res) => {
  const sub = requireSession(req, res)
  if (!sub) return
  const result = checkSecondFactor(sub, String(req.body.code || ""))
  if (result !== "ok") return res.redirect("/account?done=" + encodeURIComponent(secondFactorError(result)))
  const codes = generateRecoveryCodes()
  replaceRecoveryCodes(sub, codes.map((code) => hashRecoveryCode(sub, code)))
  renderCodes(req, res, codes)
})

router.post("/totp/disable", csrfProtection, (req, res) => {
  const sub = requireSession(req, res)
  if (!sub) return
  const result = checkSecondFactor(sub, String(req.body.code || ""))
  if (result !== "ok") return res.redirect("/account?done=" + encodeURIComponent(secondFactorError(result)))
  disableTotp(sub)
  res.redirect("/account?done=" + encodeURIComponent("Two-factor login is off."))
})

export default router
