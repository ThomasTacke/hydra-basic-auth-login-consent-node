// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import express from "express"
import urljoin from "url-join"
import csrf from "csurf"
import { hydraAdmin } from "../config"
import { hasTotp, recordLogin } from "../store"
import { secureCookies } from "../secret"
import { checkSecondFactor, secondFactorError } from "../twofactor"
import { oidcConformityMaybeFakeAcr } from "./stub/oidc-cert"
import https from "https";


// Sets up csrf protection
const csrfProtection = csrf({
  cookie: {
    sameSite: "lax",
  },
})
const router = express.Router()

router.get("/", csrfProtection, (req, res, next) => {
  // The challenge is used to fetch information about the login request from ORY Hydra.
  const challenge = req.query.login_challenge
  if (typeof challenge !== "string" || !challenge) {
    next(new Error("Expected a login challenge to be set but received none."))
    return
  }

  hydraAdmin
    .getOAuth2LoginRequest({ loginChallenge: challenge })
    .then((body) => {
      // If hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate
      // the user.
      if (body.skip) {
        // You can apply logic here, for example update the number of times the user logged in.
        // ...

        recordLogin(String(body.subject))

        // Now it's time to grant the login request. You could also deny the request if something went terribly wrong
        // (e.g. your arch-enemy logging in...)
        return hydraAdmin
          .acceptOAuth2LoginRequest({
            loginChallenge: challenge,
            acceptOAuth2LoginRequest: {
              // All we need to do is to confirm that we indeed want to log in the user.
              subject: String(body.subject),
            },
          })
          .then((body) => {
            // All we need to do now is to redirect the user back to hydra!
            res.redirect(String(body.redirect_to))
          })
      }

      // If authentication can't be skipped we MUST show the login UI.
      res.render("login", {
        csrfToken: req.csrfToken(),
        challenge: challenge,
        action: urljoin(process.env.BASE_URL || "", "/login"),
        hint: body.oidc_context?.login_hint || "",
        clientName: body.client?.client_name || "",
      })
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(next)
})

router.post("/", csrfProtection, (req, res, next) => {
  const challenge = req.body.challenge;

  if (req.body.submit === "Deny access") {
    return hydraAdmin.rejectOAuth2LoginRequest({
      loginChallenge: challenge,
      rejectOAuth2Request: {
        error: "access_denied",
        error_description: "The resource owner denied the request",
      },
    })
    .then((data) => res.redirect(String(data.redirect_to)))
    .catch(next);
  }

  // The mail address becomes the subject: "Kiwi@…" and "kiwi@…" must be the same user
  const email = String(req.body.email || "").trim().toLowerCase();
  const authHeader = Buffer.from(`${email}:${req.body.password}`).toString("base64");

  const authHostname = process.env.AUTH_HOSTNAME;
  const authPort = process.env.AUTH_PORT;
  const authPath = process.env.AUTH_PATH || "";
  const authMethod = process.env.AUTH_METHOD || "GET";
  if (!authHostname)
    throw new Error("Environment variable AUTH_HOSTNAME not set");
  
  if (!authPort)
    throw new Error("Environment variable AUTH_PORT not set");
  
  const options = {
    hostname: authHostname,
    port: authPort,
    path: authPath,
    method: authMethod,
    headers: {
      "Authorization": `Basic ${authHeader}`,
      "Accept": "application/json",
    },
  };

  const mailReq = https.request(options, (response) => {
    if (response.statusCode === 401) {
      return res.render("login", {
        csrfToken: req.csrfToken(),
        challenge,
        action: urljoin(process.env.BASE_URL || "", "/login"),
        hint: email,
        clientName: String(req.body.client_name || ""),
        error: "Email or password is not correct.",
      });
    }

    if (response.statusCode && Math.floor(response.statusCode / 100) === 5) {
      return res.render("error", { title: "Error", message: "The mail server could not check the login. Please try again later." });
    }

    // success: continue Hydra login accept
    recordLogin(email)
    const remember = Boolean(req.body.remember)

    // Two-factor login set up: ask for the code first, the password check is kept in a
    // signed cookie for 5 minutes
    if (hasTotp(email)) {
      res.cookie(PENDING, JSON.stringify({ challenge, email, remember, exp: Date.now() + PENDING_MS }), {
        httpOnly: true, secure: secureCookies, sameSite: "lax", path: "/login", signed: true, maxAge: PENDING_MS,
      })
      return renderSecondFactor(req, res, String(req.body.client_name || ""), "")
    }

    acceptLogin(challenge, email, remember, ["pwd"], res, next)
  });

  mailReq.on("error", (err) => {
    console.error(err);
    res.render("error", { title: "Error", message: "The mail server is not reachable. Please try again later." });
  });

  mailReq.end();
});

const PENDING = "login_2fa"
const PENDING_MS = 5 * 60 * 1000

const renderSecondFactor = (req: express.Request, res: express.Response, clientName: string, error: string) =>
  res.render("totp", {
    title: "Two-factor login",
    csrfToken: req.csrfToken(),
    action: urljoin(process.env.BASE_URL || "", "/login/totp"),
    clientName,
    error,
  })

const acceptLogin = (
  challenge: string, email: string, remember: boolean, amr: string[],
  res: express.Response, next: express.NextFunction,
) =>
  hydraAdmin.getOAuth2LoginRequest({ loginChallenge: challenge })
    .then((loginRequest) =>
      hydraAdmin.acceptOAuth2LoginRequest({ loginChallenge: challenge, acceptOAuth2LoginRequest: {
        subject: email,
        remember,
        remember_for: 3600,
        acr: oidcConformityMaybeFakeAcr(loginRequest, "0"),
        // How the user signed in, e.g. ["pwd", "otp"]; ends up in the ID token
        amr,
      } })
    )
    .then((data) => res.redirect(String(data.redirect_to)))
    .catch(next)

router.post("/totp", csrfProtection, (req, res, next) => {
  let pending: { challenge?: string; email?: string; remember?: boolean; exp?: number } = {}
  try {
    pending = JSON.parse(req.signedCookies[PENDING] || "{}")
  } catch {
    // handled below
  }
  if (!pending.challenge || !pending.email || !pending.exp || pending.exp < Date.now()) {
    res.clearCookie(PENDING, { path: "/login" })
    return res.render("error", { title: "Error", message: "The sign-in has expired. Go back to the app and sign in again." })
  }

  if (req.body.submit === "Cancel") {
    res.clearCookie(PENDING, { path: "/login" })
    return hydraAdmin.rejectOAuth2LoginRequest({
      loginChallenge: pending.challenge,
      rejectOAuth2Request: { error: "access_denied", error_description: "The resource owner denied the request" },
    })
      .then((data) => res.redirect(String(data.redirect_to)))
      .catch(next)
  }

  const result = checkSecondFactor(pending.email, String(req.body.code || ""))
  if (result !== "ok") {
    return renderSecondFactor(req, res, String(req.body.client_name || ""), secondFactorError(result))
  }

  res.clearCookie(PENDING, { path: "/login" })
  acceptLogin(pending.challenge, pending.email, Boolean(pending.remember), ["pwd", "otp"], res, next)
})

export default router
