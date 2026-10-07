// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import express from "express"
import url from "url"
import urljoin from "url-join"
import csrf from "csurf"
import { hydraAdmin } from "../config"
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
  // Parses the URL query
  const query = url.parse(req.url, true).query

  // The challenge is used to fetch information about the login request from ORY Hydra.
  const challenge = String(query.login_challenge)
  if (!challenge) {
    next(new Error("Expected a login challenge to be set but received none."))
    return
  }

  hydraAdmin
    .adminGetOAuth2LoginRequest(challenge)
    .then(({ data: body }) => {
      // If hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate
      // the user.
      if (body.skip) {
        // You can apply logic here, for example update the number of times the user logged in.
        // ...

        // Now it's time to grant the login request. You could also deny the request if something went terribly wrong
        // (e.g. your arch-enemy logging in...)
        return hydraAdmin
          .adminAcceptOAuth2LoginRequest(challenge, {
            // All we need to do is to confirm that we indeed want to log in the user.
            subject: String(body.subject),
          })
          .then(({ data: body }) => {
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
      })
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(next)
})

router.post("/", csrfProtection, (req, res, next) => {
  const challenge = req.body.challenge;

  if (req.body.submit === "Deny access") {
    return hydraAdmin.adminRejectOAuth2LoginRequest(challenge, {
      error: "access_denied",
      error_description: "The resource owner denied the request",
    })
    .then(({ data }) => res.redirect(String(data.redirect_to)))
    .catch(next);
  }

  const authHeader = Buffer.from(`${req.body.email}:${req.body.password}`).toString("base64");

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
        error: "The username / password combination is not correct",
      });
    }

    if (response.statusCode && Math.floor(response.statusCode / 100) === 5) {
      return res.render("error", { error: "Server error" });
    }

    // success: continue Hydra login accept
    hydraAdmin.adminGetOAuth2LoginRequest(challenge)
      .then(({ data: loginRequest }) =>
        hydraAdmin.adminAcceptOAuth2LoginRequest(challenge, {
          subject: req.body.email, // use the real email
          remember: Boolean(req.body.remember),
          remember_for: 3600,
          acr: oidcConformityMaybeFakeAcr(loginRequest, "0")
        })
      )
      .then(({ data }) => res.redirect(String(data.redirect_to)))
      .catch(next);
  });

  mailReq.on("error", (err) => {
    res.render("error", { error: err.message });
  });

  mailReq.end();
});

export default router
