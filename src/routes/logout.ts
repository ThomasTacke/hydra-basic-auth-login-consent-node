// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import express from "express"
import urljoin from "url-join"
import csrf from "csurf"
import { hydraAdmin } from "../config"

// Sets up csrf protection
const csrfProtection = csrf({ cookie: true })
const router = express.Router()

router.get("/", csrfProtection, (req, res, next) => {
  // The challenge is used to fetch information about the logout request from ORY Hydra.
  const challenge = req.query.logout_challenge
  if (typeof challenge !== "string" || !challenge) {
    next(new Error("Expected a logout challenge to be set but received none."))
    return
  }

  hydraAdmin
    .getOAuth2LogoutRequest({ logoutChallenge: challenge })
    // This will be called if the HTTP request was successful
    .then(() => {
      // Here we have access to e.g. response.subject, response.sid, ...

      // The most secure way to perform a logout request is by asking the user if he/she really want to log out.
      res.render("logout", {
        csrfToken: req.csrfToken(),
        challenge: challenge,
        action: urljoin(process.env.BASE_URL || "", "/logout"),
      })
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(next)
})

router.post("/", csrfProtection, (req, res, next) => {
  // The challenge is now a hidden input field, so let's take it from the request body instead
  const challenge = req.body.challenge

  if (req.body.submit === "No") {
    return (
      hydraAdmin
        .rejectOAuth2LogoutRequest({ logoutChallenge: challenge })
        .then(() => {
          // The user did not want to log out. Let's redirect him back somewhere or do something else.
          res.redirect("https://www.ory.sh/")
        })
        // This will handle any error that happens when making HTTP calls to hydra
        .catch(next)
    )
  }

  // The user agreed to log out, let's accept the logout request.
  hydraAdmin
    .acceptOAuth2LogoutRequest({ logoutChallenge: challenge })
    .then((body) => {
      // All we need to do now is to redirect the user back to hydra!
      res.redirect(String(body.redirect_to))
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(next)
})

export default router
