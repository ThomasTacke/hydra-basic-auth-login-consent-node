// Admin view of the account page: organizations and memberships. Only for poste.io's
// super admins (admin flag from the poste.io export).

import express from "express"
import csrf from "csurf"
import { sessionSub } from "./account"
import { posteUser } from "../poste"
import {
  defaultRole,
  disableTotp,
  hasTotp,
  deleteOrg,
  listMemberships,
  listOrgs,
  listUsers,
  Role,
  saveOrg,
  setMembership,
} from "../store"

const router = express.Router()
const csrfProtection = csrf({ cookie: { sameSite: "lax" } })

const ORG_ID = /^[a-z0-9][a-z0-9-]{0,62}$/ // like Pangolin's organization IDs
const ROLES = ["admin", "member", "none"]

router.use((req, res, next) => {
  const sub = sessionSub(req)
  if (!sub) {
    res.redirect("/account") // sign in first
    return
  }
  if (!posteUser(sub)?.admin) {
    const err: Error & { status?: number } = new Error("Only mail server admins can open this page.")
    err.status = 403
    next(err)
    return
  }
  next()
})

router.get("/", csrfProtection, (req, res) => {
  const orgs = listOrgs()
  const explicit = new Map(listMemberships().map((m) => [`${m.sub} ${m.org}`, m.role]))
  const users = listUsers().map((u) => ({
    ...u,
    totp: hasTotp(u.sub),
    roles: orgs.map((org) => ({
      org: org.id,
      explicit: explicit.get(`${u.sub} ${org.id}`) || "",
      byDomain: defaultRole(u.sub, org),
    })),
  }))
  res.render("admin", {
    title: "Users and organizations",
    csrfToken: req.csrfToken(),
    orgs,
    users,
    saved: req.query.saved === "1",
    error: typeof req.query.error === "string" ? req.query.error : "",
  })
})

// Create or update an organization
router.post("/orgs", csrfProtection, (req, res) => {
  const id = String(req.body.id || "").trim().toLowerCase()
  const name = String(req.body.name || "").trim().slice(0, 100) || id
  const domains = String(req.body.domains || "")
    .toLowerCase()
    .split(/[\s,]+/)
    .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
    .join(" ")
  if (!ORG_ID.test(id)) {
    res.redirect("/account/admin?error=" + encodeURIComponent("The ID may only contain a-z, 0-9 and -."))
    return
  }
  saveOrg({ id, name, domains })
  res.redirect("/account/admin?saved=1")
})

router.post("/orgs/delete", csrfProtection, (req, res) => {
  deleteOrg(String(req.body.id || "")) // memberships go with it
  res.redirect("/account/admin?saved=1")
})

// Roles of one user: role_<org> = "" (domain rule) | admin | member | none
router.post("/members", csrfProtection, (req, res) => {
  const sub = String(req.body.sub || "").trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sub)) {
    res.redirect("/account/admin?error=" + encodeURIComponent("That is not a mail address."))
    return
  }
  for (const org of listOrgs()) {
    const role = String(req.body[`role_${org.id}`] ?? "")
    setMembership(sub, org.id, ROLES.includes(role) ? (role as Role) : null)
  }
  res.redirect("/account/admin?saved=1")
})

// Lost phone and recovery codes: the user signs in with the password again and can set
// up two-factor login anew
router.post("/totp/reset", csrfProtection, (req, res) => {
  disableTotp(String(req.body.sub || ""))
  res.redirect("/account/admin?saved=1")
})

export default router
