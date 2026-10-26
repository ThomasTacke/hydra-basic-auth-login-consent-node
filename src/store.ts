// Profile store: one row per user who has signed in via SSO.
// The login app owns this data; poste.io only checks passwords (see README).

import { DatabaseSync } from "node:sqlite"
import fs from "fs"
import path from "path"

const file = process.env.PROFILE_DB || "/data/profiles.db"
fs.mkdirSync(path.dirname(file), { recursive: true })
const db = new DatabaseSync(file)
db.exec("PRAGMA foreign_keys = ON")

const schemaVersion = () => (db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version

// Schema version in PRAGMA user_version, so later steps can migrate
if (schemaVersion() < 1) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS profiles (
      sub TEXT PRIMARY KEY,   -- lowercase mail address (Hydra subject)
      name TEXT,              -- set by the user; NULL = name from poste.io
      created_at TEXT NOT NULL,
      last_login_at TEXT NOT NULL
    );
    PRAGMA user_version = 1;
  `)
}

if (schemaVersion() < 2) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS orgs (
      id TEXT PRIMARY KEY,             -- Pangolin's organization ID
      name TEXT NOT NULL,
      domains TEXT NOT NULL DEFAULT '' -- mail domains whose mailboxes are members by default
    );
    CREATE TABLE IF NOT EXISTS memberships (
      sub TEXT NOT NULL,
      org TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'none')), -- none: overrides the domain rule
      PRIMARY KEY (sub, org)
    );
    PRAGMA user_version = 2;
  `)
}

export interface Profile {
  sub: string
  name: string | null
  created_at: string
  last_login_at: string
}

const upsertLogin = db.prepare(`
  INSERT INTO profiles (sub, created_at, last_login_at) VALUES (?, ?, ?)
  ON CONFLICT (sub) DO UPDATE SET last_login_at = excluded.last_login_at
`)
const selectProfile = db.prepare("SELECT * FROM profiles WHERE sub = ?")

// Creates the profile on the first login, afterwards only updates last_login_at
export const recordLogin = (sub: string) => {
  const now = new Date().toISOString()
  upsertLogin.run(sub, now, now)
}

export const getProfile = (sub: string) => selectProfile.get(sub) as Profile | undefined

const updateName = db.prepare("UPDATE profiles SET name = ? WHERE sub = ?")

// null: use poste.io's name again
export const setName = (sub: string, name: string | null) => {
  updateName.run(name, sub)
}

// ---- Organizations and memberships

export interface Org {
  id: string
  name: string
  domains: string
}

export type Role = "admin" | "member" | "none"

const selectOrgs = db.prepare("SELECT * FROM orgs ORDER BY id")
const upsertOrg = db.prepare(`
  INSERT INTO orgs (id, name, domains) VALUES (?, ?, ?)
  ON CONFLICT (id) DO UPDATE SET name = excluded.name, domains = excluded.domains
`)
const removeOrg = db.prepare("DELETE FROM orgs WHERE id = ?")
const selectMemberships = db.prepare("SELECT * FROM memberships")
const selectMembershipsOf = db.prepare("SELECT * FROM memberships WHERE sub = ?")
const upsertMembership = db.prepare(`
  INSERT INTO memberships (sub, org, role) VALUES (?, ?, ?)
  ON CONFLICT (sub, org) DO UPDATE SET role = excluded.role
`)
const removeMembership = db.prepare("DELETE FROM memberships WHERE sub = ? AND org = ?")
const selectUsers = db.prepare(`
  SELECT sub, MAX(last_login_at) AS last_login_at FROM (
    SELECT sub, last_login_at FROM profiles
    UNION ALL SELECT sub, NULL FROM memberships
  ) GROUP BY sub ORDER BY sub
`)

export const listOrgs = () => selectOrgs.all() as unknown as Org[]
export const saveOrg = (org: Org) => upsertOrg.run(org.id, org.name, org.domains)
export const deleteOrg = (id: string) => removeOrg.run(id)

export const listMemberships = () =>
  selectMemberships.all() as unknown as { sub: string; org: string; role: Role }[]

// role null: back to the domain rule
export const setMembership = (sub: string, org: string, role: Role | null) => {
  if (role) {
    upsertMembership.run(sub, org, role)
  } else {
    removeMembership.run(sub, org)
  }
}

// Everyone who has signed in or has an explicit membership
export const listUsers = () =>
  selectUsers.all() as unknown as { sub: string; last_login_at: string | null }[]

const domainOf = (sub: string) => sub.split("@")[1] || ""
const orgDomains = (org: Org) => org.domains.split(/[\s,]+/).filter(Boolean)

// Role from the domain rule alone (member or none)
export const defaultRole = (sub: string, org: Org): Role =>
  orgDomains(org).includes(domainOf(sub)) ? "member" : "none"

// Effective memberships: explicit entries first, else the domain rule
export const orgsOf = (sub: string) => {
  const explicit = new Map(
    (selectMembershipsOf.all(sub) as unknown as { org: string; role: Role }[]).map((m) => [m.org, m.role]),
  )
  return listOrgs()
    .map((org) => ({ org, role: explicit.get(org.id) ?? defaultRole(sub, org) }))
    .filter((m) => m.role !== "none") as { org: Org; role: "admin" | "member" }[]
}
