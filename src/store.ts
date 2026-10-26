// Profile store: one row per user who has signed in via SSO.
// The login app owns this data; poste.io only checks passwords (see README).

import { DatabaseSync } from "node:sqlite"
import fs from "fs"
import path from "path"

const file = process.env.PROFILE_DB || "/data/profiles.db"
fs.mkdirSync(path.dirname(file), { recursive: true })
const db = new DatabaseSync(file)

// Schema version in PRAGMA user_version, so later steps can migrate
if ((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version < 1) {
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
