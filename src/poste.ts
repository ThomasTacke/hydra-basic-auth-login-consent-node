// Name and admin flag per mailbox, exported from poste.io by export-claims.sh in
// bento-kx/server-setup. Only these fields leave poste.io, never the password hashes.

import fs from "fs"

interface PosteUser {
  address: string
  name: string | null
  admin: number
  disabled: number
}

const file = process.env.POSTE_USERS_FILE || "/claims/poste-users.json"
let cache: { mtimeMs: number; users: Map<string, PosteUser> } | undefined
let warned = false

// Re-reads the file only when the export has replaced it
export const posteUser = (address: string): PosteUser | undefined => {
  try {
    const { mtimeMs } = fs.statSync(file)
    if (!cache || cache.mtimeMs !== mtimeMs) {
      const list: PosteUser[] = JSON.parse(fs.readFileSync(file, "utf8"))
      cache = { mtimeMs, users: new Map(list.map((u) => [u.address.toLowerCase(), u])) }
    }
    warned = false
  } catch (err) {
    if (!warned) {
      console.warn(`Cannot read ${file}, names and groups fall back to defaults: ${err}`)
      warned = true
    }
  }
  return cache?.users.get(address.toLowerCase())
}
