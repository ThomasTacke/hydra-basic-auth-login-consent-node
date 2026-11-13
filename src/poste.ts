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
const load = () => {
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
  return cache?.users
}

export const posteUser = (address: string): PosteUser | undefined => load()?.get(address.toLowerCase())

// Whether the mailbox list could be read at all: without it, an unknown address means
// nothing
export const posteUsersKnown = (): boolean => load() !== undefined

// Mailboxes whose address is at most maxDistance edits away (typos), closest first
export const similarMailboxes = (address: string, maxDistance = 3, limit = 3): string[] => {
  const wanted = address.toLowerCase()
  return [...(load()?.keys() ?? [])]
    .map((candidate) => ({ candidate, distance: editDistance(wanted, candidate) }))
    .filter((m) => m.distance > 0 && m.distance <= maxDistance)
    .sort((a, b) => a.distance - b.distance || a.candidate.localeCompare(b.candidate))
    .slice(0, limit)
    .map((m) => m.candidate)
}

// Levenshtein distance: insertions, deletions and substitutions
export const editDistance = (a: string, b: string): number => {
  let previous = Array.from({ length: b.length + 1 }, (_, j) => j)
  for (let i = 1; i <= a.length; i++) {
    const current = [i]
    for (let j = 1; j <= b.length; j++) {
      current[j] = Math.min(
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      )
    }
    previous = current
  }
  return previous[b.length]
}
