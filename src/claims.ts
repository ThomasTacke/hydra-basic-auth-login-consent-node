// ID token claims for the logged in user, built at consent time.
// The subject is the lowercase mail address used at login.

import { getProfile, orgsOf } from "./store"
import { posteUser } from "./poste"

export const idTokenClaims = (subject: string = "", scopes: string[] = []) => {
  const localPart = subject.includes("@") ? subject.split("@")[0] : subject
  const claims: { [key: string]: unknown } = {
    email: subject,
    email_verified: true,
    preferred_username: localPart,
  }

  if (scopes.includes("profile")) {
    const poste = posteUser(subject)
    // The user's own name first, then poste.io's, then the part before the @
    claims.name = getProfile(subject)?.name || poste?.name || localPart
    const memberships = orgsOf(subject)
    // Organization IDs, e.g. for Pangolin: contains(orgs, '{{orgId}}')
    claims.orgs = memberships.map((m) => m.org.id)
    // "admin" for poste.io's super admins, plus "<org>:admin" / "<org>:member"
    claims.groups = [...(poste?.admin ? ["admin"] : []), ...memberships.map((m) => `${m.org.id}:${m.role}`)]
  }

  return claims
}
