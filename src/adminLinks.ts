// Links for the "Administration" section of the account page, shown to admins only.
// ADMIN_LINKS: entries separated by ";", each "Title|URL|Description" (description optional).

export interface AdminLink {
  title: string
  url: string
  description: string
}

const parse = (value: string): AdminLink[] =>
  value
    .split(";")
    .map((entry) => entry.split("|").map((field) => field.trim()))
    .filter(([title, url]) => title && /^https?:\/\//.test(url || ""))
    .map(([title, url, description]) => ({ title, url, description: description || "" }))

export const adminLinks = parse(process.env.ADMIN_LINKS || "")
