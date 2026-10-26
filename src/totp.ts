// TOTP (RFC 6238: HMAC-SHA1, 30 s, 6 digits) and recovery codes, with Node's crypto only

import crypto from "crypto"
import { deriveKey } from "./secret"

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

export const base32Encode = (buf: Buffer) => {
  let bits = 0
  let value = 0
  let out = ""
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31]
  return out
}

export const base32Decode = (text: string) => {
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of text.toUpperCase().replace(/[^A-Z2-7]/g, "")) {
    value = (value << 5) | BASE32.indexOf(char)
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

export const generateSecret = () => base32Encode(crypto.randomBytes(20))

export const currentStep = (now = Date.now()) => Math.floor(now / 1000 / 30)

export const codeAt = (secret: string, step: number) => {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(counter).digest()
  const offset = hmac[hmac.length - 1] & 0xf
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0")
}

// Accepts the current code and one step either side (clock drift). Returns the step the
// code belongs to, or null. Steps up to lastStep are refused, so a code works only once.
export const verifyCode = (secret: string, code: string, lastStep: number | null = null) => {
  const clean = code.replace(/\s/g, "")
  if (!/^\d{6}$/.test(clean)) return null
  const now = currentStep()
  for (const step of [now - 1, now, now + 1]) {
    if (lastStep !== null && step <= lastStep) continue
    if (crypto.timingSafeEqual(Buffer.from(codeAt(secret, step)), Buffer.from(clean))) return step
  }
  return null
}

export const otpauthUrl = (secret: string, account: string, issuer: string) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` +
  `?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`

// TOTP secrets are stored encrypted (AES-256-GCM): iv.tag.ciphertext, base64
const encryptionKey = () => deriveKey("login-app totp encryption")

export const encryptSecret = (plain: string) => {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv)
  const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()])
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString("base64")).join(".")
}

export const decryptSecret = (stored: string) => {
  const [iv, tag, data] = stored.split(".").map((part) => Buffer.from(part, "base64"))
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8")
}

// Recovery codes: 10 x "xxxx-xxxx" (no 0/o, 1/l/i), stored only as HMAC
const CODE_CHARS = "abcdefghjkmnpqrstuvwxyz23456789"

export const generateRecoveryCodes = () =>
  Array.from({ length: 10 }, () => {
    const chars = Array.from({ length: 8 }, () => CODE_CHARS[crypto.randomInt(CODE_CHARS.length)])
    return `${chars.slice(0, 4).join("")}-${chars.slice(4).join("")}`
  })

export const hashRecoveryCode = (sub: string, code: string) =>
  crypto
    .createHmac("sha256", deriveKey("login-app recovery codes"))
    .update(`${sub}:${code.toLowerCase().replace(/[^a-z0-9]/g, "")}`)
    .digest("hex")
