// Checks a second factor: a TOTP code (6 digits) or a recovery code

import { decryptSecret, hashRecoveryCode, verifyCode } from "./totp"
import { acceptTotpStep, getProfile, isTotpLocked, recordTotpFailure, useRecoveryCode } from "./store"

export type SecondFactorResult = "ok" | "wrong" | "locked"

export const checkSecondFactor = (sub: string, input: string): SecondFactorResult => {
  const profile = getProfile(sub)
  if (!profile?.totp_secret) return "wrong"
  if (isTotpLocked(sub)) return "locked"

  const code = input.trim()
  if (/^\d[\d\s]*$/.test(code)) {
    const step = verifyCode(decryptSecret(profile.totp_secret), code, profile.totp_last_step)
    if (step !== null) {
      acceptTotpStep(sub, step)
      return "ok"
    }
  } else if (code && useRecoveryCode(sub, hashRecoveryCode(sub, code))) {
    return "ok"
  }

  recordTotpFailure(sub)
  return isTotpLocked(sub) ? "locked" : "wrong"
}

export const secondFactorError = (result: SecondFactorResult) =>
  result === "locked"
    ? "Too many wrong codes. Two-factor login is locked for 15 minutes."
    : "The code is not correct."
