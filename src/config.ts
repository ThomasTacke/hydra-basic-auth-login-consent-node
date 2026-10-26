// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import { Configuration, OAuth2Api } from "@ory/hydra-client-fetch"

const headers: Record<string, string> = {}

if (process.env.MOCK_TLS_TERMINATION) {
  headers["X-Forwarded-Proto"] = "https"
}

const configuration = new Configuration({
  basePath: process.env.HYDRA_ADMIN_URL,
  accessToken: process.env.ORY_API_KEY || process.env.ORY_PAT,
  headers,
})

const hydraAdmin = new OAuth2Api(configuration)

export { hydraAdmin }
