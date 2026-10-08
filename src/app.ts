// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import express, { NextFunction, Response, Request } from "express"
import path from "path"
import logger from "morgan"
import cookieParser from "cookie-parser"
import bodyParser from "body-parser"

import routes from "./routes"
import login from "./routes/login"
import logout from "./routes/logout"
import consent from "./routes/consent"

const app = express()

// serve static files from "public" folder
app.use(express.static(path.join(__dirname, "../public")))
// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

// view engine setup
app.set("views", path.join(__dirname, "..", "views"))
app.set("view engine", "pug")

app.use(logger("dev"))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use("/", routes)
app.use("/login", login)
app.use("/logout", logout)
app.use("/consent", consent)

// catch 404 and forward to error handler
app.use((req, res, next) => {
  const err: Error & { status?: number } = new Error("This page does not exist.")
  err.status = 404
  next(err)
})

// Error handler: the details go to the log, the user gets a short message.
// Express only treats handlers with four parameters as error handlers.
app.use((err: Error & { status?: number; code?: string }, req: Request, res: Response, next: NextFunction) => {
  const status = err.status || 500
  if (status >= 500) {
    console.error(err.stack || err)
  }
  let message = "The request could not be completed."
  if (status === 404) {
    message = err.message
  } else if (err.code === "EBADCSRFTOKEN") {
    message = "The form has expired. Go back to the app and sign in again."
  }
  res.status(status).render("error", { title: "Error", message })
})

const listenOn = Number(process.env.PORT || 3000)
app.listen(listenOn, () => {
  console.log(`Listening on http://0.0.0.0:${listenOn}`)
})
