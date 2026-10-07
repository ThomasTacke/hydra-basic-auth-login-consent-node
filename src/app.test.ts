import express from "express";
import path from "path";

const app = express();

// Serve static assets
app.use(express.static(path.join(__dirname, "..", "public")));

// Set Pug as the view engine
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "..", "views"));

app.get("/", (req, res) => {
  res.render("index", {
    challenge: "TEST_CHALLENGE",
    csrfToken: "FAKE_CSRF",
    error: null
  });
});

// Example route for login
app.get("/login", (req, res) => {
  res.render("login", {
    challenge: "TEST_CHALLENGE",
    csrfToken: "FAKE_CSRF",
    error: null
  });
});

// Example route for consent
app.get("/consent", (req, res) => {
  res.render("consent", {
    challenge: "TEST_CHALLENGE",
    requestedScopes: ["openid", "profile", "email"],
    client: { client_name: "Immich Test App" }
  });
});

app.listen(3000, () => console.log("Preview server running on http://localhost:3000"));
