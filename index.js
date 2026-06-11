const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("./database");

const app = express();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "hershield_secret",
    resave: false,
    saveUninitialized: false
  })
);

// ---------------- HOME ----------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------------- LOGIN PAGE ----------------
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// ---------------- REGISTER PAGE ----------------
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

// ---------------- DASHBOARD ----------------
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ---------------- ADMIN CHECK ----------------
function isAdmin(req) {
  return req.session.user === "admin";
}

// ---------------- ADMIN PANEL ----------------
app.get("/admin", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/dashboard");

  db.all("SELECT id, username FROM users", [], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.send("Error loading users");
    }

    let html = `
      <h1>Admin Panel</h1>
      <h3>User Management</h3>

      <table border="1" style="margin:auto; width:60%; text-align:center;">
        <tr>
          <th>ID</th>
          <th>Username</th>
          <th>Action</th>
        </tr>
    `;

    rows.forEach((user) => {
      html += `
        <tr>
          <td>${user.id}</td>
          <td>${user.username}</td>
          <td>
            <a href="/delete-user/${user.id}">
              <button style="background:red;color:white;">Delete</button>
            </a>
          </td>
        </tr>
      `;
    });

    html += `
      </table>
      <br>
      <a href="/dashboard">Back</a>
    `;

    res.send(html);
  });
});

// ---------------- DELETE USER ----------------
app.get("/delete-user/:id", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/dashboard");

  db.run(
    "DELETE FROM users WHERE id = ?",
    [req.params.id],
    (err) => {
      if (err) console.error(err.message);
      res.redirect("/admin");
    }
  );
});

// ---------------- REGISTER ----------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed],
      (err) => {
        if (err) {
          console.error(err.message);
          return res.redirect("/register");
        }

        res.redirect("/login");
      }
    );
  } catch (err) {
    console.error(err.message);
    res.redirect("/register");
  }
});

// ---------------- LOGIN ----------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err || !user) return res.redirect("/login");

      try {
        const match = await bcrypt.compare(password, user.password);

        if (match) {
          req.session.user = user.username;
          return res.redirect("/dashboard");
        }

        return res.redirect("/login");
      } catch (err) {
        console.error(err.message);
        return res.redirect("/login");
      }
    }
  );
});

// ---------------- LOGOUT ----------------
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err.message);
    res.redirect("/login");
  });
});

// ---------------- START SERVER ----------------
app.listen(3000, () => {
  console.log("HerShield running on http://localhost:3000");
});