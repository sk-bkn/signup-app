const express = require("express");
const crypto = require("crypto");
const path = require("path");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize SQLite database
const db = new Database(path.join(__dirname, "accounts.db"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    project_name TEXT NOT NULL,
    project_type TEXT NOT NULL,
    success_metric TEXT NOT NULL,
    goal_target TEXT NOT NULL,
    target_date TEXT NOT NULL,
    start_value TEXT NOT NULL,
    end_value TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

app.use(express.json());

// Serve login page as the landing page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.use(express.static(path.join(__dirname, "public")));

// Hash password with salt
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

// Create account endpoint
app.post("/api/create-account", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt);

  try {
    db.prepare("INSERT INTO accounts (email, password_hash, salt) VALUES (?, ?, ?)").run(
      email.toLowerCase().trim(),
      passwordHash,
      salt
    );
    res.json({ success: true, message: "Account created successfully!" });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// Login endpoint
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const account = db.prepare("SELECT * FROM accounts WHERE email = ?").get(email.toLowerCase().trim());

  if (!account) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const passwordHash = hashPassword(password, account.salt);

  if (passwordHash !== account.password_hash) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  res.json({ success: true });
});

// Change password endpoint
app.post("/api/change-password", (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters." });
  }

  const account = db.prepare("SELECT * FROM accounts WHERE email = ?").get(email.toLowerCase().trim());

  if (!account) {
    return res.status(401).json({ error: "Account not found." });
  }

  const currentHash = hashPassword(currentPassword, account.salt);
  if (currentHash !== account.password_hash) {
    return res.status(401).json({ error: "Current password is incorrect." });
  }

  const newSalt = crypto.randomBytes(16).toString("hex");
  const newHash = hashPassword(newPassword, newSalt);

  db.prepare("UPDATE accounts SET password_hash = ?, salt = ? WHERE email = ?").run(
    newHash, newSalt, email.toLowerCase().trim()
  );

  res.json({ success: true, message: "Password changed successfully!" });
});

// Create project endpoint
app.post("/api/projects", (req, res) => {
  const { email, projectName, projectType, successMetric, goalTarget, targetDate, startValue, endValue } = req.body;

  if (!email || !projectName || !projectType || !successMetric || !goalTarget || !targetDate || !startValue || !endValue) {
    return res.status(400).json({ error: "All fields are required." });
  }

  db.prepare(`INSERT INTO projects (email, project_name, project_type, success_metric, goal_target, target_date, start_value, end_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    email.toLowerCase().trim(), projectName, projectType, successMetric, goalTarget, targetDate, startValue, endValue
  );

  res.json({ success: true });
});

// Get projects endpoint
app.get("/api/projects", (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  const projects = db.prepare("SELECT * FROM projects WHERE email = ? ORDER BY created_at DESC").all(email.toLowerCase().trim());
  res.json(projects);
});

// Update project endpoint
app.put("/api/projects/:id", (req, res) => {
  const { id } = req.params;
  const { projectName, projectType, successMetric, goalTarget, targetDate, startValue, endValue } = req.body;

  if (!projectName || !projectType || !successMetric || !goalTarget || !targetDate || !startValue || !endValue) {
    return res.status(400).json({ error: "All fields are required." });
  }

  db.prepare(`UPDATE projects SET project_name = ?, project_type = ?, success_metric = ?, goal_target = ?, target_date = ?, start_value = ?, end_value = ? WHERE id = ?`).run(
    projectName, projectType, successMetric, goalTarget, targetDate, startValue, endValue, id
  );

  res.json({ success: true });
});

// Delete project endpoint
app.delete("/api/projects/:id", (req, res) => {
  db.prepare("DELETE FROM projects WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
