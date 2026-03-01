const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize PostgreSQL database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      project_name TEXT NOT NULL,
      project_type TEXT NOT NULL,
      success_metric TEXT NOT NULL,
      goal_target TEXT NOT NULL,
      target_date TEXT NOT NULL,
      start_value TEXT NOT NULL,
      current_value TEXT NOT NULL DEFAULT '',
      end_value TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Add current_value column if it doesn't exist (for existing tables)
  await pool.query(`
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS current_value TEXT NOT NULL DEFAULT ''
  `);
}

initDb().catch(err => console.error("DB init error:", err));

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
app.post("/api/create-account", async (req, res) => {
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
    await pool.query(
      "INSERT INTO accounts (email, password_hash, salt) VALUES ($1, $2, $3)",
      [email.toLowerCase().trim(), passwordHash, salt]
    );
    res.json({ success: true, message: "Account created successfully!" });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// Login endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const result = await pool.query("SELECT * FROM accounts WHERE email = $1", [email.toLowerCase().trim()]);
  const account = result.rows[0];

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
app.post("/api/change-password", async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters." });
  }

  const result = await pool.query("SELECT * FROM accounts WHERE email = $1", [email.toLowerCase().trim()]);
  const account = result.rows[0];

  if (!account) {
    return res.status(401).json({ error: "Account not found." });
  }

  const currentHash = hashPassword(currentPassword, account.salt);
  if (currentHash !== account.password_hash) {
    return res.status(401).json({ error: "Current password is incorrect." });
  }

  const newSalt = crypto.randomBytes(16).toString("hex");
  const newHash = hashPassword(newPassword, newSalt);

  await pool.query(
    "UPDATE accounts SET password_hash = $1, salt = $2 WHERE email = $3",
    [newHash, newSalt, email.toLowerCase().trim()]
  );

  res.json({ success: true, message: "Password changed successfully!" });
});

// Create project endpoint
app.post("/api/projects", async (req, res) => {
  const { email, projectName, projectType, successMetric, goalTarget, targetDate, startValue, currentValue, endValue } = req.body;

  if (!email || !projectName || !projectType || !successMetric || !goalTarget || !targetDate || !startValue || !endValue) {
    return res.status(400).json({ error: "All fields are required." });
  }

  await pool.query(
    `INSERT INTO projects (email, project_name, project_type, success_metric, goal_target, target_date, start_value, current_value, end_value) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [email.toLowerCase().trim(), projectName, projectType, successMetric, goalTarget, targetDate, startValue, currentValue || "", endValue]
  );

  res.json({ success: true });
});

// Get projects endpoint
app.get("/api/projects", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  const result = await pool.query(
    "SELECT * FROM projects WHERE email = $1 ORDER BY created_at DESC",
    [email.toLowerCase().trim()]
  );
  res.json(result.rows);
});

// Update project endpoint
app.put("/api/projects/:id", async (req, res) => {
  const { id } = req.params;
  const { projectName, projectType, successMetric, goalTarget, targetDate, startValue, currentValue, endValue } = req.body;

  if (!projectName || !projectType || !successMetric || !goalTarget || !targetDate || !startValue || !endValue) {
    return res.status(400).json({ error: "All fields are required." });
  }

  await pool.query(
    `UPDATE projects SET project_name = $1, project_type = $2, success_metric = $3, goal_target = $4, target_date = $5, start_value = $6, current_value = $7, end_value = $8 WHERE id = $9`,
    [projectName, projectType, successMetric, goalTarget, targetDate, startValue, currentValue || "", endValue, id]
  );

  res.json({ success: true });
});

// Delete project endpoint
app.delete("/api/projects/:id", async (req, res) => {
  await pool.query("DELETE FROM projects WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
