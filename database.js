const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

const db = new Database(path.join(__dirname, 'expenses.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    session_token TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

try { db.exec('ALTER TABLE users ADD COLUMN session_token TEXT DEFAULT \'\''); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    amount REAL NOT NULL,
    category TEXT NOT NULL,
    description TEXT DEFAULT '',
    date TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

const SALT_ROUNDS = 10;

function hashPassword(password) {
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

function comparePassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('\x1b[31m%s\x1b[0m', 'FATAL: ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set.');
  process.exit(1);
}

const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(ADMIN_USERNAME);
if (!existing) {
  const h = hashPassword(ADMIN_PASSWORD);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, h);
  console.log(`Default user "${ADMIN_USERNAME}" created`);
}

function validatePassword(password) {
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one digit';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password))
    return 'Password must contain at least one special character';
  return null;
}

const CATEGORIES = [
  'Groceries',
  'Food & Dining',
  'Transport',
  'Mobile Recharge & Bills',
  'Shopping',
  'Entertainment',
  'Healthcare',
  'Education',
  'Rent & Housing',
  'Utilities',
  'Savings & Investments',
  'Miscellaneous',
];

module.exports = { db, CATEGORIES, hashPassword, comparePassword, validatePassword };
