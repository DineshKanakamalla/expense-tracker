const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  family: 4,
});

pool.on('error', (err) => {
  console.error('Unexpected pool error:', err);
  process.exit(1);
});

const SALT_ROUNDS = 10;

function hashPassword(password) {
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

function comparePassword(password, hash) {
  return bcrypt.compareSync(password, hash);
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

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      session_token TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id SERIAL PRIMARY KEY,
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      description TEXT DEFAULT '',
      date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('\x1b[31m%s\x1b[0m', 'FATAL: ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set.');
    process.exit(1);
  }

  const existing = await pool.query('SELECT id FROM users WHERE username = $1', [ADMIN_USERNAME]);
  if (existing.rows.length === 0) {
    const h = hashPassword(ADMIN_PASSWORD);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [ADMIN_USERNAME, h]);
    console.log(`Default user "${ADMIN_USERNAME}" created`);
  }
}

module.exports = { pool, initDB, CATEGORIES, hashPassword, comparePassword, validatePassword };
