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
      role TEXT DEFAULT 'user',
      session_token TEXT DEFAULT '',
      session_expires_at BIGINT,
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
      user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS session_expires_at BIGINT');
  await pool.query(`DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='session_expires_at' AND data_type='timestamp without time zone') THEN
      ALTER TABLE users ALTER COLUMN session_expires_at TYPE BIGINT USING EXTRACT(EPOCH FROM session_expires_at)::bigint * 1000;
    END IF;
  END $$;`);
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'");
  await pool.query('ALTER TABLE expenses ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)');

  const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('\x1b[31m%s\x1b[0m', 'FATAL: ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set.');
    process.exit(1);
  }

  const existing = await pool.query('SELECT id FROM users WHERE username = $1', [ADMIN_USERNAME]);
  if (existing.rows.length === 0) {
    const h = hashPassword(ADMIN_PASSWORD);
    await pool.query('INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)', [ADMIN_USERNAME, h, 'admin']);
    console.log(`Default admin user "${ADMIN_USERNAME}" created`);
  } else {
    await pool.query('UPDATE users SET role = $1 WHERE username = $2', ['admin', ADMIN_USERNAME]);
  }

  const adminRow = await pool.query('SELECT id FROM users WHERE username = $1', [ADMIN_USERNAME]);
  const adminId = adminRow.rows[0].id;
  await pool.query('UPDATE expenses SET user_id = $1 WHERE user_id IS NULL', [adminId]);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE)
  `);
  await pool.query(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'session_pkey') THEN
      ALTER TABLE "session" ADD CONSTRAINT session_pkey PRIMARY KEY ("sid");
    END IF;
  END $$;`);
  await pool.query('CREATE INDEX IF NOT EXISTS session_expire_idx ON "session" ("expire")');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses (date)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_expenses_user_id ON expenses (user_id)');
}

module.exports = { pool, initDB, CATEGORIES, hashPassword, comparePassword, validatePassword };
