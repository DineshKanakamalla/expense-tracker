require('express-async-errors');
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const path = require('path');
const { pool, CATEGORIES, hashPassword, comparePassword, validatePassword } = require('./database');

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('\x1b[31m%s\x1b[0m', 'FATAL: SESSION_SECRET environment variable must be set.');
  process.exit(1);
}
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

app.set('trust proxy', process.env.RENDER === 'true' ? 1 : 0);

const PgSession = require('connect-pg-simple')(session);

app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TIMEOUT_MS,
  },
}));

const loginAttempts = new Map();
setInterval(() => loginAttempts.clear(), 15 * 60 * 1000);

function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const key = `login:${ip}`;
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (entry && entry.count >= 5 && now - entry.start < 15 * 60 * 1000) {
    return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
  }
  next();
}

function recordLoginFailure(ip) {
  const key = `login:${ip}`;
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now - entry.start > 15 * 60 * 1000) {
    loginAttempts.set(key, { count: 1, start: now });
  } else {
    entry.count++;
  }
}

const trustedOrigins = process.env.TRUSTED_ORIGINS
  ? process.env.TRUSTED_ORIGINS.split(',').map(s => s.trim())
  : [];

function csrfCheck(req, res, next) {
  if (req.method === 'GET') return next();
  const origin = req.get('Origin');
  const referer = req.get('Referer');
  const header = origin || referer;
  if (!header) {
    return res.status(403).json({ error: 'CSRF check failed — missing Origin/Referer' });
  }
  const host = req.get('X-Forwarded-Host') || req.get('Host');
  try {
    const url = new URL(header);
    if (url.host === host || trustedOrigins.includes(url.origin)) return next();
  } catch {}
  res.status(403).json({ error: 'CSRF check failed' });
}

app.use('/api/', csrfCheck);

async function requireAuth(req, res, next) {
  try {
    if (!req.session || !req.session.authenticated) {
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      return req.path === '/' ? res.sendFile(path.join(__dirname, 'public', 'login.html')) : next();
    }
    const result = await pool.query(
      'SELECT session_token, session_expires_at FROM users WHERE id = $1',
      [req.session.userId]
    );
    const user = result.rows[0];
    if (!user || req.session.sessionToken !== user.session_token) {
      req.session.destroy(() => {
        if (req.path.startsWith('/api/')) {
          return res.status(401).json({ error: 'Session expired — login elsewhere' });
        }
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
      });
      return;
    }
    await pool.query(
      'UPDATE users SET session_expires_at = $1 WHERE id = $2',
      [Date.now() + SESSION_TIMEOUT_MS, req.session.userId]
    );
    next();
  } catch (err) {
    next(err);
  }
}

const validateExpense = (body) => {
  const { amount, category, description, date } = body;
  if (!amount || typeof amount !== 'number' || amount <= 0)
    return 'Amount must be a positive number';
  if (!category || !CATEGORIES.includes(category))
    return `Category must be one of: ${CATEGORIES.join(', ')}`;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date))
    return 'Date must be in YYYY-MM-DD format';
  const d = new Date(date);
  if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== date)
    return 'Date is not a valid calendar date';
  if (description && description.length > 200)
    return 'Description must be under 200 characters';
  return null;
};

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.post('/api/login', loginRateLimit, async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (username.length > 50 || password.length > 128) {
    return res.status(400).json({ error: 'Input too long' });
  }
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user || !comparePassword(password, user.password_hash)) {
    recordLoginFailure(ip);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  if (user.session_token && user.session_token.length > 0) {
    if (user.session_expires_at && Date.now() < user.session_expires_at) {
      return res.status(409).json({ error: 'User already logged in elsewhere' });
    }
    await pool.query("UPDATE users SET session_token = '' WHERE id = $1", [user.id]);
  }
  loginAttempts.delete(`login:${ip}`);
  const token = randomToken();
  const expiresAt = Date.now() + SESSION_TIMEOUT_MS;
  await pool.query(
    'UPDATE users SET session_token = $1, session_expires_at = $2 WHERE id = $3',
    [token, expiresAt, user.id]
  );
  req.session.authenticated = true;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.sessionToken = token;
  res.json({ success: true });
});

app.post('/api/logout', async (req, res) => {
  if (req.session && req.session.userId) {
    await pool.query("UPDATE users SET session_token = '', session_expires_at = NULL WHERE id = $1", [req.session.userId]);
  }
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.json({ authenticated: true, username: req.session.username });
  }
  res.json({ authenticated: false });
});

app.use(requireAuth);

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
  const user = result.rows[0];
  if (!user || !comparePassword(currentPassword, user.password_hash)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  if (comparePassword(newPassword, user.password_hash)) {
    return res.status(400).json({ error: 'New password must be different from current password' });
  }
  const validationError = validatePassword(newPassword);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }
  await pool.query(
    'UPDATE users SET password_hash = $1, session_token = $2, session_expires_at = NULL WHERE id = $3',
    [hashPassword(newPassword), '', req.session.userId]
  );
  req.session.destroy(() => res.json({ success: true, redirect: '/login.html' }));
});

app.get('/api/categories', (req, res) => {
  res.json(CATEGORIES);
});

app.get('/api/expenses', async (req, res) => {
  const { month, year } = req.query;
  let rows;
  if (month && year) {
    const start = `${year}-${month.padStart(2, '0')}-01`;
    const endDate = new Date(+year, +month, 1);
    endDate.setMonth(endDate.getMonth() + 1);
    const end = endDate.toISOString().slice(0, 10);
    const r = await pool.query(
      `SELECT id, amount, category, description, TO_CHAR(date, 'YYYY-MM-DD') as date, created_at
       FROM expenses
       WHERE date >= $1 AND date < $2
       ORDER BY date DESC, id DESC`,
      [start, end]
    );
    rows = r.rows;
  } else {
    const r = await pool.query(
      `SELECT id, amount, category, description, TO_CHAR(date, 'YYYY-MM-DD') as date, created_at
       FROM expenses ORDER BY date DESC, id DESC`
    );
    rows = r.rows;
  }
  res.json(rows);
});

app.post('/api/expenses', async (req, res) => {
  const error = validateExpense(req.body);
  if (error) return res.status(400).json({ error });

  const { amount, category, description, date } = req.body;
  const result = await pool.query(
    'INSERT INTO expenses (amount, category, description, date) VALUES ($1, $2, $3, $4) RETURNING id',
    [amount, category, (description || '').slice(0, 200), date]
  );
  res.status(201).json({ id: result.rows[0].id });
});

app.put('/api/expenses/:id', async (req, res) => {
  const error = validateExpense(req.body);
  if (error) return res.status(400).json({ error });

  const { amount, category, description, date } = req.body;
  const result = await pool.query(
    `UPDATE expenses SET amount = $1, category = $2, description = $3, date = $4
     WHERE id = $5`,
    [amount, category, (description || '').slice(0, 200), date, req.params.id]
  );
  if (result.rowCount === 0) return res.status(404).json({ error: 'Expense not found' });
  res.json({ success: true });
});

app.delete('/api/expenses/:id', async (req, res) => {
  const result = await pool.query('DELETE FROM expenses WHERE id = $1', [req.params.id]);
  if (result.rowCount === 0) return res.status(404).json({ error: 'Expense not found' });
  res.json({ success: true });
});

app.get('/api/summary', async (req, res) => {
  const { year } = req.query;
  const y = year || new Date().getFullYear().toString();
  const start = `${y}-01-01`;
  const end = `${+y + 1}-01-01`;

  const result = await pool.query(
    `SELECT category, TO_CHAR(date, 'MM') as month, SUM(amount)::float as total
     FROM expenses
     WHERE date >= $1 AND date < $2
     GROUP BY category, month
     ORDER BY month, category`,
    [start, end]
  );

  res.json(result.rows);
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const { initDB } = require('./database');

const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Expense tracker running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('\x1b[31m%s\x1b[0m', 'Failed to initialize database:', err);
  process.exit(1);
});
