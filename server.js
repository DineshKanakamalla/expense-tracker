const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const path = require('path');
const { db, CATEGORIES, hashPassword, comparePassword, validatePassword } = require('./database');

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

app.set('trust proxy', 1);

app.use(session({
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

// --- Rate limiter (in-memory) ---
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

// --- Origin/Referer CSRF check for state-changing API routes ---
const trustedOrigins = process.env.TRUSTED_ORIGINS
  ? process.env.TRUSTED_ORIGINS.split(',').map(s => s.trim())
  : [];

function csrfCheck(req, res, next) {
  if (req.method === 'GET') return next();
  const origin = req.get('Origin');
  const referer = req.get('Referer');
  const header = origin || referer;
  if (!header) return next();
  const host = req.get('X-Forwarded-Host') || req.get('Host');
  try {
    const url = new URL(header);
    if (url.host === host || trustedOrigins.includes(url.origin)) return next();
  } catch {}
  res.status(403).json({ error: 'CSRF check failed' });
}

app.use('/api/', csrfCheck);

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (!req.session || !req.session.authenticated) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return req.path === '/' ? res.sendFile(path.join(__dirname, 'public', 'login.html')) : next();
  }
  const user = db.prepare('SELECT session_token FROM users WHERE id = ?').get(req.session.userId);
  if (!user || req.session.sessionToken !== user.session_token) {
    req.session.destroy(() => {
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Session expired — login elsewhere' });
      }
      res.sendFile(path.join(__dirname, 'public', 'login.html'));
    });
    return;
  }
  next();
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

// --- Public auth routes ---
app.post('/api/login', loginRateLimit, (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (username.length > 50 || password.length > 128) {
    return res.status(400).json({ error: 'Input too long' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !comparePassword(password, user.password_hash)) {
    recordLoginFailure(ip);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginAttempts.delete(`login:${ip}`);
  const token = randomToken();
  db.prepare('UPDATE users SET session_token = ? WHERE id = ?').run(token, user.id);
  req.session.authenticated = true;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.sessionToken = token;
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  if (req.session && req.session.userId) {
    db.prepare('UPDATE users SET session_token = \'\' WHERE id = ?').run(req.session.userId);
  }
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.json({ authenticated: true, username: req.session.username });
  }
  res.json({ authenticated: false });
});

// --- Protected routes ---
app.use(requireAuth);

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/change-password', (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
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
  db.prepare('UPDATE users SET password_hash = ?, session_token = ? WHERE id = ?')
    .run(hashPassword(newPassword), '', req.session.userId);
  req.session.destroy(() => res.json({ success: true, redirect: '/login.html' }));
});

app.get('/api/categories', (req, res) => {
  res.json(CATEGORIES);
});

app.get('/api/expenses', (req, res) => {
  const { month, year } = req.query;
  let rows;
  if (month && year) {
    rows = db.prepare(
      `SELECT * FROM expenses
       WHERE strftime('%m', date) = ? AND strftime('%Y', date) = ?
       ORDER BY date DESC, id DESC`
    ).all(month.padStart(2, '0'), year);
  } else {
    rows = db.prepare('SELECT * FROM expenses ORDER BY date DESC, id DESC').all();
  }
  res.json(rows);
});

app.post('/api/expenses', (req, res) => {
  const error = validateExpense(req.body);
  if (error) return res.status(400).json({ error });

  const { amount, category, description, date } = req.body;
  const stmt = db.prepare(
    'INSERT INTO expenses (amount, category, description, date) VALUES (?, ?, ?, ?)'
  );
  const result = stmt.run(amount, category, (description || '').slice(0, 200), date);
  res.status(201).json({ id: result.lastInsertRowid });
});

app.put('/api/expenses/:id', (req, res) => {
  const error = validateExpense(req.body);
  if (error) return res.status(400).json({ error });

  const { amount, category, description, date } = req.body;
  const stmt = db.prepare(
    `UPDATE expenses SET amount = ?, category = ?, description = ?, date = ?
     WHERE id = ?`
  );
  const result = stmt.run(amount, category, (description || '').slice(0, 200), date, req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Expense not found' });
  res.json({ success: true });
});

app.delete('/api/expenses/:id', (req, res) => {
  const result = db.prepare('DELETE FROM expenses WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Expense not found' });
  res.json({ success: true });
});

app.get('/api/summary', (req, res) => {
  const { year } = req.query;
  const y = year || new Date().getFullYear().toString();

  const rows = db.prepare(
    `SELECT category, strftime('%m', date) as month, SUM(amount) as total
     FROM expenses
     WHERE strftime('%Y', date) = ?
     GROUP BY category, month
     ORDER BY month, category`
  ).all(y);

  res.json(rows);
});

// --- Centralized error handler ---
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Expense tracker running at http://localhost:${PORT}`);
});
