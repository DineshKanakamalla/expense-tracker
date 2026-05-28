# Expense Tracker

Personal UPI spending tracker with monthly category-wise summaries.

## Features

- **Add expenses** — log amount, category, date, and optional description
- **All expenses** — filterable list by month/year
- **Monthly summary** — category-wise breakdown with a horizontal bar chart
- **Single‑session auth** — login invalidates any previous session
- **Password change** — with strength validation (≥8 chars, upper, lower, digit, special)
- **Responsive design** — works on mobile and desktop

## Tech Stack

- Node.js + Express
- SQLite (better-sqlite3)
- bcrypt for password hashing
- express-session with SQLiteSessionStore
- Helmet security headers + CSP
- Rate‑limited login (5 attempts / 15 min per IP)

## Development

```bash
# install dependencies
npm install

# start the server
node server.js
```

Server listens on `http://localhost:3000`.

## Environment

Set these environment variables before starting:

| Variable        | Description                        |
|-----------------|------------------------------------|
| `SESSION_KEY`   | Secret for session cookie signing  |
| `TRUSTED_ORIGINS` | Comma‑separated origins for CSRF |

## Deployment

Deployed on [Render](https://render.com) free tier. Kept awake via UptimeRobot 5‑minute ping.

Live: https://expense-tracker-eq0o.onrender.com

Default credentials: **admin / Din@01#**
