const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');
const { hashPassword, checkPassword } = require('../lib/sde');
const { esc, page } = require('../lib/html');

const db = new Pool({
  connectionString: process.env.POSTGRES_URL?.split('?')[0],
  ssl: { rejectUnauthorized: false },
});

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS sec_settings (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    xss_vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
    sde_vulnerable BOOLEAN NOT NULL DEFAULT TRUE
  );
  INSERT INTO sec_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

  CREATE TABLE IF NOT EXISTS sec_users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    protected BOOLEAN NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sec_sessions (
    id TEXT PRIMARY KEY,
    user_id INT NOT NULL REFERENCES sec_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS sec_comments (
    id SERIAL PRIMARY KEY,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  ALTER TABLE sec_settings ENABLE ROW LEVEL SECURITY;
  ALTER TABLE sec_users ENABLE ROW LEVEL SECURITY;
  ALTER TABLE sec_sessions ENABLE ROW LEVEL SECURITY;
  ALTER TABLE sec_comments ENABLE ROW LEVEL SECURITY;
`;

async function setup() {
  await db.query(SCHEMA);
  await db.query(
    `INSERT INTO sec_users (username, password, protected)
     VALUES ($1, $2, FALSE), ($3, $4, TRUE)
     ON CONFLICT (username) DO NOTHING`,
    ['alice', 'alice123', 'bob', hashPassword('bob123')],
  );
}

const ready = setup();
ready.catch((err) => console.error('Setup failed:', err.message));

function getCookie(req, name) {
  const hit = (req.headers.cookie ?? '').split('; ').find((c) => c.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
}

function setSessionCookie(req, res, sid) {
  res.cookie('sid', sid, {
    httpOnly: !req.settings.xss_vulnerable,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  });
}

async function findUser(sid) {
  if (!sid) return null;
  const { rows } = await db.query(
    'SELECT u.* FROM sec_sessions s JOIN sec_users u ON u.id = s.user_id WHERE s.id = $1',
    [sid],
  );
  return rows[0] ?? null;
}

async function startSession(req, res, userId) {
  const sid = crypto.randomBytes(32).toString('hex');
  await db.query('INSERT INTO sec_sessions (id, user_id) VALUES ($1, $2)', [sid, userId]);
  setSessionCookie(req, res, sid);
}

const go = (res, path, msg) => res.redirect(msg ? `${path}?msg=${encodeURIComponent(msg)}` : path);

const app = express();
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));

app.use(async (req, res, next) => {
  await ready;
  const { rows } = await db.query('SELECT * FROM sec_settings WHERE id = 1');
  req.settings = rows[0];
  req.sid = getCookie(req, 'sid');
  req.user = await findUser(req.sid);
  if (req.user) setSessionCookie(req, res, req.sid);
  if (!req.settings.xss_vulnerable) res.set('Content-Security-Policy', "script-src 'none'");
  next();
});

app.post('/settings', async (req, res) => {
  await db.query('UPDATE sec_settings SET xss_vulnerable = $1, sde_vulnerable = $2 WHERE id = 1', [
    req.body.xss === 'on',
    req.body.sde === 'on',
  ]);
  go(res, ['/xss', '/sde'].includes(req.body.back) ? req.body.back : '/');
});

app.get('/', (req, res) => {
  const account = req.user
    ? `<form method="post" action="/logout"><button>Odjava</button></form>`
    : `<div class="row">
        <form method="post" action="/login">
          <b>Prijava</b>
          <input name="username" placeholder="korisničko ime" required>
          <input name="password" type="password" placeholder="lozinka" required>
          <button>Prijavi se</button>
        </form>
        <form method="post" action="/register">
          <b>Registracija</b>
          <input name="username" placeholder="korisničko ime" required>
          <input name="password" type="password" placeholder="lozinka" required>
          <button>Registriraj se</button>
        </form>
      </div>`;

  res.send(page(req, 'Web2 sigurnosni lab', `
    <p>Demo korisnici: <code>alice / alice123</code> i <code>bob / bob123</code>.</p>
    ${account}
    <div class="box">
      <form method="post" action="/reset"><button>Obriši komentare</button></form>
    </div>`));
});

app.post('/register', async (req, res) => {
  const { username = '', password = '' } = req.body;
  if (!username || !password) {
    return go(res, '/', 'Ispuni korisničko ime i lozinku');
  }
  const safe = !req.settings.sde_vulnerable;
  try {
    const { rows } = await db.query(
      'INSERT INTO sec_users (username, password, protected) VALUES ($1, $2, $3) RETURNING id',
      [username, safe ? hashPassword(password) : password, safe],
    );
    await startSession(req, res, rows[0].id);
    go(res, '/sde');
  } catch (err) {
    if (err.code === '23505') return go(res, '/', 'Korisničko ime je zauzeto');
    throw err;
  }
});

app.post('/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const { rows } = await db.query('SELECT * FROM sec_users WHERE username = $1', [username]);
  const user = rows[0];
  const ok = user && (user.protected ? checkPassword(password, user.password) : password === user.password);
  if (!ok) return go(res, '/', 'Pogrešno korisničko ime ili lozinka');
  await startSession(req, res, user.id);
  go(res, '/sde');
});

app.post('/logout', async (req, res) => {
  if (req.sid) await db.query('DELETE FROM sec_sessions WHERE id = $1', [req.sid]);
  res.clearCookie('sid');
  go(res, '/');
});

app.post('/reset', async (req, res) => {
  await db.query('DELETE FROM sec_comments');
  go(res, '/', 'Komentari obrisani');
});

const ATTACKS = [
  '<script>alert(document.cookie)</script>',
  '<img src="x" onerror="alert(document.cookie)">',
];

app.get('/xss', async (req, res) => {
  const comments = (await db.query('SELECT * FROM sec_comments ORDER BY id')).rows;

  const show = req.settings.xss_vulnerable ? (s) => s : esc;
  const list = comments.map((c) => `<li><b>${esc(c.author)}</b>: ${show(c.body)}</li>`).join('');
  const hints = ATTACKS.map((a) => `<li><code>${esc(a)}</code></li>`).join('');

  res.send(page(req, 'Pohranjeni XSS', `
    <form method="post" action="/comments" class="row">
      <textarea name="body" rows="3" cols="60" required placeholder="napiši komentar"></textarea>
      <button>Objavi komentar</button>
    </form>
    <h2> Primjeri napada</h2>
    <ul>${hints}</ul>
    <h2>Komentari</h2>
    <ul>${list || '<li>Još nema komentara.</li>'}</ul>`));
});

app.post('/comments', async (req, res) => {
  await db.query('INSERT INTO sec_comments (author, body) VALUES ($1, $2)', [
    req.user?.username ?? 'anonymous',
    req.body.body ?? '',
  ]);
  go(res, '/xss');
});

app.get('/sde', async (req, res) => {
  const vuln = req.settings.sde_vulnerable;
  if (!vuln) res.set('Cache-Control', 'no-store');

  let profile = '<p>Prijavi se da vidiš kako ti je lozinka spremljena.</p>';
  if (req.user) {
    const u = req.user;
    profile = `
      <p>Korisnik: <b>${esc(u.username)}</b></p>
      <p>Lozinka je spremljena kao: <code>${esc(u.password)}</code></p>`;
  }

  let dump = '';
  if (req.query.dump) {
    const { rows } = await db.query('SELECT id, username, password, protected FROM sec_users ORDER BY id');
    dump = `<table>
      <tr><th>id</th><th>username</th><th>password</th><th>protected</th></tr>
      ${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.username)}</td><td>${esc(r.password)}</td><td>${r.protected}</td></tr>`).join('')}
    </table>`;
  }

  res.send(page(req, 'Izlaganje osjetljivih podataka', `
    <div class="box"><h2>Moj profil</h2>${profile}</div>
    <div class="box">
      <h2>Napad: SDE </h2>
      <form method="get" action="/sde" class="sql">
        <input type="hidden" name="dump" value="1">
        <textarea name="query" rows="2" readonly>SELECT * FROM sec_users</textarea>
        <button>Pokreni</button>
      </form>
      ${dump}
    </div>`));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Internal server error');
});

if (require.main === module) app.listen(process.env.PORT || 3000);

module.exports = app;
