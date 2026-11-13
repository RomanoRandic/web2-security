const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ENTITIES[c]);


function page(req, title, body) {
  const { xss_vulnerable: xss, sde_vulnerable: sde } = req.settings;
  const who = req.user ? `prijavljen kao <b>${esc(req.user.username)}</b>` : 'niste prijavljeni';
  const msg = req.query.msg ? `<p class="msg">${esc(req.query.msg)}</p>` : '';

  return `<!doctype html>
<html lang="hr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 1rem; line-height: 1.4; }
  nav { display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }
  .box { border: 1px solid #ccc; border-radius: 6px; padding: .75rem 1rem; margin: 1rem 0; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row form { display: grid; gap: .4rem; min-width: 220px; }
  .bad { color: #b00020; }
  .good { color: #087f23; }
  .msg { background: #fff3cd; padding: .5rem; }
  table { border-collapse: collapse; width: 100%; font-size: .8rem; }
  td, th { border: 1px solid #ccc; padding: 4px; text-align: left; word-break: break-all; }
  code { background: #f2f2f2; padding: 0 3px; }
  .sql { display: grid; gap: .5rem; }
  .sql textarea { font-family: monospace; background: #1e1e1e; color: #d4d4d4; border: none; border-radius: 6px; padding: .6rem; resize: none; }
  .sql button { justify-self: start; }
</style>
</head>
<body>
<nav>
  <a href="/">Početna</a> <a href="/xss">XSS</a> <a href="/sde">Osjetljivi podaci</a>
  <span>${who}</span>
</nav>
<form class="box" method="post" action="/settings">
  <input type="hidden" name="back" value="${esc(req.path)}">
  <label><input type="checkbox" name="xss" ${xss ? 'checked' : ''}> XSS ranjivost uključena</label>
  <label><input type="checkbox" name="sde" ${sde ? 'checked' : ''}> Izlaganje osjetljivih podataka uključeno</label>
  <button>Spremi</button>
</form>
${msg}
<h1>${esc(title)}</h1>
${body}
</body>
</html>`;
}

module.exports = { esc, page };
