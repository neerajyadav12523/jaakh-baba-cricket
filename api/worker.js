// Jaakh Baba Cricket Pratiyogita: team registration API (Cloudflare Worker + D1).
//
// Public
//   GET  /teams                  approved teams (no phone, no PIN) + places left
//   POST /register               {name, village, captain, phone} -> pending team
// Captain (approved team + PIN; 5 wrong PINs lock editing for 15 minutes)
//   POST /captain/login          {id, pin} -> the team and its players
//   POST /captain/players        {id, pin, players: [{name, phone}]} -> saves the squad (max 15; a mobile can be in only one team)
// Admin (header "Authorization: Bearer <GitHub token with write access to GITHUB_REPO>", or the optional ADMIN_KEY)
//   GET  /admin/teams            every team incl. phone numbers
//   POST /admin/status           {id, status: "approved" | "rejected" | "pending"}; first approval returns a new 6-digit PIN
//   POST /admin/newpin           {id} -> replaces the captain PIN and returns it (to send again on WhatsApp)
//   POST /admin/delete           {id}
//   POST /admin/update           {id, name?, village?, captain?, phone?, players?} -> edit any team
//
// Bindings (wrangler.toml): DB (D1). Secrets: PIN_PEPPER, optional ADMIN_KEY. Vars: ALLOWED_ORIGINS, MAX_TEAMS, GITHUB_REPO.

const LIMITS = { text: 40, phoneDigits: 10, pinDigits: 6, regsPerIpPerHour: 5, maxPlayers: 15, pinTries: 5, lockMinutes: 15 };

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      const res = await route(request, env);
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (err) {
      return json({ error: 'server_error' }, 500, cors);
    }
  }
};

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const m = request.method;

  if (m === 'GET' && path === '/teams') return publicTeams(env);
  if (m === 'POST' && path === '/register') return register(request, env);
  if (m === 'POST' && path === '/captain/login') return captainLogin(request, env);
  if (m === 'POST' && path === '/captain/players') return captainPlayers(request, env);

  if (path.startsWith('/admin/')) {
    if (!(await isAdmin(request, env))) return json({ error: 'not_admin' }, 401);
    if (m === 'GET' && path === '/admin/teams') return adminTeams(env);
    if (m === 'POST' && path === '/admin/status') return adminStatus(request, env);
    if (m === 'POST' && path === '/admin/newpin') return adminNewPin(request, env);
    if (m === 'POST' && path === '/admin/delete') return adminDelete(request, env);
    if (m === 'POST' && path === '/admin/update') return adminUpdate(request, env);
  }
  return json({ error: 'not_found' }, 404);
}

/* ---------- public ---------- */

async function publicTeams(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, name, village, captain, players FROM teams WHERE status = 'approved' ORDER BY created_at"
  ).all();
  const max = maxTeams(env);
  const teams = results.map(r => ({ id: r.id, name: r.name, village: r.village, captain: r.captain, players: publicPlayers(r.players) }));
  return json({ teams, approved: teams.length, max, open: teams.length < max }, 200, { 'Cache-Control': 'public, max-age=30' });
}

async function register(request, env) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);
  const name = cleanText(body.name), village = cleanText(body.village), captain = cleanText(body.captain);
  const phone = String(body.phone || '').replace(/\D/g, '').slice(-LIMITS.phoneDigits);

  const missing = [];
  if (name.length < 2) missing.push('name');
  if (village.length < 2) missing.push('village');
  if (captain.length < 2) missing.push('captain');
  if (phone.length !== LIMITS.phoneDigits) missing.push('phone');
  if (missing.length) return json({ error: 'invalid', fields: missing }, 400);

  if ((await countStatus(env, 'approved')) >= maxTeams(env)) return json({ error: 'full' }, 409);

  const ipHash = await sha256Hex((request.headers.get('CF-Connecting-IP') || 'unknown') + '|' + env.PIN_PEPPER);
  const hourAgo = new Date(Date.now() - 3600e3).toISOString();
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM teams WHERE ip_hash = ? AND created_at > ?').bind(ipHash, hourAgo).first();
  if (recent.n >= LIMITS.regsPerIpPerHour) return json({ error: 'too_many' }, 429);

  const taken = await env.DB.prepare("SELECT id FROM teams WHERE lower(name) = lower(?) AND status != 'rejected'").bind(name).first();
  if (taken) return json({ error: 'name_taken' }, 409);

  const id = 't' + Date.now().toString(36) + randomHex(3);
  const now = new Date().toISOString();
  try {
    await env.DB.prepare(
      "INSERT INTO teams (id, name, village, captain, phone, status, players, created_at, updated_at, ip_hash) VALUES (?, ?, ?, ?, ?, 'pending', '[]', ?, ?, ?)"
    ).bind(id, name, village, captain, phone, now, now, ipHash).run();
  } catch (e) {
    if (String(e).includes('UNIQUE')) return json({ error: 'name_taken' }, 409);
    throw e;
  }
  return json({ ok: true, id, status: 'pending' }, 201);
}

/* ---------- captain ---------- */

/* Checks the PIN for an approved team. Returns {team} or {res} (an error response to send back). */
async function checkCaptain(env, id, pin) {
  if (!id || !/^\d{6}$/.test(String(pin || ''))) return { res: json({ error: 'wrong_pin' }, 401) };
  const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(id).first();
  if (!team || team.status !== 'approved' || !team.pin_hash) return { res: json({ error: 'not_approved' }, 403) };
  if (team.locked_until && team.locked_until > new Date().toISOString()) {
    return { res: json({ error: 'locked', until: team.locked_until }, 429) };
  }
  const hash = await hmacHex(env.PIN_PEPPER, team.pin_salt + pin);
  if (hash !== team.pin_hash) {
    const fails = team.fail_count + 1;
    const lock = fails >= LIMITS.pinTries ? new Date(Date.now() + LIMITS.lockMinutes * 60e3).toISOString() : null;
    await env.DB.prepare('UPDATE teams SET fail_count = ?, locked_until = ? WHERE id = ?').bind(lock ? 0 : fails, lock, id).run();
    return { res: json(lock ? { error: 'locked', until: lock } : { error: 'wrong_pin', triesLeft: LIMITS.pinTries - fails }, lock ? 429 : 401) };
  }
  if (team.fail_count || team.locked_until) await env.DB.prepare('UPDATE teams SET fail_count = 0, locked_until = NULL WHERE id = ?').bind(id).run();
  return { team };
}

function captainView(t) {
  return { id: t.id, name: t.name, village: t.village, captain: t.captain, players: parsePlayers(t.players), max: LIMITS.maxPlayers };
}

async function captainLogin(request, env) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);
  const c = await checkCaptain(env, body.id, body.pin);
  return c.res || json({ ok: true, team: captainView(c.team) });
}

async function captainPlayers(request, env) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);
  const c = await checkCaptain(env, body.id, body.pin);
  if (c.res) return c.res;
  const players = cleanPlayers(body.players);
  if (players.error) return json(players, 400);
  const clash = await phoneClash(env, body.id, players);
  if (clash) return json(clash, 409);
  await env.DB.prepare('UPDATE teams SET players = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(players), new Date().toISOString(), body.id).run();
  return json({ ok: true, team: captainView({ ...c.team, players: JSON.stringify(players) }) });
}

/* Player list rules: each player is {name, phone}. Names 2-40 characters and unique in the team,
   a 10-digit mobile for everyone, no mobile twice in the team, at most 15 players. */
function cleanPlayers(list) {
  if (!Array.isArray(list)) return { error: 'bad_players' };
  const out = [], seenName = new Set(), seenPhone = new Set();
  for (const p of list) {
    const name = cleanText(p && typeof p === 'object' ? p.name : p);
    if (name.length < 2) return { error: 'bad_player_name', name };
    const phone = String((p && p.phone) || '').replace(/\D/g, '').slice(-LIMITS.phoneDigits);
    if (phone.length !== LIMITS.phoneDigits) return { error: 'bad_player_phone', name };
    if (seenName.has(name.toLowerCase())) return { error: 'duplicate_player', name };
    if (seenPhone.has(phone)) return { error: 'duplicate_phone', name, phone };
    seenName.add(name.toLowerCase());
    seenPhone.add(phone);
    out.push({ name, phone });
  }
  if (out.length > LIMITS.maxPlayers) return { error: 'too_many_players', max: LIMITS.maxPlayers };
  return out;
}

/* A player's mobile may belong to only one team. Returns an error body naming the other team, or null. */
async function phoneClash(env, teamId, players) {
  const { results } = await env.DB.prepare("SELECT name, players FROM teams WHERE id != ? AND status != 'rejected'").bind(teamId).all();
  const owner = new Map();
  for (const t of results) for (const p of parsePlayers(t.players)) if (p.phone) owner.set(p.phone, t.name);
  for (const p of players) {
    if (owner.has(p.phone)) return { error: 'phone_in_other_team', name: p.name, phone: p.phone, team: owner.get(p.phone) };
  }
  return null;
}

/* Public lists show player names only; mobiles stay with the captain and the admin */
function publicPlayers(s) { return parsePlayers(s).map(p => ({ name: p.name })); }

/* ---------- admin ---------- */

async function adminTeams(env) {
  const { results } = await env.DB.prepare(
    'SELECT id, name, village, captain, phone, status, players, created_at, updated_at, (pin_hash IS NOT NULL) AS has_pin FROM teams ORDER BY created_at'
  ).all();
  return json({ teams: results.map(r => ({ ...r, has_pin: !!r.has_pin, players: parsePlayers(r.players) })), max: maxTeams(env) }, 200, { 'Cache-Control': 'no-store' });
}

async function adminStatus(request, env) {
  const body = await readJson(request);
  const status = body && body.status;
  if (!body || !body.id || !['approved', 'rejected', 'pending'].includes(status)) return json({ error: 'bad_request' }, 400);
  const team = await env.DB.prepare('SELECT id, name, status, pin_hash FROM teams WHERE id = ?').bind(body.id).first();
  if (!team) return json({ error: 'not_found' }, 404);
  if (status === 'approved' && team.status !== 'approved' && (await countStatus(env, 'approved')) >= maxTeams(env)) {
    return json({ error: 'full' }, 409);
  }
  if (status !== 'rejected' && team.status === 'rejected') {
    const clash = await env.DB.prepare("SELECT id FROM teams WHERE lower(name) = lower(?) AND status != 'rejected' AND id != ?").bind(team.name, team.id).first();
    if (clash) return json({ error: 'name_taken' }, 409);
  }
  await env.DB.prepare('UPDATE teams SET status = ?, updated_at = ? WHERE id = ?').bind(status, new Date().toISOString(), body.id).run();
  // First approval creates the captain PIN and returns it once so the admin can send it on WhatsApp
  const pin = status === 'approved' && !team.pin_hash ? await setNewPin(env, body.id) : undefined;
  return json({ ok: true, id: body.id, status, pin });
}

async function adminNewPin(request, env) {
  const body = await readJson(request);
  if (!body || !body.id) return json({ error: 'bad_request' }, 400);
  const team = await env.DB.prepare('SELECT id, status FROM teams WHERE id = ?').bind(body.id).first();
  if (!team) return json({ error: 'not_found' }, 404);
  if (team.status !== 'approved') return json({ error: 'not_approved' }, 409);
  return json({ ok: true, id: body.id, pin: await setNewPin(env, body.id) });
}

async function adminDelete(request, env) {
  const body = await readJson(request);
  if (!body || !body.id) return json({ error: 'bad_request' }, 400);
  await env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(body.id).run();
  return json({ ok: true, id: body.id });
}

async function adminUpdate(request, env) {
  const body = await readJson(request);
  if (!body || !body.id) return json({ error: 'bad_request' }, 400);
  const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(body.id).first();
  if (!team) return json({ error: 'not_found' }, 404);
  const next = { name: team.name, village: team.village, captain: team.captain, phone: team.phone, players: team.players };
  for (const k of ['name', 'village', 'captain']) {
    if (body[k] !== undefined) {
      const v = cleanText(body[k]);
      if (v.length < 2) return json({ error: 'invalid', fields: [k] }, 400);
      next[k] = v;
    }
  }
  if (body.phone !== undefined) {
    const p = String(body.phone).replace(/\D/g, '').slice(-LIMITS.phoneDigits);
    if (p.length !== LIMITS.phoneDigits) return json({ error: 'invalid', fields: ['phone'] }, 400);
    next.phone = p;
  }
  if (body.players !== undefined) {
    const players = cleanPlayers(body.players);
    if (players.error) return json(players, 400);
    const clash = await phoneClash(env, team.id, players);
    if (clash) return json(clash, 409);
    next.players = JSON.stringify(players);
  }
  if (next.name.toLowerCase() !== team.name.toLowerCase() && team.status !== 'rejected') {
    const clash = await env.DB.prepare("SELECT id FROM teams WHERE lower(name) = lower(?) AND status != 'rejected' AND id != ?").bind(next.name, team.id).first();
    if (clash) return json({ error: 'name_taken' }, 409);
  }
  await env.DB.prepare('UPDATE teams SET name = ?, village = ?, captain = ?, phone = ?, players = ?, updated_at = ? WHERE id = ?')
    .bind(next.name, next.village, next.captain, next.phone, next.players, new Date().toISOString(), team.id).run();
  return json({ ok: true, id: team.id });
}

/* Stores only a salted HMAC of the PIN and clears any wrong-PIN lock-out */
async function setNewPin(env, id) {
  const pin = randomPin(LIMITS.pinDigits);
  const salt = randomHex(16);
  const hash = await hmacHex(env.PIN_PEPPER, salt + pin);
  await env.DB.prepare('UPDATE teams SET pin_salt = ?, pin_hash = ?, fail_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?')
    .bind(salt, hash, new Date().toISOString(), id).run();
  return pin;
}

/* ---------- helpers ---------- */

function maxTeams(env) { return Number(env.MAX_TEAMS || 32); }

async function countStatus(env, status) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM teams WHERE status = ?').bind(status).first();
  return r.n;
}

function cleanText(v) { return String(v || '').replace(/[\u0000-\u001f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, LIMITS.text); }

function parsePlayers(s) { try { const a = JSON.parse(s || '[]'); return Array.isArray(a) ? a : []; } catch (e) { return []; } }

async function readJson(request) {
  try { const b = await request.json(); return b && typeof b === 'object' ? b : null; } catch (e) { return null; }
}

// Admin = the same GitHub token the owner uses for sponsors: it must have write (push) access to
// GITHUB_REPO. An optional ADMIN_KEY secret also works. Good answers are cached for 5 minutes.
const adminCache = new Map();
async function isAdmin(request, env) {
  const got = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!got) return false;
  const digest = await sha256Hex(got);
  if (env.ADMIN_KEY) {
    // compare digests so response time does not reveal how much of the key matched
    const want = await sha256Hex(env.ADMIN_KEY);
    let diff = 0;
    for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ digest.charCodeAt(i);
    if (diff === 0) return true;
  }
  const cached = adminCache.get(digest);
  if (cached && cached > Date.now()) return true;
  if (!env.GITHUB_REPO) return false;
  const r = await fetch('https://api.github.com/repos/' + env.GITHUB_REPO, {
    headers: { 'Authorization': 'Bearer ' + got, 'Accept': 'application/vnd.github+json', 'User-Agent': 'jaakh-baba-api' }
  });
  if (!r.ok) return false;
  const repo = await r.json();
  const ok = !!(repo.permissions && repo.permissions.push);
  if (ok) adminCache.set(digest, Date.now() + 5 * 60e3);
  return ok;
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const h = { 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Vary': 'Origin' };
  if (allowed.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } });
}

function randomPin(digits) {
  // rejection sampling keeps every PIN equally likely
  const max = 10 ** digits, limit = Math.floor(0xffffffff / max) * max;
  let n;
  do { n = crypto.getRandomValues(new Uint32Array(1))[0]; } while (n >= limit);
  return String(n % max).padStart(digits, '0');
}

function randomHex(bytes) { return [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join(''); }

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(key, text) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(text));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
}
