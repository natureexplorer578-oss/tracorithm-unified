const express = require("express"), path = require("path"), bcrypt = require("bcryptjs");
const session = require("express-session"), PgStore = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const pool = new Pool({ connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? { rejectUnauthorized: false } : false });
const q = (s, p) => pool.query(s, p);
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(session({
  store: new PgStore({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || (() => { throw new Error("SESSION_SECRET is required"); })(),
  resave: false, saveUninitialized: false, name: "trc.sid",
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8 * 3600 * 1000 }
}));

const COMPONENTS = ["Fish Plate", "Rail Clip", "Pandrol Clip"];
const ROLES = ["admin", "inspector", "manufacturer"];
const need = (...roles) => (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: "Please sign in." });
  if (roles.length && !roles.includes(req.session.user.role) && req.session.user.role !== "admin")
    return res.status(403).json({ success: false, message: "You do not have permission." });
  next();
};
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ success: false, message: "Server error." }); });
const bad = (res, m) => res.status(400).json({ success: false, message: m });
const days = (a, b) => Math.floor((b - a) / 864e5);
const parseInst = b => { const life = Number(b.expected_life), iv = Number(b.inspect_interval), pcs = Number(b.pieces || 1);
  if (![life, iv, pcs].every(n => Number.isInteger(n) && n > 0)) return { error: "Expected life, interval and pieces must be positive whole numbers." };
  if (!b.install_date || !b.zone || !b.station) return { error: "Zone, station and installation date are required." };
  return { life, iv, pcs }; };
const today = () => { const d = new Date(); return new Date(d.getFullYear(), d.getMonth(), d.getDate()); };

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS fittings(id SERIAL PRIMARY KEY, fitting_id TEXT UNIQUE NOT NULL, component TEXT NOT NULL, manufacturer TEXT, batch TEXT,
    mfg_date DATE, supply_date DATE, warranty_months INT, status TEXT NOT NULL DEFAULT 'Manufactured', created_by INT REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS installations(fitting_id TEXT PRIMARY KEY REFERENCES fittings(fitting_id), zone TEXT, division TEXT, station TEXT, track TEXT, km TEXT,
    installed_by TEXT, install_date DATE NOT NULL, pieces INT, expected_life INT NOT NULL, inspect_interval INT NOT NULL, condition TEXT, notes TEXT);
  CREATE TABLE IF NOT EXISTS inspections(id SERIAL PRIMARY KEY, fitting_id TEXT REFERENCES fittings(fitting_id), result TEXT NOT NULL, confidence NUMERIC, by_user TEXT, at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS events(id SERIAL PRIMARY KEY, fitting_id TEXT REFERENCES fittings(fitting_id), type TEXT NOT NULL, detail TEXT, by_user TEXT, at TIMESTAMPTZ DEFAULT now());`);
  const { rows } = await q("SELECT 1 FROM users LIMIT 1");
  if (!rows.length && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD)
    await q("INSERT INTO users(username,name,password_hash,role) VALUES($1,$1,$2,'admin')", [process.env.ADMIN_USERNAME, await bcrypt.hash(process.env.ADMIN_PASSWORD, 12)]);
}
const log = (id, type, detail, user) => q("INSERT INTO events(fitting_id,type,detail,by_user) VALUES($1,$2,$3,$4)", [id, type, detail, user]);

/* ---------- auth ---------- */
app.post("/api/login", wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return bad(res, "Enter username and password.");
  const { rows } = await q("SELECT * FROM users WHERE username=$1", [String(username).trim()]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(String(password), u.password_hash))) return res.status(401).json({ success: false, message: "Invalid username or password." });
  req.session.regenerate(() => { req.session.user = { id: u.id, username: u.username, role: u.role, name: u.name };
    req.session.save(() => res.json({ success: true, user: req.session.user })); });
}));
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ success: true })));
app.get("/api/me", (req, res) => req.session.user ? res.json({ success: true, user: req.session.user }) : res.status(401).json({ success: false }));

/* ---------- users (admin) ---------- */
app.get("/api/users", need(), (req, res, next) => req.session.user.role === "admin" ? next() : res.status(403).json({ success: false, message: "Admin only." }),
  wrap(async (req, res) => res.json({ success: true, users: (await q("SELECT id,username,name,role FROM users ORDER BY id")).rows })));
app.post("/api/users", need(), (req, res, next) => req.session.user.role === "admin" ? next() : res.status(403).json({ success: false, message: "Admin only." }),
  wrap(async (req, res) => {
    const { username, name, password, role } = req.body || {};
    if (!/^[\w.-]{3,30}$/.test(username || "")) return bad(res, "Username: 3-30 letters, numbers, . _ -");
    if (!password || password.length < 8) return bad(res, "Password must be at least 8 characters.");
    if (!ROLES.includes(role)) return bad(res, "Invalid role.");
    try { await q("INSERT INTO users(username,name,password_hash,role) VALUES($1,$2,$3,$4)", [username, name || username, await bcrypt.hash(password, 12), role]); }
    catch (e) { if (e.code === "23505") return bad(res, "Username already exists."); throw e; }
    res.json({ success: true });
  }));

/* ---------- fittings ---------- */
app.post("/api/fittings", need("manufacturer"), wrap(async (req, res) => {
  const b = req.body || {}, id = String(b.fitting_id || "").trim().toUpperCase();
  if (!/^[A-Z0-9-]{3,30}$/.test(id)) return bad(res, "Fitting ID: 3-30 letters, numbers or hyphens.");
  if (!COMPONENTS.includes(b.component)) return bad(res, "Choose a valid component.");
  const w = b.warranty_months === "" || b.warranty_months == null ? null : Number(b.warranty_months);
  if (w !== null && (!Number.isInteger(w) || w < 0)) return bad(res, "Warranty must be a whole number of months.");
  let inst = null, v = null;
  if (b.installation) {
    if (!["admin", "inspector"].includes(req.session.user.role)) return res.status(403).json({ success: false, message: "Only an inspector or admin can record installation details." });
    inst = b.installation; v = parseInst(inst); if (v.error) return bad(res, v.error);
  }
  try {
    await q("INSERT INTO fittings(fitting_id,component,manufacturer,batch,mfg_date,supply_date,warranty_months,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
      [id, b.component, b.manufacturer || null, b.batch || null, b.mfg_date || null, b.supply_date || null, w, req.session.user.id]);
  } catch (e) { if (e.code === "23505") return bad(res, "This fitting ID already exists."); throw e; }
  await log(id, "Registered", `${b.component}, batch ${b.batch || "-"}`, req.session.user.username);
  if (inst) {
    await q(`INSERT INTO installations(fitting_id,zone,division,station,track,km,installed_by,install_date,pieces,expected_life,inspect_interval,condition,notes)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [id, inst.zone, inst.division, inst.station, inst.track, inst.km, inst.installed_by, inst.install_date, v.pcs, v.life, v.iv, inst.condition || "Good", inst.notes || null]);
    await q("UPDATE fittings SET status='Installed' WHERE fitting_id=$1", [id]);
    await log(id, "Installed", `${inst.station}, track ${inst.track || "-"}, km ${inst.km || "-"}`, req.session.user.username);
  }
  res.json({ success: true, fitting_id: id });
}));
app.get("/api/fittings", need(), wrap(async (req, res) => {
  const u = req.session.user, own = u.role === "manufacturer";
  const { rows } = await q(`SELECT f.*, i.install_date, i.expected_life, i.inspect_interval,
    (SELECT result FROM inspections x WHERE x.fitting_id=f.fitting_id ORDER BY at DESC LIMIT 1) AS last_result,
    (SELECT at FROM inspections x WHERE x.fitting_id=f.fitting_id ORDER BY at DESC LIMIT 1) AS last_inspected
    FROM fittings f LEFT JOIN installations i USING(fitting_id) ${own ? "WHERE f.created_by=$1" : ""} ORDER BY f.created_at DESC`, own ? [u.id] : []);
  const t = today();
  rows.forEach(r => { if (r.install_date) { const base = r.last_inspected ? new Date(r.last_inspected) : new Date(r.install_date);
    const due = new Date(base.getFullYear(), base.getMonth(), base.getDate() + r.inspect_interval); r.overdue_days = Math.max(0, days(due, t)); r.next_inspection = due.toISOString().slice(0, 10); } });
  res.json({ success: true, fittings: rows });
}));
app.get("/api/fittings/:id", need(), wrap(async (req, res) => {
  const id = req.params.id.toUpperCase(), u = req.session.user;
  const f = (await q("SELECT * FROM fittings WHERE fitting_id=$1", [id])).rows[0];
  if (!f) return res.status(404).json({ success: false, message: "Fitting not found." });
  if (u.role === "manufacturer" && f.created_by !== u.id) return res.status(403).json({ success: false, message: "Not your fitting." });
  const inst = (await q("SELECT * FROM installations WHERE fitting_id=$1", [id])).rows[0] || null;
  const insp = (await q("SELECT result,confidence,by_user,at FROM inspections WHERE fitting_id=$1 ORDER BY at DESC", [id])).rows;
  const events = (await q("SELECT type,detail,by_user,at FROM events WHERE fitting_id=$1 ORDER BY at DESC", [id])).rows;
  let schedule = null, prediction = null;
  if (inst) {
    const t = today(), start = new Date(inst.install_date), age = days(start, t), remaining = inst.expected_life - age;
    const base = insp[0] ? new Date(insp[0].at) : start, due = new Date(base.getFullYear(), base.getMonth(), base.getDate() + inst.inspect_interval), over = days(due, t);
    schedule = { next_inspection: due.toISOString().slice(0, 10), overdue_days: Math.max(0, over), status: over > 0 ? "Overdue" : over === 0 ? "Due today" : "On schedule" };
    prediction = { age_days: age, remaining_days: Math.max(0, remaining), status: remaining <= 0 ? "Expected life reached" : "Within expected life" };
  }
  res.json({ success: true, fitting: f, installation: inst, schedule, prediction, inspections: insp, events });
}));
app.post("/api/fittings/:id/install", need("inspector"), wrap(async (req, res) => {
  const id = req.params.id.toUpperCase(), b = req.body || {};
  const life = Number(b.expected_life), iv = Number(b.inspect_interval), pcs = Number(b.pieces || 1);
  if (![life, iv, pcs].every(n => Number.isInteger(n) && n > 0)) return bad(res, "Expected life, interval and pieces must be positive whole numbers.");
  if (!b.install_date || !b.zone || !b.station) return bad(res, "Zone, station and installation date are required.");
  const f = (await q("SELECT 1 FROM fittings WHERE fitting_id=$1", [id])).rows[0];
  if (!f) return res.status(404).json({ success: false, message: "Fitting not found." });
  try {
    await q(`INSERT INTO installations(fitting_id,zone,division,station,track,km,installed_by,install_date,pieces,expected_life,inspect_interval,condition,notes)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [id, b.zone, b.division, b.station, b.track, b.km, b.installed_by, b.install_date, pcs, life, iv, b.condition || "Good", b.notes || null]);
  } catch (e) { if (e.code === "23505") return bad(res, "Already installed. Reset the installation first."); throw e; }
  await q("UPDATE fittings SET status='Installed' WHERE fitting_id=$1", [id]);
  await log(id, "Installed", `${b.station}, track ${b.track || "-"}, km ${b.km || "-"}`, req.session.user.username);
  res.json({ success: true });
}));
app.post("/api/fittings/:id/reset", need("inspector"), wrap(async (req, res) => {
  const id = req.params.id.toUpperCase();   // removes installation only; manufacturing record, inspections and history stay
  const r = await q("DELETE FROM installations WHERE fitting_id=$1", [id]);
  if (!r.rowCount) return bad(res, "This fitting is not installed.");
  await q("UPDATE fittings SET status='In Stock' WHERE fitting_id=$1", [id]);
  await log(id, "Installation reset", "Installation details cleared", req.session.user.username);
  res.json({ success: true });
}));
app.post("/api/fittings/:id/inspection", need("inspector"), wrap(async (req, res) => {
  const id = req.params.id.toUpperCase(), { result, confidence } = req.body || {}, c = Number(confidence);
  if (!["GOOD", "DAMAGED"].includes(result) || !(c >= 0 && c <= 100)) return bad(res, "Invalid inspection result.");
  if (!(await q("SELECT 1 FROM fittings WHERE fitting_id=$1", [id])).rows.length) return res.status(404).json({ success: false, message: "Fitting not found." });
  await q("INSERT INTO inspections(fitting_id,result,confidence,by_user) VALUES($1,$2,$3,$4)", [id, result, c, req.session.user.username]);
  if (result === "DAMAGED") await q("UPDATE fittings SET status='Damaged' WHERE fitting_id=$1", [id]);
  await log(id, "AI inspection", `${result} (${c.toFixed(1)}% confidence)`, req.session.user.username);
  res.json({ success: true });
}));

/* ---------- analytics ---------- */
app.get("/api/analytics", need("inspector", "manufacturer"), wrap(async (req, res) => {
  const st = (await q("SELECT status, COUNT(*)::int n FROM fittings GROUP BY status")).rows;
  const ins = (await q(`SELECT COUNT(*)::int total, COUNT(*) FILTER (WHERE result='GOOD')::int good, COUNT(*) FILTER (WHERE result='DAMAGED')::int damaged FROM inspections`)).rows[0];
  const month = (await q("SELECT to_char(at,'YYYY-MM') m, COUNT(*)::int n FROM inspections GROUP BY 1 ORDER BY 1 DESC LIMIT 6")).rows.reverse();
  const batch = (await q(`SELECT COALESCE(f.batch,'(none)') batch, COUNT(*)::int inspected, COUNT(*) FILTER (WHERE i.result='DAMAGED')::int damaged FROM inspections i JOIN fittings f USING(fitting_id) GROUP BY 1 ORDER BY 3 DESC LIMIT 8`)).rows;
  res.json({ success: true, status: st, inspections: ins, monthly: month, batches: batch });
}));

/* ---------- pages ---------- */
app.use(express.static(path.join(__dirname, "public"), { index: false }));
const page = (req, res) => res.sendFile(path.join(__dirname, "public", "index.html"));
// Old per-fitting pages keep working: they now open the same fitting inside the dashboard.
[["install.html", "TRC-FP-001"], ["railclip.html", "TRC-RC-003"], ["pandrol.html", "TRC-PC-002"]].forEach(([p, id]) => app.get("/" + p, (r, s) => s.redirect("/f/" + id)));
app.get("/f/:id", page);
app.get("/", page);

init().then(() => app.listen(process.env.PORT || 5000, () => console.log("TRACORITHM running"))).catch(e => { console.error("Startup failed:", e.message); process.exit(1); });
