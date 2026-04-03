require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const LICENSE_SECRET = process.env.LICENSE_SECRET || 'change_this_license_secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// ─── VERİTABANI KURULUM ─────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'mrtbot.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    user_name TEXT DEFAULT 'Anonim',
    player_id TEXT DEFAULT '',
    plan TEXT DEFAULT 'pro',
    duration_days INTEGER DEFAULT 30,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    activated_at TEXT,
    is_active INTEGER DEFAULT 1,
    notes TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS license_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    player_id TEXT,
    action TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ─── MİDDLEWARE ─────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'panel')));

// CORS - bot'un çalıştığı tüm gameforge domainleri
app.use(cors({
  origin: (origin, cb) => cb(null, true), // Tüm originlere izin ver (Chrome extension için)
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ─── YARDIMCI FONKSİYONLAR ──────────────────────────────────────────────

// Lisans anahtarı üret: MRT-XXXXX-XXXXX-XXXXX
function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segment = (len) => Array.from({length: len}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `MRT-${segment(5)}-${segment(5)}-${segment(5)}`;
}

// Bitiş tarihi hesapla
function calcExpiry(durationDays) {
  if (durationDays >= 9999) return null; // Sınırsız
  const d = new Date();
  d.setDate(d.getDate() + durationDays);
  return d.toISOString();
}

// Lisans geçerli mi kontrol et
function isLicenseValid(license) {
  if (!license) return { valid: false, reason: 'not_found' };
  if (!license.is_active) return { valid: false, reason: 'revoked' };
  if (license.expires_at) {
    const exp = new Date(license.expires_at);
    if (exp < new Date()) return { valid: false, reason: 'expired' };
  }
  return { valid: true };
}

// Şifreli tarih üret (orijinal botla uyumlu format)
function encryptDate(dateStr) {
  const key = Buffer.from(
    LICENSE_SECRET.padEnd(32, '0').slice(0, 32)
  );
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(dateStr, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Admin JWT doğrula
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Yetkisiz erişim' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Token geçersiz veya süresi dolmuş' });
  }
}

// Log yaz
function writeLog(key, playerId, action, ip) {
  try {
    db.prepare(`INSERT INTO license_logs (license_key, player_id, action, ip) VALUES (?,?,?,?)`)
      .run(key || '', playerId || '', action, ip || '');
  } catch {}
}

// ─── BOT API ENDPOINTLERI ────────────────────────────────────────────────

// POST /validate-token  ← bot buraya istek atıyor
app.post('/validate-token', (req, res) => {
  const { token, refreshToken, playerId, i } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!token && !refreshToken) {
    return res.json({ valid: false, expired: true, reason: 'no_token' });
  }
  const licenseKey = token || refreshToken;

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(licenseKey);
  const check = isLicenseValid(license);

  if (!check.valid) {
    writeLog(licenseKey, playerId, 'validate_fail:' + check.reason, ip);
    return res.json({
      valid: false,
      expired: check.reason === 'expired',
      reason: check.reason
    });
  }

  // İlk kullanımda aktive et
  if (!license.activated_at) {
    db.prepare('UPDATE licenses SET activated_at = datetime("now"), player_id = ? WHERE key = ?')
      .run(playerId || '', token);
  }

  // Bitiş tarihi şifrele (orijinal bot bu formatı bekliyor)
  const expiryDate = license.expires_at
    ? license.expires_at.slice(0, 10)
    : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000 * 10).toISOString().slice(0, 10);

  const supportDevs = encryptDate(expiryDate);

  writeLog(licenseKey, playerId, 'validate_ok', ip);

  res.json({
    valid: true,
    expired: false,
    plan: license.plan || 'pro',
    supportDevs,           // bot bu şifreli tarihi AES ile çözüyor
    expiresAt: license.expires_at,
    userName: license.user_name
  });
});

// ─── ADMIN: GİRİŞ ────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Şifre yanlış' });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// ─── ADMIN: LİSANS YÖNETİMİ ─────────────────────────────────────────────

// Tüm lisansları getir
app.get('/admin/licenses', authMiddleware, (req, res) => {
  const licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  res.json(licenses);
});

// Lisans oluştur
app.post('/admin/licenses', authMiddleware, (req, res) => {
  const { userName, durationDays, plan, notes } = req.body;
  const key = generateLicenseKey();
  const expiresAt = calcExpiry(parseInt(durationDays) || 30);

  db.prepare(`
    INSERT INTO licenses (key, user_name, plan, duration_days, expires_at, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(key, userName || 'Anonim', plan || 'pro', durationDays || 30, expiresAt, notes || '');

  const created = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  res.json({ success: true, license: created });
});

// Toplu lisans oluştur
app.post('/admin/licenses/bulk', authMiddleware, (req, res) => {
  const { count, durationDays, plan } = req.body;
  const num = Math.min(parseInt(count) || 5, 200);
  const expiresAt = calcExpiry(parseInt(durationDays) || 30);
  const keys = [];

  const insert = db.prepare(`
    INSERT INTO licenses (key, user_name, plan, duration_days, expires_at)
    VALUES (?, 'Bekliyor', ?, ?, ?)
  `);

  const insertMany = db.transaction(() => {
    for (let i = 0; i < num; i++) {
      const key = generateLicenseKey();
      insert.run(key, plan || 'pro', durationDays || 30, expiresAt);
      keys.push(key);
    }
  });
  insertMany();

  res.json({ success: true, count: num, keys });
});

// Lisans güncelle (kullanıcı adı, notlar)
app.put('/admin/licenses/:id', authMiddleware, (req, res) => {
  const { userName, notes, durationDays, plan } = req.body;
  const expiresAt = durationDays ? calcExpiry(parseInt(durationDays)) : undefined;

  let query = 'UPDATE licenses SET user_name = ?, notes = ?, plan = ?';
  let params = [userName, notes || '', plan || 'pro'];

  if (expiresAt !== undefined) {
    query += ', expires_at = ?, duration_days = ?';
    params.push(expiresAt, durationDays);
  }

  query += ' WHERE id = ?';
  params.push(req.params.id);

  db.prepare(query).run(...params);
  res.json({ success: true });
});

// Lisans iptal et / aktif et
app.post('/admin/licenses/:id/toggle', authMiddleware, (req, res) => {
  const lic = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!lic) return res.status(404).json({ error: 'Lisans bulunamadı' });
  db.prepare('UPDATE licenses SET is_active = ? WHERE id = ?').run(lic.is_active ? 0 : 1, req.params.id);
  res.json({ success: true, is_active: !lic.is_active });
});

// Lisans sil
app.delete('/admin/licenses/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM licenses WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── ADMIN: İSTATİSTİK ───────────────────────────────────────────────────
app.get('/admin/stats', authMiddleware, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as c FROM licenses').get().c;
  const active = db.prepare(`SELECT COUNT(*) as c FROM licenses WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).get().c;
  const expired = db.prepare(`SELECT COUNT(*) as c FROM licenses WHERE expires_at < datetime('now')`).get().c;
  const pending = db.prepare(`SELECT COUNT(*) as c FROM licenses WHERE activated_at IS NULL AND is_active = 1`).get().c;
  const revoked = db.prepare(`SELECT COUNT(*) as c FROM licenses WHERE is_active = 0`).get().c;
  const logs = db.prepare('SELECT * FROM license_logs ORDER BY created_at DESC LIMIT 20').all();

  res.json({ total, active, expired, pending, revoked, logs });
});

// ─── PANEL ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'panel', 'index.html'));
});

// ─── BAŞLAT ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ MrtBot Lisans Sunucusu çalışıyor!`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`🔑 Admin paneli: http://localhost:${PORT}/panel`);
  console.log(`📡 Bot API: POST http://localhost:${PORT}/validate-token\n`);
});

module.exports = app;
