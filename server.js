require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET        = process.env.JWT_SECRET        || 'change_this_secret';
const LICENSE_SECRET    = process.env.LICENSE_SECRET    || 'change_this_license_secret';
const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD    || 'admin123';
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET || '';   // Lemon Squeezy webhook secret

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
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Signature'],
}));

// Lemon Squeezy webhook için raw body
app.use('/webhook/lemonsqueezy', express.raw({ type: 'application/json' }));
// Gumroad webhook için form-encoded
app.use('/webhook/gumroad', express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'panel')));

// ─── YARDIMCI FONKSİYONLAR ──────────────────────────────────────────────

function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = (n) => Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `MRT-${seg(5)}-${seg(5)}-${seg(5)}`;
}

function calcExpiry(durationDays) {
  if (durationDays >= 9999) return null;
  const d = new Date();
  d.setDate(d.getDate() + durationDays);
  return d.toISOString();
}

function isLicenseValid(license) {
  if (!license) return { valid: false, reason: 'not_found' };
  if (!license.is_active) return { valid: false, reason: 'revoked' };
  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    return { valid: false, reason: 'expired' };
  }
  return { valid: true };
}

function encryptDate(dateStr) {
  const key = Buffer.from(LICENSE_SECRET.padEnd(32, '0').slice(0, 32));
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(dateStr, 'utf8', 'hex');
  enc += cipher.final('hex');
  return iv.toString('hex') + ':' + enc;
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Yetkisiz erişim' });
  try {
    req.admin = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token geçersiz veya süresi dolmuş' });
  }
}

function writeLog(key, playerId, action, ip) {
  try {
    db.prepare('INSERT INTO license_logs (license_key, player_id, action, ip) VALUES (?,?,?,?)').run(key || '', playerId || '', action, ip || '');
  } catch {}
}

// ─── EMAIL ──────────────────────────────────────────────────────────────
// .env'de ayarla: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
const mailer = nodemailer.createTransport({
  host:   process.env.SMTP_HOST   || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
  },
});

async function sendLicenseEmail(toEmail, toName, licenseKey, durationDays, plan) {
  if (!process.env.SMTP_USER) {
    console.log('[Email] SMTP yapılandırılmamış — email atlanıyor:', toEmail, licenseKey);
    return;
  }
  const expireText = durationDays >= 9999 ? 'Sınırsız' : `${durationDays} gün`;
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;background:#0d0d1a;color:#eee;border:2px solid #f0a500;border-radius:8px;padding:28px">
      <h2 style="color:#f0a500;margin:0 0 16px">⚔️ MS Bot — Lisans Anahtarınız</h2>
      <p>Merhaba <strong>${toName || 'Değerli Kullanıcı'}</strong>,</p>
      <p>Satın aldığınız için teşekkürler! Lisans anahtarınız:</p>
      <div style="background:#1a1a2e;border:1px solid #f0a500;border-radius:6px;padding:14px;text-align:center;margin:20px 0">
        <span style="font-family:monospace;font-size:22px;letter-spacing:.1em;color:#f0a500">${licenseKey}</span>
      </div>
      <p><strong>Plan:</strong> ${plan || 'Pro'} &nbsp;|&nbsp; <strong>Süre:</strong> ${expireText}</p>
      <hr style="border-color:#333;margin:20px 0">
      <p style="font-size:12px;color:#aaa"><strong>Nasıl kullanılır?</strong><br>
      1. Chrome'da Gladiatus sayfasını açın.<br>
      2. MS Bot eklentisi otomatik açılır — lisans penceresine anahtarı girin.<br>
      3. "Doğrula" butonuna basın, bot başlayacaktır.</p>
      <p style="font-size:11px;color:#666;margin-top:20px;text-align:center">
        Bu anahtar <strong>tek hesap</strong> için geçerlidir.<br>
        Destek için satıcınıza ulaşın.
      </p>
    </div>
  `;
  try {
    await mailer.sendMail({
      from:    process.env.SMTP_FROM || process.env.SMTP_USER,
      to:      toEmail,
      subject: '⚔️ MS Bot Lisans Anahtarınız',
      html,
    });
    console.log('[Email] ✔ Gönderildi:', toEmail);
  } catch (e) {
    console.error('[Email] ✖ Gönderilemedi:', e.message);
  }
}

// ─── LEMON SQUEEZY WEBHOOK ───────────────────────────────────────────────
// Lemon Squeezy Dashboard → Webhooks → URL: https://msbotcom-production.up.railway.app/webhook/lemonsqueezy
// Events: order_created
// Secret: LS_WEBHOOK_SECRET env var ile aynı olmalı

// Variant adından süreyi çıkar (örn. "30 Günlük Pro" → 30)
function parseDurationFromVariant(variantName) {
  if (!variantName) return 30;
  const m = variantName.match(/(\d+)\s*(gün|day|gun)/i);
  if (m) return parseInt(m[1]);
  if (/yıl|year|365/i.test(variantName)) return 365;
  if (/sınırsız|unlimited|lifetime/i.test(variantName)) return 9999;
  return 30;
}

// Plan adını çıkar
function parsePlanFromVariant(variantName) {
  if (!variantName) return 'pro';
  if (/premium/i.test(variantName)) return 'premium';
  if (/basic/i.test(variantName)) return 'basic';
  return 'pro';
}

app.post('/webhook/lemonsqueezy', (req, res) => {
  // İmza doğrulama
  if (LS_WEBHOOK_SECRET) {
    const sig = req.headers['x-signature'] || '';
    const expected = crypto.createHmac('sha256', LS_WEBHOOK_SECRET).update(req.body).digest('hex');
    if (sig !== expected) {
      console.warn('[Webhook] İmza hatası — istek reddedildi');
      return res.status(401).json({ error: 'Geçersiz imza' });
    }
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).json({ error: 'Geçersiz JSON' });
  }

  const event = payload?.meta?.event_name;
  console.log('[Webhook] Event:', event);

  if (event === 'order_created') {
    const attrs       = payload?.data?.attributes || {};
    const customData  = payload?.meta?.custom_data || {};
    const orderItem   = attrs?.first_order_item || {};

    // Sadece ödenmişleri işle
    if (attrs.status !== 'paid') {
      return res.json({ ok: true, skipped: 'not_paid' });
    }

    const customerEmail = attrs.user_email || '';
    const customerName  = attrs.user_name  || 'Kullanıcı';
    const variantName   = orderItem.variant_name || orderItem.product_name || '';

    // custom_data'dan veya variant adından süreyi al
    const durationDays = parseInt(customData.duration_days) || parseDurationFromVariant(variantName);
    const plan         = customData.plan || parsePlanFromVariant(variantName);
    const expiresAt    = calcExpiry(durationDays);

    // Lisans oluştur
    const key = generateLicenseKey();
    try {
      db.prepare(`
        INSERT INTO licenses (key, user_name, plan, duration_days, expires_at, notes)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(key, customerName, plan, durationDays, expiresAt, `LemonSqueezy order #${attrs.identifier || ''}`);
    } catch (e) {
      console.error('[Webhook] DB hatası:', e.message);
      return res.status(500).json({ error: 'Lisans oluşturulamadı' });
    }

    writeLog(key, '', 'webhook_created', '');
    console.log(`[Webhook] ✔ Lisans oluşturuldu: ${key} → ${customerEmail} (${durationDays}g ${plan})`);

    // Email gönder (async — webhook'u bekletmiyoruz)
    sendLicenseEmail(customerEmail, customerName, key, durationDays, plan).catch(() => {});
  }

  res.json({ ok: true });
});

// ─── GUMROAD WEBHOOK ─────────────────────────────────────────────────────
// Her ürün için ayrı ping URL'i kullan — duration query param ile:
//   30 gün:  https://msbotcom-production.up.railway.app/webhook/gumroad?duration=30
//   90 gün:  https://msbotcom-production.up.railway.app/webhook/gumroad?duration=90
//   365 gün: https://msbotcom-production.up.railway.app/webhook/gumroad?duration=365

app.post('/webhook/gumroad', async (req, res) => {
  // Test modunda çalıştırma
  if (req.body.test === 'true') {
    console.log('[Gumroad] Test ping alındı — atlanıyor');
    return res.json({ ok: true, test: true });
  }

  const customerEmail = req.body.email        || '';
  const customerName  = req.body.full_name    || req.body.email || 'Kullanıcı';
  const productName   = req.body.product_name || '';
  const purchaseId    = req.body.purchase_id  || '';

  if (!customerEmail) {
    console.warn('[Gumroad] Email yok — atlanıyor');
    return res.status(400).json({ error: 'email eksik' });
  }

  // Süreyi URL param'dan al (her ürün için farklı ping URL'i)
  let durationDays = parseInt(req.query.duration) || 30;
  const plan = req.query.plan || 'pro';

  const expiresAt = calcExpiry(durationDays);
  const key = generateLicenseKey();

  try {
    db.prepare(`
      INSERT INTO licenses (key, user_name, plan, duration_days, expires_at, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(key, customerName, plan, durationDays, expiresAt, `Gumroad #${purchaseId}`);
  } catch (e) {
    console.error('[Gumroad] DB hatası:', e.message);
    return res.status(500).json({ error: 'Lisans oluşturulamadı' });
  }

  writeLog(key, '', 'gumroad_created', '');
  console.log(`[Gumroad] ✔ ${key} → ${customerEmail} (${durationDays}g)`);

  sendLicenseEmail(customerEmail, customerName, key, durationDays, plan).catch(() => {});

  res.json({ ok: true });
});

// ─── BOT: LİSANS AKTİVASYON ─────────────────────────────────────────────
app.post('/validate-license', (req, res) => {
  const { licenseKey, playerId } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!licenseKey) return res.json({ valid: false, message: 'Lisans anahtarı boş' });

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(licenseKey);
  const check = isLicenseValid(license);

  if (!check.valid) {
    writeLog(licenseKey, playerId, 'activate_fail:' + check.reason, ip);
    return res.json({
      valid: false,
      message: check.reason === 'expired' ? 'Lisans süresi dolmuş' :
               check.reason === 'revoked' ? 'Lisans iptal edilmiş' :
               'Geçersiz lisans anahtarı',
    });
  }

  if (!license.activated_at) {
    db.prepare('UPDATE licenses SET activated_at = datetime("now"), player_id = ? WHERE key = ?').run(playerId || '', licenseKey);
  }

  const expirationDate = license.expires_at ? license.expires_at.slice(0, 10) : '2099-12-31';
  writeLog(licenseKey, playerId, 'activate_ok', ip);

  res.json({
    valid: true,
    token:          licenseKey,
    refreshToken:   licenseKey,
    expirationDate,
    supportDevs:    encryptDate(expirationDate),
    plan:           license.plan || 'pro',
    userName:       license.user_name || 'MS Bot User',
    message:        'Lisans başarıyla aktive edildi!',
  });
});

// ─── BOT: TOKEN DOĞRULAMA ────────────────────────────────────────────────
app.post('/validate-token', (req, res) => {
  const { token, refreshToken, playerId } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!token && !refreshToken) return res.json({ valid: false, expired: true, reason: 'no_token' });

  const licenseKey = token || refreshToken;
  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(licenseKey);
  const check = isLicenseValid(license);

  if (!check.valid) {
    writeLog(licenseKey, playerId, 'validate_fail:' + check.reason, ip);
    return res.json({ valid: false, expired: check.reason === 'expired', reason: check.reason });
  }

  if (!license.activated_at) {
    db.prepare('UPDATE licenses SET activated_at = datetime("now"), player_id = ? WHERE key = ?').run(playerId || '', licenseKey);
  }

  const expiryDate = license.expires_at
    ? license.expires_at.slice(0, 10)
    : '2099-12-31';

  writeLog(licenseKey, playerId, 'validate_ok', ip);

  res.json({
    valid:      true,
    expired:    false,
    plan:       license.plan || 'pro',
    supportDevs: encryptDate(expiryDate),
    expiresAt:  license.expires_at,
    userName:   license.user_name,
  });
});

// ─── ADMIN: GİRİŞ ────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Şifre yanlış' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// ─── ADMIN: LİSANS YÖNETİMİ ─────────────────────────────────────────────
app.get('/admin/licenses', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all());
});

app.post('/admin/licenses', authMiddleware, (req, res) => {
  const { userName, durationDays, plan, notes } = req.body;
  const key = generateLicenseKey();
  const expiresAt = calcExpiry(parseInt(durationDays) || 30);
  db.prepare('INSERT INTO licenses (key, user_name, plan, duration_days, expires_at, notes) VALUES (?,?,?,?,?,?)').run(key, userName || 'Anonim', plan || 'pro', durationDays || 30, expiresAt, notes || '');
  res.json({ success: true, license: db.prepare('SELECT * FROM licenses WHERE key = ?').get(key) });
});

app.post('/admin/licenses/bulk', authMiddleware, (req, res) => {
  const { count, durationDays, plan } = req.body;
  const num = Math.min(parseInt(count) || 5, 200);
  const expiresAt = calcExpiry(parseInt(durationDays) || 30);
  const keys = [];
  const insert = db.prepare("INSERT INTO licenses (key, user_name, plan, duration_days, expires_at) VALUES (?, 'Bekliyor', ?, ?, ?)");
  db.transaction(() => {
    for (let i = 0; i < num; i++) {
      const key = generateLicenseKey();
      insert.run(key, plan || 'pro', durationDays || 30, expiresAt);
      keys.push(key);
    }
  })();
  res.json({ success: true, count: num, keys });
});

app.put('/admin/licenses/:id', authMiddleware, (req, res) => {
  const { userName, notes, durationDays, plan } = req.body;
  const expiresAt = durationDays ? calcExpiry(parseInt(durationDays)) : undefined;
  let q = 'UPDATE licenses SET user_name = ?, notes = ?, plan = ?';
  let p = [userName, notes || '', plan || 'pro'];
  if (expiresAt !== undefined) { q += ', expires_at = ?, duration_days = ?'; p.push(expiresAt, durationDays); }
  q += ' WHERE id = ?'; p.push(req.params.id);
  db.prepare(q).run(...p);
  res.json({ success: true });
});

app.post('/admin/licenses/:id/toggle', authMiddleware, (req, res) => {
  const lic = db.prepare('SELECT * FROM licenses WHERE id = ?').get(req.params.id);
  if (!lic) return res.status(404).json({ error: 'Lisans bulunamadı' });
  db.prepare('UPDATE licenses SET is_active = ? WHERE id = ?').run(lic.is_active ? 0 : 1, req.params.id);
  res.json({ success: true, is_active: !lic.is_active });
});

app.delete('/admin/licenses/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM licenses WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── ADMIN: İSTATİSTİK ───────────────────────────────────────────────────
app.get('/admin/stats', authMiddleware, (req, res) => {
  res.json({
    total:   db.prepare('SELECT COUNT(*) as c FROM licenses').get().c,
    active:  db.prepare("SELECT COUNT(*) as c FROM licenses WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))").get().c,
    expired: db.prepare("SELECT COUNT(*) as c FROM licenses WHERE expires_at < datetime('now')").get().c,
    pending: db.prepare("SELECT COUNT(*) as c FROM licenses WHERE activated_at IS NULL AND is_active = 1").get().c,
    revoked: db.prepare('SELECT COUNT(*) as c FROM licenses WHERE is_active = 0').get().c,
    logs:    db.prepare('SELECT * FROM license_logs ORDER BY created_at DESC LIMIT 20').all(),
  });
});

// ─── PANEL ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'panel', 'index.html'));
});

// ─── BAŞLAT ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ MS Bot Lisans Sunucusu — port ${PORT}`);
  console.log(`📡 Validate: POST /validate-license | /validate-token`);
  console.log(`💳 Webhook:  POST /webhook/lemonsqueezy`);
  console.log(`🔧 Panel:    http://localhost:${PORT}\n`);
});

module.exports = app;
