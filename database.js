const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

// مسار قاعدة البيانات: من متغير البيئة (Railway Volume) أو محلياً
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "elon-trader.db");

// التأكد من وجود المجلد الأب (مهم عند استخدام Volume على Railway)
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(DB_PATH);

// ===============================
// قاعدة البيانات الأساسية
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        fullname TEXT,
        phone TEXT,
        referral_code TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

db.run(
    `CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used INTEGER DEFAULT 0
    )`
);

// ===============================
// ترحيل أعمدة إضافية لجدول المستخدمين
// ===============================
function ensureColumn(table, column, definition) {
    db.all(`PRAGMA table_info(${table})`, (err, rows) => {
        if (err) return console.error("migration error:", err.message);
        const exists = rows.some(r => r.name === column);
        if (!exists) {
            db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`, (e) => {
                if (e) console.error(`migration error (${table}.${column}):`, e.message);
            });
        }
    });
}

ensureColumn("users", "balance", "REAL DEFAULT 0");
ensureColumn("users", "referrer_id", "INTEGER");
ensureColumn("users", "status", "TEXT DEFAULT 'active'");
ensureColumn("users", "blocked", "INTEGER DEFAULT 0");
ensureColumn("users", "last_login", "DATETIME");
ensureColumn("users", "total_deposits", "REAL DEFAULT 0");
ensureColumn("users", "total_withdrawals", "REAL DEFAULT 0");
ensureColumn("users", "invite_code", "TEXT");
ensureColumn("users", "trading_paused", "INTEGER DEFAULT 0");
ensureColumn("users", "trading_paused_reason", "TEXT");
ensureColumn("users", "plan_started_at", "INTEGER");


// ===============================
// حسابات الإدارة
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        fullname TEXT,
        role TEXT DEFAULT 'admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// خطط الاستثمار
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        min_amount REAL NOT NULL,
        max_amount REAL NOT NULL,
        daily_percent REAL DEFAULT 5,
        duration_days INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// محافظ الإيداع (الشبكات)
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network TEXT UNIQUE NOT NULL,
        address TEXT NOT NULL,
        status TEXT DEFAULT 'operational',
        confirmations_required INTEGER DEFAULT 3,
        eta_minutes INTEGER DEFAULT 20,
        min_amount REAL DEFAULT 50,
        max_amount REAL DEFAULT 30000,
        fee_fixed REAL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// عمليات الإيداع
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS deposits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        network TEXT NOT NULL,
        address TEXT,
        txid TEXT,
        hash TEXT,
        amount_sent REAL,
        notes TEXT,
        proof_path TEXT,
        status TEXT DEFAULT 'pending',
        reviewed_by INTEGER,
        reviewed_at DATETIME,
        verification_status TEXT DEFAULT 'pending',
        verification_message TEXT,
        verified_at INTEGER,
        verified_from TEXT,
        verified_amount REAL,
        verified_to TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// ترحيل أعمدة التحقق من الإيداعات (لقواعد البيانات القديمة)
// ===============================
ensureColumn("deposits", "verification_status", "TEXT DEFAULT 'pending'");
ensureColumn("deposits", "verification_message", "TEXT");
ensureColumn("deposits", "verified_at", "INTEGER");
ensureColumn("deposits", "verified_from", "TEXT");
ensureColumn("deposits", "verified_amount", "REAL");
ensureColumn("deposits", "verified_to", "TEXT");

// ===============================
// عمليات السحب
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        network TEXT NOT NULL,
        address TEXT NOT NULL,
        fee REAL DEFAULT 0,
        net_amount REAL DEFAULT 0,
        status TEXT DEFAULT 'pending',
        reviewed_by INTEGER,
        reviewed_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// الأرباح (أرباح التداول + عمولات الإحالة)
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS earnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        type TEXT DEFAULT 'profit',
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// علاقات الإحالة
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL,
        referred_id INTEGER NOT NULL,
        commission REAL DEFAULT 0,
        level INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ترحيل: إضافة عمود level لقواعد البيانات الحالية
ensureColumn("referrals", "level", "INTEGER DEFAULT 1");

// ===============================
// الإشعارات
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT,
        message TEXT,
        type TEXT DEFAULT 'info',
        read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);
// ===============================
// محفظة العمل لكل مستخدم
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS account_work_wallets (
        user_id INTEGER PRIMARY KEY,
        balance REAL DEFAULT 0,
        currency TEXT DEFAULT 'USDT',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// تحويلات الرصيد
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS account_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        idempotency_key TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// سجل عمليات الحساب
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS account_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);
// ===============================
// الإعدادات العامة
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`
);

// ===============================
// سجل النشاطات
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        admin_email TEXT,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
);

// ===============================
// جلسات التداول
// ===============================
db.run(
    `CREATE TABLE IF NOT EXISTS trade_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        started_at INTEGER NOT NULL,
        ends_at INTEGER NOT NULL,
        claimed_at INTEGER,
        status TEXT DEFAULT 'running'
    )`
);

// ===============================
// قيود التفرد (UNIQUE) لحماية البيانات
// ===============================
db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_deposits_txid
        ON deposits(LOWER(txid)) WHERE txid IS NOT NULL`);

db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_invite_code
        ON users(invite_code) WHERE invite_code IS NOT NULL`);

db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_referrals_pair
        ON referrals(referrer_id, referred_id)`);

// ===============================
// فهارس الأداء (تُسرّع الاستعلامات)
// ===============================
db.run(`CREATE INDEX IF NOT EXISTS idx_deposits_user        ON deposits(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_deposits_status      ON deposits(status)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_withdrawals_user     ON withdrawals(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_withdrawals_status   ON withdrawals(status)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_earnings_user_type   ON earnings(user_id, type)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_notif_user_read      ON notifications(user_id, read)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_referrals_referrer   ON referrals(referrer_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_referrals_referred   ON referrals(referred_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_trade_sessions_user  ON trade_sessions(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_pwresets_email_code  ON password_resets(email, code)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_activity_created     ON activity_logs(created_at)`);

module.exports = db;