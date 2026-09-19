require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const path = require("path");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const db = require("./database");

const app = express();
const PORT = process.env.PORT || 5000;

// مجلد رفع الملفات — داخل Volume على Railway
const fs = require("fs");
const uploadsDir = process.env.UPLOAD_DIR || path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// للتعامل مع reverse proxy (Railway، Heroku، ...)
app.set('trust proxy', 1);

// رؤوس أمنية
app.use(helmet({
    contentSecurityPolicy: false,      // لا نفعّل CSP (الواجهة تستخدم inline)
    crossOriginEmbedderPolicy: false,  // نسمح بـ Binance API من الواجهة
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// حد الطلبات على مسارات المصادقة
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 20,                  // 20 محاولة كحد أقصى
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: "error", message: "عدد المحاولات كبير — حاول بعد 15 دقيقة" }
});

app.use("/login", authLimiter);
app.use("/register", authLimiter);
app.use("/forgot-password", authLimiter);
app.use("/reset-password", authLimiter);
app.use("/api/admin/login", authLimiter);
app.use("/api/admin/forgot-password", authLimiter);
app.use("/api/admin/reset-password", authLimiter);

app.use(express.json({ limit: '150kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET غير موجود في .env — لن يعمل الخادم");
    process.exit(1);
}
// ========== متجر الجلسات (SQLite) ==========
const sessionsDir = process.env.DB_PATH
    ? path.dirname(process.env.DB_PATH)
    : path.join(__dirname, "data");

if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir, { recursive: true });
}

const sessionStore = new SQLiteStore({
    db: "sessions.db",
    dir: sessionsDir,
    concurrentDB: true
});
// ==========================================

// إعدادات الكوكي المشتركة
const isProduction = process.env.NODE_ENV === 'production';

const cookieOpts = {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction
};

// جلسة الأدمن — كوكي منفصل، تُطبق فقط على /admin و /api/admin
const adminSession = session({
        store: sessionStore,
    name: 'elite.admin.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOpts
});
app.use(['/admin', '/admin-login', '/api/admin'], adminSession);

// جلسة المستخدم العادي — كوكي منفصل
app.use(
    session({
                store: sessionStore,
        name: 'elite.sid',
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: cookieOpts
    })
);
// حماية ملفات الإثبات — لا يصل إليها إلا مستخدم مسجّل
app.use(
    '/uploads',
    (req, res, next) => {
        if (!req.session.userId && !req.session.isAdmin) {
            return res.status(401).send('غير مصرح');
        }
        next();
    },
    express.static(uploadsDir)
);

// الصفحة الرئيسية
app.get("/", (req, res) => {
    // إذا كان المستخدم مسجلاً، وجهه إلى home.html
    if (req.session.userId) {
        return res.sendFile(path.join(__dirname, "public", "home.html"));
    }
    // وإلا أظهر صفحة تسجيل الدخول
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// صفحة إنشاء الحساب
app.get("/register", (req, res) => {
    // إذا كان مسجلاً، وجّهه إلى home
    if (req.session.userId) {
        return res.redirect("/home");
    }
    res.sendFile(path.join(__dirname, "public", "register.html"));
});

// تشغيل ملفات الواجهة (بعد المسارات لضمان أولوية الجلسة)
app.use(express.static(path.join(__dirname, "public")));

// ===============================
// إعداد إرسال البريد عبر Gmail
// ===============================
// إرسال البريد عبر Resend (HTTP API — لا يستخدم SMTP)
async function sendEmail({ to, subject, html }) {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
        throw new Error("RESEND_API_KEY غير موجود في المتغيرات");
    }
    const from = process.env.EMAIL_FROM || "ELITE TRADING <onboarding@resend.dev>";

    const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + apiKey,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ from, to: [to], subject, html })
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error("Resend error (" + res.status + "): " + errText);
    }
    return await res.json();
}

// ===============================
// دوال التحقق من المدخلات
// ===============================
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const PHONE_RE = /^\+\d{7,15}$/;

function isValidEmail(email) {
    return typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email);
}
function isValidPhone(phone) {
    if (!phone) return true; // اختياري
    return typeof phone === 'string' && PHONE_RE.test(phone);
}

// صيغ عناوين المحافظ لكل شبكة
const ADDR_TRC20_RE   = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;                // TRON: T + 33
const ADDR_EVM_RE     = /^0x[a-fA-F0-9]{40}$/;                        // Ethereum/Polygon
const ADDR_BEP20_RE   = /^0x[a-fA-F0-9]{40}$/;                        // BSC (نفس EVM)

function isValidWalletAddress(network, address) {
    if (typeof address !== 'string') return false;
    const a = address.trim();
    if (a.length < 20 || a.length > 100) return false;
    if (network === 'trc20')   return ADDR_TRC20_RE.test(a);
    if (network === 'erc20')   return ADDR_EVM_RE.test(a);
    if (network === 'polygon') return ADDR_EVM_RE.test(a);
    if (network === 'bep20')   return ADDR_BEP20_RE.test(a);
    return false;
}

function isValidTxid(network, txid) {
    if (typeof txid !== 'string') return false;
    const t = txid.trim();
    if (!t) return false;
    if (network === 'trc20')   return /^[a-fA-F0-9]{64}$/.test(t);   // TRON: 64 hex
    if (network === 'erc20')   return /^0x[a-fA-F0-9]{64}$/.test(t); // EVM: 0x + 64
    if (network === 'polygon') return /^0x[a-fA-F0-9]{64}$/.test(t);
    if (network === 'bep20')   return /^0x[a-fA-F0-9]{64}$/.test(t);
    return false;
}
// ===============================
// إنشاء حساب جديد
// ===============================
app.post("/register", async (req, res) => {
    try {
        const { email, password, fullname, phone, referral } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                status: "error",
                message: "يرجى إدخال البريد الإلكتروني وكلمة المرور"
            });
        }

        if (!isValidEmail(email.trim().toLowerCase())) {
            return res.status(400).json({
                status: "error",
                message: "صيغة البريد الإلكتروني غير صحيحة"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                status: "error",
                message: "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
            });
        }

        if (password.length > 128) {
            return res.status(400).json({
                status: "error",
                message: "كلمة المرور طويلة جداً"
            });
        }

        if (fullname && String(fullname).length > 100) {
            return res.status(400).json({
                status: "error",
                message: "الاسم طويل جداً"
            });
        }

        if (!isValidPhone(phone)) {
            return res.status(400).json({
                status: "error",
                message: "صيغة رقم الهاتف غير صحيحة"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        db.run(
            "INSERT INTO users (email, password, fullname, phone) VALUES (?, ?, ?, ?)",
            [
                email.trim().toLowerCase(),
                hashedPassword,
                fullname ? fullname.trim() : null,
                phone ? phone.trim() : null
            ],
            function (err) {

                if (err) {
                    if (err.message.includes("UNIQUE")) {
                        return res.status(400).json({
                            status: "error",
                            message: "هذا البريد الإلكتروني مسجل بالفعل"
                        });
                    }

                    console.error(err);

                    return res.status(500).json({
                        status: "error",
                        message: "حدث خطأ أثناء إنشاء الحساب"
                    });
                }

                const newUserId = this.lastID;

                // تسجيل علاقة الإحالة إذا وُجد كود دعوة صحيح
                if (referral) {
                    const cleanCode = referral.trim().toUpperCase();
                    db.get(
                        "SELECT id FROM users WHERE invite_code = ? AND id != ?",
                        [cleanCode, newUserId],
                        (refErr, refUser) => {
                            if (!refErr && refUser) {
                                db.run(
                                    "UPDATE users SET referrer_id = ? WHERE id = ?",
                                    [refUser.id, newUserId]
                                );
                                db.run(
                                    "INSERT INTO referrals (referrer_id, referred_id, level) VALUES (?, ?, 1)",
                                    [refUser.id, newUserId]
                                );
                            }
                        }
                    );
                }

                res.json({
                    status: "success",
                    message: "تم إنشاء الحساب بنجاح",
                    userId: newUserId
                });
            }
        );

    } catch (error) {
        console.error(error);

        res.status(500).json({
            status: "error",
            message: "حدث خطأ في الخادم"
        });
    }
});

// ===============================
// تسجيل الدخول
// ===============================
app.post("/login", (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            status: "error",
            message: "يرجى إدخال البريد الإلكتروني وكلمة المرور"
        });
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email.trim().toLowerCase()],
        async (err, user) => {

            if (err) {
                console.error(err);

                return res.status(500).json({
                    status: "error",
                    message: "حدث خطأ في قاعدة البيانات"
                });
            }

            if (!user) {
                return res.status(401).json({
                    status: "error",
                    message: "البريد الإلكتروني أو كلمة المرور غير صحيحة"
                });
            }

            const passwordMatch = await bcrypt.compare(
                password,
                user.password
            );

            if (!passwordMatch) {
                return res.status(401).json({
                    status: "error",
                    message: "البريد الإلكتروني أو كلمة المرور غير صحيحة"
                });
            }

            if (Number(user.blocked) === 1) {
                return res.status(403).json({
                    status: "error",
                    message: "هذا الحساب موقوف — يرجى التواصل مع الدعم"
                });
            }
            // تحديث تاريخ آخر تسجيل دخول
            db.run("UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);

            // إعادة توليد الجلسة (حماية من Session Fixation)
            req.session.regenerate((regenErr) => {
                if (regenErr) {
                    console.error("SESSION REGENERATE ERROR:", regenErr);
                    return res.status(500).json({ status: "error", message: "حدث خطأ أثناء تسجيل الدخول" });
                }

                // إذا اختار المستخدم "تذكرني"، مدد مدة الجلسة إلى 7 أيام
                if (req.body.rememberMe) {
                    req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000;
                }
                req.session.userId = user.id;
                req.session.userEmail = user.email;

                res.json({
                    status: "success",
                    message: "تم تسجيل الدخول بنجاح",
                    user: {
                        id: user.id,
                        email: user.email,
                        fullname: user.fullname,
                        phone: user.phone
                    }
                });
            });
        }
    );
});

// ===============================
// طلب استعادة كلمة المرور (إرسال رمز)
// ===============================
app.post("/forgot-password", (req, res) => {

    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            status: "error",
            message: "يرجى إدخال البريد الإلكتروني"
        });
    }

    const normalizedEmail = email.trim().toLowerCase();

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [normalizedEmail],
        (err, user) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    status: "error",
                    message: "حدث خطأ في الخادم"
                });
            }

            // لأسباب أمنية، نعطي نفس الرد سواء كان البريد مسجلاً أم لا
            if (!user) {
                return res.json({
                    status: "success",
                    message: "إذا كان البريد مسجلاً لدينا، فسيصلك رمز التحقق"
                });
            }

            const code = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

            db.run(
                "INSERT INTO password_resets (email, code, expires_at) VALUES (?, ?, ?)",
                [normalizedEmail, code, expiresAt],
                async function (insertErr) {

                    if (insertErr) {
                        console.error(insertErr);
                        return res.status(500).json({
                            status: "error",
                            message: "حدث خطأ أثناء إنشاء رمز الاستعادة"
                        });
                    }

                    try {
                        await sendEmail({
    to: normalizedEmail,
    subject: "رمز استعادة كلمة المرور - ELITE TRADING",
    html: `
                                <div style="font-family: Arial; text-align: center; padding: 20px;">
                                    <h2 style="color:#0eae91;">ELITE TRADING</h2>
                                    <p>رمز استعادة كلمة المرور الخاص بك هو:</p>
                                    <h1 style="letter-spacing: 6px;">${code}</h1>
                                    <p>صالح لمدة 15 دقيقة فقط.</p>
                                </div>
                            `
                        });

                        res.json({
                            status: "success",
                            message: "تم إرسال رمز التحقق إلى بريدك الإلكتروني"
                        });

                    } catch (mailErr) {
                        console.error(mailErr);
                        res.status(500).json({
                            status: "error",
                            message: "تعذر إرسال البريد الإلكتروني، تأكد من إعدادات الخادم"
                        });
                    }
                }
            );
        }
    );
});

// ===============================
// التحقق من الرمز وتعيين كلمة مرور جديدة
// ===============================
app.post("/reset-password", async (req, res) => {

    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
        return res.status(400).json({
            status: "error",
            message: "يرجى تعبئة جميع الحقول"
        });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            status: "error",
            message: "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
        });
    }

    const normalizedEmail = email.trim().toLowerCase();

    db.get(
        `SELECT * FROM password_resets
         WHERE email = ? AND code = ? AND used = 0
         ORDER BY id DESC LIMIT 1`,
        [normalizedEmail, code.trim()],
        async (err, resetRow) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    status: "error",
                    message: "حدث خطأ في الخادم"
                });
            }

            if (!resetRow) {
                return res.status(400).json({
                    status: "error",
                    message: "الرمز غير صحيح"
                });
            }

            if (new Date(resetRow.expires_at) < new Date()) {
                return res.status(400).json({
                    status: "error",
                    message: "انتهت صلاحية الرمز، يرجى طلب رمز جديد"
                });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 12);

            db.run(
                "UPDATE users SET password = ? WHERE email = ?",
                [hashedPassword, normalizedEmail],
                function (updateErr) {

                    if (updateErr) {
                        console.error(updateErr);
                        return res.status(500).json({
                            status: "error",
                            message: "تعذر تحديث كلمة المرور"
                        });
                    }

                    db.run(
                        "UPDATE password_resets SET used = 1 WHERE id = ?",
                        [resetRow.id]
                    );

                    res.json({
                        status: "success",
                        message: "تم تغيير كلمة المرور بنجاح"
                    });
                }
            );
        }
    );
});

// ===============================
// تحديث الملف الشخصي (الاسم والهاتف)
// ===============================
app.post("/update-profile", requireAuth, (req, res) => {

    const { fullname, phone } = req.body;

    db.run(
        "UPDATE users SET fullname = ?, phone = ? WHERE id = ?",
        [fullname || null, phone || null, req.session.userId],
        function (err) {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    status: "error",
                    message: "تعذر تحديث البيانات"
                });
            }

            res.json({
                status: "success",
                message: "تم تحديث البيانات بنجاح"
            });
        }
    );
});

// ===============================
// تشغيل الخادم
// ===============================

// ===============================
// الصفحة الرئيسية
// ===============================
app.get("/home", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/");
    }

    res.sendFile(path.join(__dirname, "public", "home.html"));
});
// ===============================
// صفحة حسابي
// ===============================
// ===============================
// الصفحات المحمية (تتطلب تسجيل دخول)
// ===============================

app.get("/account", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "account.html"));
});

app.get("/deposit", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "deposit.html"));
});

app.get("/withdraw", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "withdraw.html"));
});

app.get("/trade", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "trade.html"));
});

app.get("/work", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "work.html"));
});

app.get("/friends", (req, res) => {
    if (!req.session.userId) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "friends.html"));
});
// ===============================
// API: جلب بيانات المستخدم الحالي
// ===============================
app.get("/api/user", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: "error", message: "غير مسجل دخول" });
    }

    db.get(
        "SELECT id, email, fullname, phone, referral_code, created_at, balance, total_deposits, total_withdrawals, status, blocked, invite_code FROM users WHERE id = ?",
        [req.session.userId],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            if (!user) {
                return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
            }

            ensureInviteCode(user.id, (code) => {
                res.json({
                    status: "success",
                    user: {
                        id: user.id,
                        email: user.email,
                        fullname: user.fullname || "مستخدم",
                        phone: user.phone || "غير محدد",
                        balance: user.balance || 0,
                        referralCode: code || user.referral_code || "لا يوجد",
                        joinedDate: user.created_at || "اليوم",
                        status: user.status || "active",
                        blocked: !!user.blocked
                    }
                });
            });
        }
    );
});

// ===============================
// API: جلب أرباح المستخدم (التداول والإحالات)
// ===============================
app.get("/api/user/earnings", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: "error", message: "غير مسجل دخول" });
    }

    db.get(
        `SELECT
            COALESCE(SUM(CASE WHEN type = 'profit' THEN amount ELSE 0 END), 0) 
            + COALESCE(SUM(CASE WHEN type IN ('transfer_out_work', 'transfer_out', 'withdraw') THEN amount ELSE 0 END), 0) AS profit,
            COALESCE(SUM(CASE WHEN type = 'referral' THEN amount ELSE 0 END), 0)
            + COALESCE(SUM(CASE WHEN type = 'transfer_out_ref' THEN amount ELSE 0 END), 0) AS referral
         FROM earnings WHERE user_id = ?`,
        [req.session.userId],
        (err, row) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            res.json({
                status: "success",
                profit: Math.max(row.profit || 0, 0),
                referral: Math.max(row.referral || 0, 0)
            });
        }
    );
});

// ===============================
// API: إشعارات المستخدم
// ===============================
app.get("/api/user/notifications", requireAuth, (req, res) => {
    db.all(
        `SELECT id, title, message, type, read, created_at
         FROM notifications
         WHERE user_id = ?
         ORDER BY id DESC
         LIMIT 50`,
        [req.session.userId],
        (err, rows) => {
            if (err) {
                console.error("USER NOTIFICATIONS ERROR:", err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            res.json({ status: "success", notifications: rows || [] });
        }
    );
});

app.get("/api/user/notifications/unread-count", requireAuth, (req, res) => {
    db.get(
        `SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND read = 0`,
        [req.session.userId],
        (err, row) => {
            if (err) {
                console.error("UNREAD COUNT ERROR:", err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            res.json({ status: "success", count: (row && row.cnt) || 0 });
        }
    );
});

app.post("/api/user/notifications/:id/read", requireAuth, (req, res) => {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) {
        return res.status(400).json({ status: "error", message: "معرّف غير صحيح" });
    }
    db.run(
        `UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?`,
        [id, req.session.userId],
        function (err) {
            if (err) {
                console.error("NOTIF MARK READ ERROR:", err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            res.json({ status: "success", updated: this.changes });
        }
    );
});

app.post("/api/user/notifications/read-all", requireAuth, (req, res) => {
    db.run(
        `UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0`,
        [req.session.userId],
        function (err) {
            if (err) {
                console.error("NOTIF READ ALL ERROR:", err);
                return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            }
            res.json({ status: "success", updated: this.changes });
        }
    );
});
// ===============================
// API: حالة جلسة التداول الحالية
// ===============================
app.get("/api/trade/session", requireAuth, (req, res) => {
    const now = Date.now();
    const COOLDOWN_MS = 24 * 60 * 60 * 1000;

    db.get(`SELECT u.balance, u.total_deposits, u.trading_paused, u.trading_paused_reason, u.plan_started_at,
                   COALESCE(w.balance, 0) AS work_wallet_balance
            FROM users u
            LEFT JOIN account_work_wallets w ON w.user_id = u.id
            WHERE u.id = ?`, [req.session.userId], (err, user) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });

        const userTradingPaused = Number(user.trading_paused) === 1;
        const userPauseReason = user.trading_paused_reason || "";

        db.get(
            `SELECT * FROM trade_sessions
             WHERE user_id = ?
             ORDER BY id DESC LIMIT 1`,
            [req.session.userId],
            (sErr, session) => {
                if (sErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

                db.all("SELECT * FROM plans ORDER BY min_amount ASC", (pErr, plans) => {
                    if (pErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

                    const deposits = Number(user.total_deposits || 0);
                    const workWallet = Number(user.work_wallet_balance || 0);
                    const planBasis = deposits + workWallet;
                    let currentPlan = null;
                    if (Array.isArray(plans)) {
                        for (let i = plans.length - 1; i >= 0; i--) {
                            if (planBasis >= plans[i].min_amount) {
                                currentPlan = plans[i];
                                break;
                            }
                        }
                    }

                    // ============ عدّاد مدة الخطة (تُقرأ من الخطة الحالية) ============
                    const planDurationDays = currentPlan ? (Number(currentPlan.duration_days) || 180) : 180;
                    const PLAN_DURATION_MS = planDurationDays * 24 * 60 * 60 * 1000;
                    let planDaysLeft = null;
                    let planStart = (user.plan_started_at !== null && user.plan_started_at !== undefined)
                        ? Number(user.plan_started_at)
                        : null;

                    if (currentPlan) {
                        if (planStart === null) {
                            // أول زيارة مع خطة → ابدأ العدّاد الآن
                            planStart = Date.now();
                            db.run("UPDATE users SET plan_started_at = ? WHERE id = ?", [planStart, req.session.userId]);
                            planDaysLeft = planDurationDays;
                        } else if (planStart === 0) {
                            // انتهت سابقاً — في انتظار إيداع أو تحويل جديد
                            planDaysLeft = 0;
                        } else {
                            const elapsed = Date.now() - planStart;
                            if (elapsed >= PLAN_DURATION_MS) {
                                // انتهت المدة → احتفظ فقط بالأرباح غير المسحوبة (withdrawable)
                                db.run(
                                    `UPDATE users 
                                     SET balance = MAX(0, (SELECT COALESCE(SUM(amount), 0) FROM earnings WHERE user_id = ? AND type IN ('profit','referral','withdraw','withdraw_reverse','transfer_out','transfer_out_work','transfer_out_ref'))),
                                         plan_started_at = 0
                                     WHERE id = ?`,
                                    [req.session.userId, req.session.userId]
                                );
                                db.run("UPDATE account_work_wallets SET balance = 0 WHERE user_id = ?", [req.session.userId]);
                                planDaysLeft = 0;
                            } else {
                                planDaysLeft = Math.ceil((PLAN_DURATION_MS - elapsed) / (24 * 60 * 60 * 1000));
                            }
                        }
                    }
                    // ============ نهاية عدّاد مدة الخطة ============

                    const dayOfWeek = new Date().getDay();
                    const isWeekend = (dayOfWeek === 0 || dayOfWeek === 6);

                    let sessionState = "idle";
                    let currentSession = null;

                    if (session) {
                        currentSession = {
                            id: session.id,
                            planId: session.plan_id,
                            amount: session.amount,
                            startedAt: session.started_at,
                            endsAt: session.ends_at,
                            claimedAt: session.claimed_at,
                            status: session.status
                        };

                        if (session.status === "running") {
                            if (now >= session.ends_at) {
                                sessionState = "done";
                            } else {
                                sessionState = "running";
                            }
                        } else if (session.status === "claimed") {
                            const cooldownEnd = session.started_at + COOLDOWN_MS;
                            if (now < cooldownEnd) {
                                sessionState = "cooldown";
                                currentSession.cooldownEndsAt = cooldownEnd;
                            } else {
                                sessionState = "idle";
                            }
                        }
                    }

                    let dailyAmount = 0;
                    if (currentPlan) {
                        const base = Math.min(planBasis, currentPlan.max_amount);
                        dailyAmount = Math.round(base * currentPlan.daily_percent) / 100;
                    }

                    res.json({
                        status: "success",
                        now: now,
                        isWeekend: isWeekend,
                        dayOfWeek: dayOfWeek,
                        plan: currentPlan ? {
                            id: currentPlan.id,
                            name: currentPlan.name,
                            minAmount: currentPlan.min_amount,
                            maxAmount: currentPlan.max_amount,
                            dailyPercent: currentPlan.daily_percent
                        } : null,
                        deposits: deposits,
                        workWallet: workWallet,
                        planBasis: planBasis,
                        dailyAmount: dailyAmount,
                        sessionState: sessionState,
                        session: currentSession,
                        tradingPaused: userTradingPaused,
                        pauseReason: userPauseReason,
                        planDaysLeft: planDaysLeft
                    });
                });
            }
        );
    });
});

// ===============================
// API: بدء جلسة تداول جديدة
// ===============================
app.post("/api/trade/start", requireAuth, (req, res) => {
    const now = Date.now();
    const SESSION_MS = 2 * 60 * 60 * 1000;
    const COOLDOWN_MS = 24 * 60 * 60 * 1000;

    const dayOfWeek = new Date().getDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
        return res.status(400).json({
            status: "error",
            message: "الأسواق مغلقة في عطلة نهاية الأسبوع (السبت والأحد)"
        });
    }

    // التحقق من حالة تداول المستخدم
    db.get(
        "SELECT total_deposits, trading_paused FROM users WHERE id = ?",
        [req.session.userId],
        (uErr, uRow) => {
            if (uErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            if (!uRow) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
            if (Number(uRow.trading_paused) === 1) {
                return res.status(400).json({
                    status: "error",
                    message: "التداول متوقف — يرجى تفقد الإشعارات",
                    paused: true
                });
            }

            proceedTradeStart();
        }
    );

    function proceedTradeStart(){
    db.get(`SELECT u.total_deposits, COALESCE(w.balance, 0) AS work_wallet_balance
            FROM users u
            LEFT JOIN account_work_wallets w ON w.user_id = u.id
            WHERE u.id = ?`, [req.session.userId], (err, user) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });

        const deposits = Number(user.total_deposits || 0);
        const workWallet = Number(user.work_wallet_balance || 0);
        const planBasis = deposits + workWallet;

        db.all("SELECT * FROM plans ORDER BY min_amount ASC", (pErr, plans) => {
            if (pErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

            let currentPlan = null;
            if (Array.isArray(plans)) {
                for (let i = plans.length - 1; i >= 0; i--) {
                    if (planBasis >= plans[i].min_amount) {
                        currentPlan = plans[i];
                        break;
                    }
                }
            }

            if (!currentPlan) {
                return res.status(400).json({
                    status: "error",
                    message: "لا توجد خطة مفعّلة. أودع على الأقل 50 USDT لتفعيل الخطة الأولى."
                });
            }

            const fail = (msg, code) => {
                db.run("ROLLBACK", () => res.status(code).json({ status: "error", message: msg }));
            };

            db.run("BEGIN IMMEDIATE", (beginErr) => {
                if (beginErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

                db.get(
                    "SELECT * FROM trade_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                    [req.session.userId],
                    (sErr, lastSession) => {
                        if (sErr) return fail("خطأ في الخادم", 500);

                        if (lastSession) {
                            if (lastSession.status === "running" && now < lastSession.ends_at) {
                                return fail("لديك جلسة جارية بالفعل", 400);
                            }
                            if (lastSession.status === "running" && now >= lastSession.ends_at) {
                                return fail("لديك أرباح جاهزة للاستلام. استلمها أولاً ثم ابدأ جلسة جديدة.", 400);
                            }
                            if (lastSession.status === "claimed") {
                                const cooldownEnd = lastSession.started_at + COOLDOWN_MS;
                                if (now < cooldownEnd) {
                                    const remaining = cooldownEnd - now;
                                    const hours = Math.floor(remaining / 3600000);
                                    const minutes = Math.floor((remaining % 3600000) / 60000);
                                    return fail(`الجلسة القادمة متاحة بعد ${hours} ساعة و ${minutes} دقيقة`, 400);
                                }
                            }
                        }

                        const base = Math.min(planBasis, currentPlan.max_amount);
                        const amount = Math.round(base * currentPlan.daily_percent) / 100;
                        const startedAt = now;
                        const endsAt = now + SESSION_MS;

                        db.run(
                            `INSERT INTO trade_sessions (user_id, plan_id, amount, started_at, ends_at, status)
                             VALUES (?, ?, ?, ?, ?, 'running')`,
                            [req.session.userId, currentPlan.id, amount, startedAt, endsAt],
                            function (insErr) {
                                if (insErr || this.changes !== 1) return fail("تعذر بدء الجلسة", 500);
                                const newSessionId = this.lastID;

                                db.run("COMMIT", (commitErr) => {
                                    if (commitErr) return res.status(500).json({ status: "error", message: "تعذر إتمام العملية" });
                                    res.json({
                                        status: "success",
                                        session: {
                                            id: newSessionId,
                                            planId: currentPlan.id,
                                            amount: amount,
                                            startedAt: startedAt,
                                            endsAt: endsAt,
                                            status: "running"
                                        }
                                    });
                                });
                            }
                        );
                    }
                );
            });
        });
    });
    }
});

// ===============================
// API: استلام أرباح جلسة التداول
// ===============================
app.post("/api/trade/claim", requireAuth, (req, res) => {
    const now = Date.now();

    // التحقق من حالة تداول المستخدم
    db.get(
        "SELECT trading_paused FROM users WHERE id = ?",
        [req.session.userId],
        (uErr, uRow) => {
            if (uErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            if (!uRow) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
            if (Number(uRow.trading_paused) === 1) {
                return res.status(400).json({
                    status: "error",
                    message: "التداول متوقف — يرجى تفقد الإشعارات",
                    paused: true
                });
            }

            proceedTradeClaim();
        }
    );

    function proceedTradeClaim(){
    const fail = (msg, code) => {
        db.run("ROLLBACK", () => res.status(code).json({ status: "error", message: msg }));
    };

    db.run("BEGIN IMMEDIATE", (beginErr) => {
        if (beginErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

        db.get(
            "SELECT * FROM trade_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            [req.session.userId],
            (err, session) => {
                if (err) return fail("خطأ في الخادم", 500);
                if (!session) return fail("لا توجد جلسة للاستلام", 404);
                if (session.status !== "running") return fail("الجلسة مستلمة مسبقاً", 400);
                if (now < session.ends_at) {
                    const remaining = session.ends_at - now;
                    const hours = Math.floor(remaining / 3600000);
                    const minutes = Math.floor((remaining % 3600000) / 60000);
                    return fail(`الجلسة لم تنتهِ بعد. متبقٍ: ${hours} ساعة و ${minutes} دقيقة`, 400);
                }

                const amount = Number(session.amount || 0);

                // UPDATE ذرّي: يشترط status='running'
                db.run(
                    "UPDATE trade_sessions SET status = 'claimed', claimed_at = ? WHERE id = ? AND status = 'running'",
                    [now, session.id],
                    function (updErr) {
                        if (updErr || this.changes !== 1) {
                            console.error("TRADE CLAIM UPDATE ERROR:", updErr);
                            return fail("تعذر استلام الأرباح", 500);
                        }

                        db.run(
                            "UPDATE users SET balance = balance + ? WHERE id = ?",
                            [amount, req.session.userId],
                            (balErr) => {
                                if (balErr) return fail("تعذر تحديث الرصيد", 500);

                                db.run(
                                    "INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, 'profit', ?)",
                                    [req.session.userId, amount, "أرباح جلسة تداول #" + session.id],
                                    (earnErr) => {
                                        if (earnErr) return fail("تعذر تسجيل الأرباح", 500);

                                        notifyUser(
                                            req.session.userId,
                                            "تم استلام أرباح التداول",
                                            "تمت إضافة " + amount.toFixed(2) + " USDT إلى رصيدك.",
                                            "success"
                                        );

                                        db.run("COMMIT", (commitErr) => {
                                            if (commitErr) return res.status(500).json({ status: "error", message: "تعذر إتمام العملية" });
                                            res.json({
                                                status: "success",
                                                claimed: amount,
                                                sessionId: session.id
                                            });
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    });
    }
});

// ===============================
// API: سجل جلسات التداول
// ===============================
app.get("/api/trade/history", requireAuth, (req, res) => {
    db.all(
        `SELECT id, plan_id, amount, started_at, ends_at, claimed_at, status
         FROM trade_sessions
         WHERE user_id = ? AND status = 'claimed'
         ORDER BY id DESC LIMIT 30`,
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json({ status: "success", sessions: rows || [] });
        }
    );
});

// ===============================
// لوحة الإدارة + واجهات المالية
// ===============================
const multer = require("multer");
// fs و uploadsDir معرّفان في أعلى الملف

const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"];

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadsDir),
        filename: (req, file, cb) => {
            const extMap = {
                "image/jpeg": ".jpg",
                "image/png": ".png",
                "image/webp": ".webp"
            };
            const safeExt = extMap[file.mimetype] || ".jpg";
            cb(null, "dep_" + Date.now() + "_" + Math.round(Math.random() * 1e6) + safeExt);
        }
    }),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
            return cb(null, true);
        }
        return cb(new Error("INVALID_FILE_TYPE"));
    }
});

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ status: "error", message: "غير مسجل دخول" });
    next();
}
function requireAdmin(req, res, next) {
    if (!req.session.isAdmin) return res.status(401).json({ status: "error", message: "غير مصرح بالوصول" });
    next();
}
function logActivity(req, action, details) {
    db.run(
        "INSERT INTO activity_logs (admin_id, admin_email, action, details) VALUES (?, ?, ?, ?)",
        [req.session.adminId || null, req.session.adminEmail || null, action, details || null]
    );
}
function notifyUser(userId, title, message, type) {
    db.run(
        "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
        [userId, title || "", message || "", type || "info"]
    );
}

// حساب مستوى الخطة بناءً على قيمة الأساس (deposits + workWallet)
// تُرجع: 1, 2, 3, ... (رقم الخطة) أو 0 (لا خطة)
function getPlanLevel(planBasis, plans) {
    if (!Array.isArray(plans) || plans.length === 0) return 0;
    let level = 0;
    for (let i = plans.length - 1; i >= 0; i--) {
        if (planBasis >= plans[i].min_amount) {
            level = i + 1;
            break;
        }
    }
    return level;
}
function toIso(dateStr) {
    if (!dateStr) return null;
    try { const d = new Date(dateStr); return isNaN(d) ? dateStr : d.toISOString(); }
    catch (e) { return dateStr; }
}
function makeInviteCode(userId) {
    return "EL" + String(userId).padStart(4, "0") + Math.random().toString(36).slice(2, 6).toUpperCase();
}
function ensureInviteCode(userId, cb) {
    db.get("SELECT invite_code FROM users WHERE id = ?", [userId], (err, u) => {
        if (err || !u) return cb(null);
        if (u.invite_code) return cb(u.invite_code);
        const code = makeInviteCode(userId);
        db.run("UPDATE users SET invite_code = ? WHERE id = ?", [code, userId], (e) => cb(e ? null : code));
    });
}

// تحديث عنوان المحفظة الواردة + جلبها
function getNetwork(network, cb) {
    db.get("SELECT * FROM wallets WHERE network = ?", [network], cb);
}

// ===============================
// التحقق من الإيداعات على البلوكتشين
// ===============================
const USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const USDT_ERC20_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const USDT_POLYGON_CONTRACT = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";

async function verifyTrc20Deposit(txid, expectedAmount, expectedAddress) {
    try {
        const headers = { 'Accept': 'application/json' };
        if (process.env.TRONGRID_API_KEY) {
            headers['TRON-PRO-API-KEY'] = process.env.TRONGRID_API_KEY;
        }
        const url = `https://api.trongrid.io/v1/accounts/${expectedAddress}/transactions/trc20?limit=200&only_to=true`;
        const res = await fetch(url, { headers });
        if (!res.ok) {
            return { status: 'failed', message: 'فشل الاتصال بـ TronGrid (HTTP ' + res.status + ')' };
        }
        const data = await res.json();
        const list = (data && data.data) || [];
        const tx = list.find(t => t.transaction_id === txid);
        if (!tx) {
            return { status: 'not_found', message: 'TXID غير موجود في آخر 200 معاملة لهذا العنوان' };
        }
        const tokenAddr = tx.token_info && tx.token_info.address;
        if (tokenAddr !== USDT_TRC20_CONTRACT) {
            return {
                status: 'mismatch',
                message: 'العملة المُرسلة ليست USDT (TRC20)',
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: null
            };
        }
        if (tx.to !== expectedAddress) {
            return {
                status: 'mismatch',
                message: 'العنوان المُستلم لا يطابق عنواننا',
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: null
            };
        }
        const decimals = (tx.token_info && tx.token_info.decimals) || 6;
        const amount = Number(tx.value) / Math.pow(10, decimals);
        const tolerance = Math.max(0.001 * expectedAmount, 0.01);
        if (amount + tolerance < expectedAmount) {
            return {
                status: 'mismatch',
                message: `المبلغ المُكتشف (${amount} USDT) لا يطابق المطلوب (${expectedAmount} USDT)`,
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: amount
            };
        }
        return {
            status: 'verified',
            message: `✅ تم التحقق: ${amount} USDT من ${tx.from}`,
            verified_from: tx.from || null,
            verified_to: tx.to || null,
            verified_amount: amount
        };
    } catch (e) {
        console.error('TRC20 verify error:', e);
        return { status: 'failed', message: 'خطأ: ' + e.message };
    }
}

async function verifyEvmDeposit(network, txid, expectedAmount, expectedAddress) {
    try {
        // ERC20 (Ethereum) + Polygon — كلاهما يعمل مع Etherscan V2 المجاني
        const apiKey = process.env.ETHERSCAN_API_KEY;
        if (!apiKey) {
            return { status: 'pending', message: 'مفتاح Etherscan غير مُعدّ' };
        }

        // تحديد chainId + عقد USDT حسب الشبكة
        let chainId, targetContract;
        if (network === 'polygon') {
            chainId = 137;
            targetContract = USDT_POLYGON_CONTRACT;
        } else {
            // erc20
            chainId = 1;
            targetContract = USDT_ERC20_CONTRACT;
        }

        const baseUrl = `https://api.etherscan.io/v2/api?chainid=${chainId}`;
        const url = `${baseUrl}&module=account&action=tokentx&address=${expectedAddress}&page=1&offset=200&sort=desc&apikey=${apiKey}`;
        const res = await fetch(url);
        if (!res.ok) {
            return { status: 'failed', message: 'فشل الاتصال بـ Explorer (HTTP ' + res.status + ')' };
        }
        const data = await res.json();
        if (!data || data.status !== '1' || !Array.isArray(data.result)) {
            const msg = (data && data.message) || 'استجابة غير صحيحة';
            return { status: 'failed', message: 'فشل: ' + msg };
        }
        const tx = data.result.find(t =>
            (t.hash || '').toLowerCase() === String(txid).toLowerCase()
        );
        if (!tx) {
            return { status: 'not_found', message: 'TXID غير موجود في آخر 200 معاملة لهذا العنوان' };
        }
        if ((tx.contractAddress || '').toLowerCase() !== targetContract.toLowerCase()) {
            return {
                status: 'mismatch',
                message: 'العملة المُرسلة ليست USDT',
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: null
            };
        }
        if ((tx.to || '').toLowerCase() !== String(expectedAddress).toLowerCase()) {
            return {
                status: 'mismatch',
                message: 'العنوان المُستلم لا يطابق عنواننا',
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: null
            };
        }
        const decimals = Number(tx.tokenDecimal) || (network === 'bep20' ? 18 : 6);
        const amount = Number(tx.value) / Math.pow(10, decimals);
        const tolerance = Math.max(0.001 * expectedAmount, 0.01);
        if (amount + tolerance < expectedAmount) {
            return {
                status: 'mismatch',
                message: `المبلغ المُكتشف (${amount} USDT) لا يطابق المطلوب (${expectedAmount} USDT)`,
                verified_from: tx.from || null,
                verified_to: tx.to || null,
                verified_amount: amount
            };
        }
        return {
            status: 'verified',
            message: `✅ تم التحقق: ${amount} USDT`,
            verified_from: tx.from || null,
            verified_to: tx.to || null,
            verified_amount: amount
        };
    } catch (e) {
        console.error('EVM verify error:', e);
        return { status: 'failed', message: 'خطأ: ' + e.message };
    }
}

async function verifyDeposit(network, txid, expectedAmount, expectedAddress) {
    if (!txid) return { status: 'failed', message: 'TXID مفقود' };
    if (network === 'trc20') return verifyTrc20Deposit(txid, expectedAmount, expectedAddress);
    if (network === 'erc20' || network === 'polygon') {
        return verifyEvmDeposit(network, txid, expectedAmount, expectedAddress);
    }
    return { status: 'failed', message: 'شبكة غير مدعومة' };
}

// حفظ نتيجة التحقق في قاعدة البيانات
function saveVerificationResult(depositId, result) {
    return new Promise((resolve) => {
        db.run(
            `UPDATE deposits
             SET verification_status = ?,
                 verification_message = ?,
                 verified_at = ?,
                 verified_from = ?,
                 verified_amount = ?,
                 verified_to = ?
             WHERE id = ?`,
            [
                result.status || 'failed',
                result.message || null,
                Date.now(),
                result.verified_from || null,
                result.verified_amount != null ? result.verified_amount : null,
                result.verified_to || null,
                depositId
            ],
            (e) => {
                if (e) console.error('saveVerificationResult error:', e);
                resolve(!e);
            }
        );
    });
}

// ===============================
// التهيئة: إنشاء حساب إدارة + بيانات افتراضية
// ===============================
function seedAdmin() {
    const adminEmail = "elitetrading4433@gmail.com";
const oldEmail = "sifd358@gmail.com";
    const defaultPw = process.env.ADMIN_DEFAULT_PASSWORD;

    if (!defaultPw) {
        console.error("ADMIN_DEFAULT_PASSWORD غير موجود في .env — لن يُنشأ حساب الإدارة");
        return;
    }

    // حذف الحساب القديم إن وُجد
    db.run("DELETE FROM admin_users WHERE email = ?", [oldEmail], () => {
        db.get("SELECT id FROM admin_users WHERE email = ?", [adminEmail], async (err, row) => {
            if (!err && !row) {
                const hash = await bcrypt.hash(defaultPw, 12);
                db.run(
                    "INSERT INTO admin_users (email, password, fullname, role) VALUES (?, ?, ?, ?)",
                    [adminEmail, hash, "مدير النظام", "super_admin"],
                    (e) => {
                        if (e) {
                            console.error("seed admin error: " + e.message);
                        } else if (process.env.NODE_ENV !== 'production') {
                            console.log("حساب الإدارة جاهز");
                        }
                    }
                );
            }
        });
    });
}
function seedPlans() {
    db.get("SELECT COUNT(*) AS c FROM plans", (err, r) => {
        if (err || (r && r.c > 0)) return;
        const defs = [
            ["الخطة الذهبية", 50, 500, 5],
            ["الخطة البلاتينية", 500, 3000, 5],
            ["الخطة الماسية", 3000, 10000, 5],
            ["الخطة الملكية", 10000, 30000, 5]
        ];
        const stmt = db.prepare("INSERT INTO plans (name, min_amount, max_amount, daily_percent) VALUES (?, ?, ?, ?)");
        defs.forEach(p => stmt.run(p[0], p[1], p[2], p[3]));
        stmt.finalize();
    });
}
function seedWallets() {
    db.get("SELECT COUNT(*) AS c FROM wallets", (err, r) => {
        if (err || (r && r.c > 0)) return;
        const defs = [
            ["trc20", "TQSJLCKawiwicZ9CNSVuKjHyjoicveLyD", "operational", 3, 5, 50, 100000, 1],
            ["erc20", "0x3Fe3793A37A3C03C58a2320f505Fafb1d1cc9A31", "operational", 4, 15, 50, 100000, 5],
            ["polygon", "0x3Fe3793A37A3C03C58a2320f505Fafb1d1cc9A31", "operational", 3, 5, 50, 100000, 0.1]
        ];
        const stmt = db.prepare("INSERT INTO wallets (network, address, status, confirmations_required, eta_minutes, min_amount, max_amount, fee_fixed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        defs.forEach(w => stmt.run(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]));
        stmt.finalize();
    });
}
function seedSettings() {
    db.get("SELECT COUNT(*) AS c FROM settings", (err, r) => {
        if (err || (r && r.c > 0)) return;
        const defs = [
            ["site_name", "ELITE TRADING"],
            ["support_email", "support@elite.trading"],
            ["min_deposit", "50"],
            ["max_deposit", "100000"],
            ["min_withdraw", "10"],
            ["referral_percent", "8"],
            ["currency", "USDT"],
            ["referral_share_text", "🔥 انضم إلى ELITE TRADING — خطط استثمارية بعائد يومي 5% وأرباح إحالة على 5 مستويات!"],
            ["telegram_channel", "https://t.me/elite1trading"],
            ["telegram_support", "@elite_trading44"]
        ];
        const stmt = db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)");
        defs.forEach(kv => stmt.run(kv[0], kv[1]));
        stmt.finalize();
    });
}

seedAdmin();
seedPlans();
seedWallets();
seedSettings();

// migration لمرة واحدة: تصحيح النص القديم من "4 مستويات" إلى "5 مستويات"
db.run(
    "UPDATE settings SET value = REPLACE(value, 'على 4 مستويات', 'على 5 مستويات') WHERE key = 'referral_share_text' AND value LIKE '%4 مستويات%'"
);

// تنظيف دوري لجدول password_resets — يحذف الرموز المنتهية أو المستخدمة
function cleanupPasswordResets() {
    db.run(
        "DELETE FROM password_resets WHERE used = 1 OR datetime(expires_at) < datetime('now', '-1 day')",
        function (err) {
            if (err) {
                console.error("[CLEANUP] password_resets error:", err.message);
            } else if (this.changes > 0 && process.env.NODE_ENV !== 'production') {
                console.log(`[CLEANUP] Deleted ${this.changes} old password_resets`);
            }
        }
    );
}

// تنفيذ أول تنظيف بعد 30 ثانية من الإقلاع
setTimeout(cleanupPasswordResets, 30 * 1000);

// تنفيذ التنظيف كل 24 ساعة
setInterval(cleanupPasswordResets, 24 * 60 * 60 * 1000);

// ===============================
// صفحة الإدارة
// ===============================
app.get("/admin", (req, res) => {
    if (!req.session.isAdmin) return res.redirect("/admin-login");
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin-login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-login.html"));
});

// ===============================
// API المستخدم: الرصيد
// ===============================
app.get("/api/user/balance", requireAuth, (req, res) => {
    db.get(
        "SELECT id, balance, referral_code FROM users WHERE id = ?",
        [req.session.userId],
        (err, user) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });

            db.get(
                `SELECT COALESCE(SUM(amount), 0) AS withdrawable
                 FROM earnings
                 WHERE user_id = ? AND type IN ('profit','referral','withdraw','withdraw_reverse','transfer_out','transfer_out_work','transfer_out_ref')`,
                [user.id],
                (e2, earningsRow) => {
                    if (e2) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                    const withdrawable = Math.max(Number(earningsRow.withdrawable || 0), 0);
                    const mainBalance = Number(user.balance || 0);

                    db.get(
                        "SELECT COALESCE(balance, 0) AS work_balance FROM account_work_wallets WHERE user_id = ?",
                        [user.id],
                        (e3, workRow) => {
                            if (e3) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                            const workBalance = Number((workRow && workRow.work_balance) || 0);
                            const totalBalance = mainBalance + workBalance;

                            ensureInviteCode(user.id, (code) => {
                                res.json({
                                    balance: totalBalance,
                                    mainBalance: mainBalance,
                                    workBalance: workBalance,
                                    withdrawable: withdrawable,
                                    capital: Math.max(mainBalance - withdrawable, 0),
                                    accountRef: code || ""
                                });
                            });
                        }
                    );
                }
            );
        }
    );
});

// ===============================
// API الإيداع
// ===============================
app.get("/api/deposit/networks", requireAuth, (req, res) => {
    db.all("SELECT * FROM wallets ORDER BY id", (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json((rows || []).map(w => ({
            id: w.network,
            address: w.address,
            status: w.status,
            confirmationsRequired: w.confirmations_required,
            etaMinutes: w.eta_minutes,
            minAmount: w.min_amount,
            maxAmount: w.max_amount
        })));
    });
});
// ===============================
// API عام: قائمة الخطط النشطة
// ===============================
app.get("/api/plans", (req, res) => {
    db.all(
        "SELECT id, name, min_amount, max_amount, daily_percent, duration_days FROM plans WHERE active = 1 ORDER BY min_amount ASC",
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json(rows || []);
        }
    );
});

app.get("/api/deposit/history", requireAuth, (req, res) => {
    db.all(
        `SELECT id, amount, network, created_at AS date, status
         FROM deposits WHERE user_id = ? ORDER BY id DESC LIMIT 100`,
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json((rows || []).map(r => ({ ...r, date: toIso(r.date) })));
        }
    );
});

app.post("/api/deposit/confirm", requireAuth, upload.single("proof"), (req, res) => {
    const { network, address, amount, txid, hash, amountSent, notes } = req.body;
    const idempotencyKey = req.headers["x-idempotency-key"];
    if (!network || !amount) {
        return res.status(400).json({ status: "error", message: "بيانات غير مكتملة" });
    }

    const cleanNetwork = String(network).trim().toLowerCase();
    const cleanTxid = txid ? String(txid).trim() : null;

    getNetwork(cleanNetwork, (err, net) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!net) return res.status(400).json({ status: "error", message: "شبكة غير مدعومة" });

        const min = net.min_amount || 50;
        const max = net.max_amount || 30000;
        const amt = Number(amount);
        if (isNaN(amt) || amt < min || amt > max) {
            return res.status(400).json({ status: "error", message: "المبلغ خارج الحدود المسموح بها" });
        }

        // منع TXID مكرر
        const insertDeposit = () => {
            if (idempotencyKey) {
                db.get(
                    "SELECT id FROM deposits WHERE notes = ? LIMIT 1",
                    ["__IDEM__:" + idempotencyKey],
                    (idemErr, idemRow) => {
                        if (idemErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                        if (idemRow) {
                            return res.status(400).json({
                                status: "error",
                                message: "تم إرسال هذا الطلب مسبقاً"
                            });
                        }
                        doInsert();
                    }
                );
            } else {
                doInsert();
            }
        };

        const doInsert = () => {
            db.run(
                `INSERT INTO deposits (user_id, amount, network, address, txid, hash, amount_sent, notes, proof_path, status, verification_status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending')`,
                [
                    req.session.userId,
                    amt,
                    cleanNetwork,
                    address || net.address || null,
                    cleanTxid,
                    hash || null,
                    amountSent != null ? Number(amountSent) : null,
                    (idempotencyKey ? "__IDEM__:" + idempotencyKey + " | " : "") + (notes || ""),
                    req.file ? "/uploads/" + req.file.filename : null
                ],
                function (insErr) {
                    if (insErr) return res.status(500).json({ status: "error", message: "تعذر حفظ الإيداع" });
                    const depositId = this.lastID;

                    // استدعاء التحقق الآلي (لا نُوقفه على الرد)
                    if (cleanTxid) {
                        verifyDeposit(cleanNetwork, cleanTxid, amt, net.address)
                            .then(result => {
                                return saveVerificationResult(depositId, result).then(() => result);
                            })
                            .then(result => {
                                if (process.env.NODE_ENV !== 'production') {
                                    console.log(`[VERIFY] Deposit #${depositId} → ${result.status}`);
                                }
                                // القبول التلقائي عند نجاح التحقق
                                if (result.status === 'verified') {
                                    autoApproveDeposit(depositId, req.session.adminId || null)
                                        .then(ok => {
                                            if (ok && process.env.NODE_ENV !== 'production') {
                                                console.log(`[AUTO-APPROVE] Deposit #${depositId} approved automatically`);
                                            }
                                        })
                                        .catch(e => console.error(`[AUTO-APPROVE] Deposit #${depositId} error:`, e));
                                }
                            })
                            .catch(e => {
                                console.error(`[VERIFY] Deposit #${depositId} error:`, e);
                            });
                    } else {
                        saveVerificationResult(depositId, {
                            status: 'failed',
                            message: 'لم يتم تقديم TXID'
                        });
                    }

                    res.json({ success: true, depositId: depositId });
                }
            );
        };

        if (cleanTxid) {
            db.get(
                "SELECT id FROM deposits WHERE LOWER(txid) = LOWER(?) LIMIT 1",
                [cleanTxid],
                (dupErr, dup) => {
                    if (dupErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                    if (dup) {
                        return res.status(400).json({
                            status: "error",
                            message: "هذا الـ TXID مُستخدم بالفعل في طلب إيداع سابق"
                        });
                    }
                    insertDeposit();
                }
            );
        } else {
            insertDeposit();
        }
    });
});

// ===============================
// API السحب
// ===============================
app.get("/api/withdraw/networks", requireAuth, (req, res) => {
    db.get("SELECT value FROM settings WHERE key = 'min_withdraw'", (sErr, sRow) => {
        const globalMin = (sRow && Number(sRow.value)) || 10;
        db.all("SELECT * FROM wallets ORDER BY id", (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json((rows || []).map(w => ({ id: w.network, feeFixed: w.fee_fixed || 0, minAmount: globalMin })));
        });
    });
});

app.get("/api/withdraw/history", requireAuth, (req, res) => {
    db.all(
        "SELECT id, amount, network, address, created_at AS date, status FROM withdrawals WHERE user_id = ? ORDER BY id DESC LIMIT 100",
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json((rows || []).map(r => ({ ...r, date: toIso(r.date) })));
        }
    );
});

app.post("/api/withdraw/submit", requireAuth, (req, res) => {
    const { network, address, amount } = req.body;
    if (!network || !address) return res.status(400).json({ status: "error", message: "بيانات غير مكتملة" });
    const amt = Number(amount);
    if (!amt || isNaN(amt) || amt <= 0) {
        return res.status(400).json({ status: "error", message: "بيانات سحب غير صحيحة" });
    }

    const cleanNetwork = String(network).trim().toLowerCase();
    const cleanAddress = String(address).trim();

    if (!isValidWalletAddress(cleanNetwork, cleanAddress)) {
        return res.status(400).json({
            status: "error",
            message: "صيغة عنوان المحفظة غير صحيحة لهذه الشبكة"
        });
    }

    getNetwork(cleanNetwork, (nErr, net) => {
        if (nErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!net) return res.status(400).json({ status: "error", message: "شبكة غير مدعومة" });

        db.get("SELECT value FROM settings WHERE key = 'min_withdraw'", (sErr, sRow) => {
            const min = (sRow && Number(sRow.value)) || 10;
            if (amt < min) return res.status(400).json({ status: "error", message: `الحد الأدنى للسحب ${min} USDT` });

            const feeAmt = Number(net.fee_fixed) || 0;
            const netAmt = Math.max(amt - feeAmt, 0);

            const fail = (msg, code) => {
                db.run("ROLLBACK", () => res.status(code).json({ status: "error", message: msg }));
            };

            db.run("BEGIN IMMEDIATE", (beginErr) => {
                if (beginErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

                db.get(
                    `SELECT u.balance, u.blocked,
                            COALESCE((SELECT SUM(amount) FROM earnings WHERE user_id = u.id AND type IN ('profit','referral','withdraw','withdraw_reverse','transfer_out','transfer_out_work','transfer_out_ref')), 0) AS withdrawable
                     FROM users u WHERE u.id = ?`,
                    [req.session.userId],
                    (err, user) => {
                        if (err) return fail("خطأ في الخادم", 500);
                        if (!user) return fail("المستخدم غير موجود", 404);
                        if (user.blocked) return fail("الحساب موقوف", 403);
                        if (Number(user.withdrawable) < amt) {
                            return fail("الرصيد القابل للسحب غير كافٍ. المتاح: " + Number(user.withdrawable).toFixed(2) + " USDT", 400);
                        }

                        db.run(
                            `INSERT INTO withdrawals (user_id, amount, network, address, fee, net_amount, status)
                             VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
                            [req.session.userId, amt, cleanNetwork, cleanAddress, feeAmt, netAmt],
                            function (insErr) {
                                if (insErr || this.changes !== 1) return fail("تعذر حفظ طلب السحب", 500);
                                const newWithdrawalId = this.lastID;

                                db.run(
                                    "UPDATE users SET balance = balance - ?, total_withdrawals = total_withdrawals + ? WHERE id = ? AND balance >= ?",
                                    [amt, amt, req.session.userId, amt],
                                    function (updErr) {
                                        if (updErr || this.changes !== 1) return fail("الرصيد غير كافٍ", 400);

                                        db.run(
                                            "INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, 'withdraw', ?)",
                                            [req.session.userId, -amt, "سحب #WD-" + newWithdrawalId],
                                            (earnErr) => {
                                                if (earnErr) return fail("تعذر تسجيل حركة السحب", 500);
                                                db.run("COMMIT", (commitErr) => {
                                                    if (commitErr) return res.status(500).json({ status: "error", message: "تعذر إتمام العملية" });
                                                    res.json({ success: true, requestId: "WD-" + newWithdrawalId });
                                                });
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    });
});

// ===============================
// تسجيل دخول الإدارة
// ===============================
app.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ status: "error", message: "يرجى إدخال البريد وكلمة المرور" });
    }
    db.get("SELECT * FROM admin_users WHERE email = ?", [email.trim().toLowerCase()], async (err, admin) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في قاعدة البيانات" });
        if (!admin) return res.status(401).json({ status: "error", message: "بيانات الدخول غير صحيحة" });
        const ok = await bcrypt.compare(password, admin.password);
        if (!ok) return res.status(401).json({ status: "error", message: "بيانات الدخول غير صحيحة" });

        db.run("INSERT INTO activity_logs (admin_id, admin_email, action, details) VALUES (?, ?, ?, ?)",
            [admin.id, admin.email, "تسجيل دخول", "تم تسجيل دخول المشرف"]);

        // إعادة توليد الجلسة (حماية من Session Fixation)
        req.session.regenerate((regenErr) => {
            if (regenErr) {
                console.error("ADMIN SESSION REGENERATE ERROR:", regenErr);
                return res.status(500).json({ status: "error", message: "حدث خطأ أثناء تسجيل الدخول" });
            }

            req.session.isAdmin = true;
            req.session.adminId = admin.id;
            req.session.adminEmail = admin.email;

            res.json({ status: "success", admin: { id: admin.id, email: admin.email, fullname: admin.fullname, role: admin.role } });
        });
    });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
    logActivity(req, "تسجيل خروج", "تم تسجيل خروج المشرف");
    req.session.isAdmin = false;
    req.session.adminId = null;
    req.session.adminEmail = null;
    res.json({ status: "success" });
});

// ===============================
// نسيت كلمة مرور المدير (إرسال رمز)
// ===============================
app.post("/api/admin/forgot-password", (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ status: "error", message: "يرجى إدخال البريد الإلكتروني" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    db.get("SELECT id, email FROM admin_users WHERE email = ?", [normalizedEmail], (err, admin) => {
        if (err) {
            console.error("ADMIN FORGOT ERROR:", err);
            return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        }

        // لأسباب أمنية: نفس الرد سواء كان البريد مسجلاً أم لا
        if (!admin) {
            return res.json({
                status: "success",
                message: "إذا كان البريد مسجلاً لدينا، فسيصلك رمز التحقق"
            });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        db.run(
            "INSERT INTO password_resets (email, code, expires_at) VALUES (?, ?, ?)",
            [normalizedEmail, code, expiresAt],
            async function (insertErr) {
                if (insertErr) {
                    console.error("ADMIN FORGOT INSERT ERROR:", insertErr);
                    return res.status(500).json({ status: "error", message: "حدث خطأ أثناء إنشاء الرمز" });
                }

                                   try {
                        await sendEmail({
                            to: normalizedEmail,
                            subject: "رمز استعادة كلمة مرور المدير - ELITE TRADING",
                            html: `
                                <div style="font-family: Arial; text-align: center; padding: 20px;">
                                    <h2 style="color:#0eae91;">ELITE TRADING</h2>
                                    <p style="color:#e8a33d;font-weight:bold;">رمز استعادة كلمة مرور لوحة الإدارة</p>
                                    <p>رمز التحقق الخاص بك هو:</p>
                                    <h1 style="letter-spacing: 6px;color:#0a1412;">${code}</h1>
                                    <p style="color:#888;">صالح لمدة 15 دقيقة فقط.</p>
                                    <p style="color:#888;font-size:12px;">إذا لم تطلب هذا الرمز، تجاهل هذه الرسالة.</p>
                                </div>
                            `
                        });

                        console.log("ADMIN RESET CODE SENT to " + normalizedEmail);

                        res.json({
                            status: "success",
                            message: "تم إرسال رمز التحقق إلى بريدك الإلكتروني"
                        });
                    } catch (mailErr) {
                        console.error("ADMIN FORGOT MAIL ERROR:", mailErr);
                        res.status(500).json({
                            status: "error",
                            message: "تعذر إرسال البريد الإلكتروني"
                        });
                    }
            }
        );
    });
});

// ===============================
// تأكيد رمز استعادة كلمة مرور المدير
// ===============================
app.post("/api/admin/reset-password", async (req, res) => {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
        return res.status(400).json({ status: "error", message: "يرجى تعبئة جميع الحقول" });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ status: "error", message: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    db.get("SELECT id FROM admin_users WHERE email = ?", [normalizedEmail], (aErr, admin) => {
        if (aErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!admin) return res.status(400).json({ status: "error", message: "البريد الإلكتروني غير صحيح" });

        db.get(
            `SELECT * FROM password_resets
             WHERE email = ? AND code = ? AND used = 0
             ORDER BY id DESC LIMIT 1`,
            [normalizedEmail, code.trim()],
            async (err, resetRow) => {
                if (err) {
                    console.error("ADMIN RESET ERROR:", err);
                    return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                }

                if (!resetRow) {
                    return res.status(400).json({ status: "error", message: "الرمز غير صحيح" });
                }

                if (new Date(resetRow.expires_at) < new Date()) {
                    return res.status(400).json({ status: "error", message: "انتهت صلاحية الرمز، يرجى طلب رمز جديد" });
                }

                const hashedPassword = await bcrypt.hash(newPassword, 12);

                db.run(
                    "UPDATE admin_users SET password = ? WHERE email = ?",
                    [hashedPassword, normalizedEmail],
                    function (updateErr) {
                        if (updateErr) {
                            console.error("ADMIN RESET UPDATE ERROR:", updateErr);
                            return res.status(500).json({ status: "error", message: "تعذر تحديث كلمة المرور" });
                        }

                        db.run("UPDATE password_resets SET used = 1 WHERE id = ?", [resetRow.id]);

                        // تسجيل النشاط
                        db.run(
                            "INSERT INTO activity_logs (admin_email, action, details) VALUES (?, ?, ?)",
                            [normalizedEmail, "استعادة كلمة المرور", "تم تغيير كلمة مرور المدير عبر البريد الإلكتروني"]
                        );

                        res.json({
                            status: "success",
                            message: "تم تغيير كلمة المرور بنجاح"
                        });
                    }
                );
            }
        );
    });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
    db.get("SELECT id, email, fullname, role FROM admin_users WHERE id = ?", [req.session.adminId], (err, admin) => {
        if (err || !admin) return res.status(401).json({ status: "error", message: "غير مصرح" });
        res.json({ status: "success", admin: admin });
    });
});

// ===============================
// API عام: نص رسالة الإحالة
// ===============================
app.get("/api/referral/message", (req, res) => {
    db.get("SELECT value FROM settings WHERE key = 'referral_share_text'", (err, row) => {
        const defaultText = "🔥 انضم إلى ELITE TRADING — خطط استثمارية بعائد يومي 5% وأرباح إحالة على 5 مستويات!";
        res.json({
            status: "success",
            message: (row && row.value) ? row.value : defaultText
        });
    });
});

// ===============================
// API عام: روابط التواصل (تليجرام)
// ===============================
app.get("/api/settings/contact", (req, res) => {
    db.all(
        "SELECT key, value FROM settings WHERE key IN ('telegram_channel','telegram_support')",
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            const out = { telegram_channel: "", telegram_support: "" };
            (rows || []).forEach(r => { out[r.key] = r.value || ""; });
            res.json(out);
        }
    );
});

// ===============================
// لوحة التحكم: الإحصائيات
// ===============================
app.get("/api/admin/stats", requireAdmin, (req, res) => {
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

    db.get("SELECT COUNT(*) AS users, SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked FROM users", (e1, u) => {
        db.get(
            "SELECT COUNT(*) AS newUsers FROM users WHERE date(created_at) >= date(?)",
            [weekAgo],
            (e2, nu) => {

                db.get(
                    `SELECT COUNT(*) AS cnt, COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END),0) AS pendingSum,
                            COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END),0) AS approvedSum,
                            COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) AS pendingCnt FROM deposits`,
                    (e3, d) => {

                        db.get(
                            `SELECT COUNT(*) AS cnt, COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END),0) AS pendingSum,
                                    COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END),0) AS approvedSum,
                                    COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) AS pendingCnt FROM withdrawals`,
                            (e4, w) => {

                                db.get(
                                    `SELECT COALESCE(SUM(CASE WHEN type='profit' THEN amount ELSE 0 END),0) AS profit,
                                            COALESCE(SUM(CASE WHEN type='referral' THEN amount ELSE 0 END),0) AS referral,
                                            COALESCE(SUM(amount),0) AS total FROM earnings`,
                                    (e5, ear) => {

                                        db.all(
                                            `SELECT date(created_at) AS d, SUM(amount) AS s FROM deposits WHERE status='approved'
                                             GROUP BY date(created_at) ORDER BY d DESC LIMIT 14`,
                                            (e6, chart) => {

                                                db.all(
                                                    "SELECT a.action, a.details, a.created_at, COALESCE(a.admin_email,'') AS admin_email FROM activity_logs a ORDER BY a.id DESC LIMIT 10",
                                                    (e7, logs) => {
                                                        res.json({
                                                            users: { total: (u && u.users) || 0, blocked: (u && u.blocked) || 0, newUsers: (nu && nu.newUsers) || 0 },
                                                            deposits: d || {},
                                                            withdrawals: w || {},
                                                            earnings: ear || { profit: 0, referral: 0, total: 0 },
                                                            chart: (chart || []).map(c => ({ d: c.d, s: c.s })),
                                                            logs: logs || []
                                                        });
                                                    }
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    });
});

// ===============================
// إدارة المستخدمين
// ===============================
app.get("/api/admin/users", requireAdmin, (req, res) => {
    const q = (req.query.q || "").trim();
    const status = req.query.status || "";
    let sql = `SELECT u.id, u.email, u.fullname, u.phone, u.referral_code, u.invite_code,
                      u.balance, u.blocked, u.status, u.last_login, u.created_at,
                      u.total_deposits, u.total_withdrawals, u.trading_paused,
                      u.trading_paused_reason, u.plan_started_at, u.referrer_id,
                      COALESCE((SELECT balance FROM account_work_wallets WHERE user_id = u.id), 0) AS work_balance,
                      (SELECT COUNT(*) FROM deposits dd WHERE dd.user_id = u.id) AS deposits_cnt,
                      (SELECT COUNT(*) FROM withdrawals ww WHERE ww.user_id = u.id) AS withdrawals_cnt
               FROM users u WHERE 1=1`;
    const params = [];
    if (q) { sql += " AND (u.email LIKE ? OR u.fullname LIKE ? OR u.phone LIKE ? OR u.referral_code LIKE ?)"; const like = "%" + q + "%"; params.push(like, like, like, like); }
    if (status === "blocked") sql += " AND u.blocked = 1";
    sql += " ORDER BY COALESCE(u.total_deposits, 0) DESC, u.id DESC LIMIT 200";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        const total = rows.reduce((s, r) => s + (r.balance || 0), 0);
        res.json({ users: rows, totalBalance: total });
    });
});

app.post("/api/admin/users", requireAdmin, async (req, res) => {
    const { email, password, fullname, phone, balance } = req.body;
    if (!email || !password) return res.status(400).json({ status: "error", message: "البريد وكلمة المرور مطلوبان" });
    try {
        const hash = await bcrypt.hash(password, 12);
        const code = "EL" + Math.random().toString(36).slice(2, 8).toUpperCase();
        db.run(
            "INSERT INTO users (email, password, fullname, phone, referral_code, balance) VALUES (?, ?, ?, ?, ?, ?)",
            [email.trim().toLowerCase(), hash, fullname || null, phone || null, code, Number(balance) || 0],
            function (err) {
                if (err) return res.status(400).json({ status: "error", message: err.message.includes("UNIQUE") ? "البريد مسجل مسبقاً" : "تعذر إنشاء المستخدم" });
                logActivity(req, "إنشاء مستخدم", email);
                res.json({ status: "success", message: "تم إنشاء المستخدم", userId: this.lastID });
            }
        );
    } catch (e) {
        res.status(500).json({ status: "error", message: "خطأ في الخادم" });
    }
});

app.put("/api/admin/users/:id", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const { balance, blocked, fullname, phone, status } = req.body;
    const fields = [];
    const params = [];
    if (balance != null && !isNaN(Number(balance))) { fields.push("balance = ?"); params.push(Number(balance)); }
    if (blocked != null) { fields.push("blocked = ?"); params.push(blocked ? 1 : 0); }
    if (status !== undefined) { fields.push("status = ?"); params.push(status); }
    if (fullname !== undefined) { fields.push("fullname = ?"); params.push(fullname); }
    if (phone !== undefined) { fields.push("phone = ?"); params.push(phone); }
    if (!fields.length) return res.status(400).json({ status: "error", message: "لا توجد بيانات للتحديث" });

    params.push(id);
    db.run("UPDATE users SET " + fields.join(", ") + " WHERE id = ?", params, function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر تحديث المستخدم" });
        logActivity(req, "تعديل مستخدم", "المستخدم #" + id + " (" + fields.join(", ") + ")");
        res.json({ status: "success", message: "تم التحديث بنجاح" });
    });
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    db.run("UPDATE users SET blocked = 1 WHERE id = ?", [id], function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر تعطيل المستخدم" });
        logActivity(req, "حظر مستخدم", "المستخدم #" + id);
        res.json({ status: "success", message: "تم حظر المستخدم" });
    });
});

// ===============================
// تفاصيل مستخدم كاملة (للأدمن)
// ===============================
app.get("/api/admin/users/:id/details", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) {
        return res.status(400).json({ status: "error", message: "معرّف غير صحيح" });
    }

    db.get(
        `SELECT id, email, fullname, phone, referral_code, invite_code, referrer_id,
                balance, total_deposits, total_withdrawals, status, blocked,
                last_login, created_at, trading_paused, trading_paused_reason, plan_started_at
         FROM users WHERE id = ?`,
        [id],
        (err, user) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });

            // الأرصدة
            db.get(
                "SELECT COALESCE(balance, 0) AS work_balance FROM account_work_wallets WHERE user_id = ?",
                [id],
                (e2, workRow) => {
                    db.get(
                        `SELECT COALESCE(SUM(amount), 0) AS withdrawable
                         FROM earnings WHERE user_id = ?
                         AND type IN ('profit','referral','withdraw','withdraw_reverse','transfer_out','transfer_out_work','transfer_out_ref')`,
                        [id],
                        (e3, earRow) => {
                            // الإحصائيات
                            db.get(
                                `SELECT
                                    (SELECT COUNT(*) FROM deposits WHERE user_id = ?) AS dep_cnt,
                                    (SELECT COALESCE(SUM(amount),0) FROM deposits WHERE user_id = ? AND status='approved') AS dep_sum,
                                    (SELECT COUNT(*) FROM withdrawals WHERE user_id = ?) AS wd_cnt,
                                    (SELECT COALESCE(SUM(amount),0) FROM withdrawals WHERE user_id = ? AND status='approved') AS wd_sum,
                                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = ?) AS ref_cnt,
                                    (SELECT COALESCE(SUM(commission),0) FROM referrals WHERE referrer_id = ?) AS ref_sum`,
                                [id, id, id, id, id, id],
                                (e4, stats) => {
                                    // آخر 50 إيداعاً
                                    db.all(
                                        `SELECT id, amount, network, status, txid, created_at, verification_status
                                         FROM deposits WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
                                        [id],
                                        (e5, deposits) => {
                                            // آخر 50 سحباً
                                            db.all(
                                                `SELECT id, amount, fee, net_amount, network, address, status, created_at
                                                 FROM withdrawals WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
                                                [id],
                                                (e6, withdrawals) => {
                                                    // آخر 50 تحويلاً
                                                    db.all(
                                                        `SELECT id, amount, source, target, status, created_at
                                                         FROM account_transfers WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
                                                        [id],
                                                        (e7, transfers) => {
                                                            // آخر 50 حركة
                                                            db.all(
                                                                `SELECT id, title, type, amount, status, created_at
                                                                 FROM account_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
                                                                [id],
                                                                (e8, transactions) => {
                                                                    // آخر 30 إشعاراً
                                                                    db.all(
                                                                        `SELECT id, title, message, type, read, created_at
                                                                         FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 30`,
                                                                        [id],
                                                                        (e9, notifications) => {
                                                                            // المُحيل (إن وُجد)
                                                                            const finalize = (referrer) => {
                                                                                const mainBalance = Number(user.balance || 0);
                                                                                const workBalance = Number((workRow && workRow.work_balance) || 0);
                                                                                const withdrawable = Math.max(Number((earRow && earRow.withdrawable) || 0), 0);

                                                                                res.json({
                                                                                    status: "success",
                                                                                    user: {
                                                                                        id: user.id,
                                                                                        email: user.email,
                                                                                        fullname: user.fullname || "",
                                                                                        phone: user.phone || "",
                                                                                        referralCode: user.referral_code || "",
                                                                                        inviteCode: user.invite_code || "",
                                                                                        referrerId: user.referrer_id || null,
                                                                                        status: user.status || "active",
                                                                                        blocked: !!user.blocked,
                                                                                        lastLogin: user.last_login || null,
                                                                                        createdAt: user.created_at || null,
                                                                                        tradingPaused: Number(user.trading_paused) === 1,
                                                                                        tradingPausedReason: user.trading_paused_reason || "",
                                                                                        planStartedAt: user.plan_started_at || null,
                                                                                        totalDeposits: Number(user.total_deposits || 0),
                                                                                        totalWithdrawals: Number(user.total_withdrawals || 0)
                                                                                    },
                                                                                    balances: {
                                                                                        main: mainBalance,
                                                                                        work: workBalance,
                                                                                        total: mainBalance + workBalance,
                                                                                        withdrawable: withdrawable
                                                                                    },
                                                                                    stats: {
                                                                                        depositsCount: (stats && stats.dep_cnt) || 0,
                                                                                        depositsSum: (stats && stats.dep_sum) || 0,
                                                                                        withdrawalsCount: (stats && stats.wd_cnt) || 0,
                                                                                        withdrawalsSum: (stats && stats.wd_sum) || 0,
                                                                                        referralsCount: (stats && stats.ref_cnt) || 0,
                                                                                        referralsCommission: (stats && stats.ref_sum) || 0
                                                                                    },
                                                                                    referrer: referrer || null,
                                                                                    deposits: deposits || [],
                                                                                    withdrawals: withdrawals || [],
                                                                                    transfers: transfers || [],
                                                                                    transactions: transactions || [],
                                                                                    notifications: notifications || []
                                                                                });
                                                                            };

                                                                            if (user.referrer_id) {
                                                                                db.get(
                                                                                    "SELECT id, email, fullname FROM users WHERE id = ?",
                                                                                    [user.referrer_id],
                                                                                    (e10, refUser) => finalize(refUser || null)
                                                                                );
                                                                            } else {
                                                                                finalize(null);
                                                                            }
                                                                        }
                                                                    );
                                                                }
                                                            );
                                                        }
                                                    );
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

// ===============================
// إيقاف تداول مستخدم (مع إشعار)
// ===============================
app.post("/api/admin/users/:id/pause-trading", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const { reason } = req.body;

    if (!reason || !String(reason).trim()) {
        return res.status(400).json({ status: "error", message: "يجب كتابة سبب الإيقاف" });
    }
    const cleanReason = String(reason).trim();

    db.get("SELECT id, email, trading_paused FROM users WHERE id = ?", [id], (err, user) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
        if (Number(user.trading_paused) === 1) {
            return res.status(400).json({ status: "error", message: "تداول المستخدم موقوف بالفعل" });
        }

        db.run(
            "UPDATE users SET trading_paused = 1, trading_paused_reason = ? WHERE id = ?",
            [cleanReason, id],
            function (updErr) {
                if (updErr) return res.status(500).json({ status: "error", message: "تعذر إيقاف التداول" });

                notifyUser(id, "⛔ تم إيقاف التداول مؤقتاً", cleanReason, "warning");
                logActivity(req, "إيقاف تداول مستخدم", user.email + " — " + cleanReason);

                res.json({ status: "success", message: "تم إيقاف التداول وإرسال إشعار" });
            }
        );
    });
});

// ===============================
// استئناف تداول مستخدم (مع إشعار)
// ===============================
app.post("/api/admin/users/:id/resume-trading", requireAdmin, (req, res) => {
    const id = Number(req.params.id);

    db.get("SELECT id, email, trading_paused FROM users WHERE id = ?", [id], (err, user) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!user) return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
        if (Number(user.trading_paused) === 0) {
            return res.status(400).json({ status: "error", message: "تداول المستخدم يعمل بالفعل" });
        }

        db.run(
            "UPDATE users SET trading_paused = 0, trading_paused_reason = NULL WHERE id = ?",
            [id],
            function (updErr) {
                if (updErr) return res.status(500).json({ status: "error", message: "تعذر استئناف التداول" });

                notifyUser(id, "✅ عاد تداولك للعمل", "يمكنك الآن بدء جلسات تداول جديدة.", "success");
                logActivity(req, "استئناف تداول مستخدم", user.email);

                res.json({ status: "success", message: "تم استئناف التداول وإرسال إشعار" });
            }
        );
    });
});

// ===============================
// إدارة الإيداعات
// ===============================
app.get("/api/admin/deposits", requireAdmin, (req, res) => {
    const status = req.query.status || "";
    let sql = "SELECT d.*, u.email AS user_email, u.fullname AS user_name FROM deposits d LEFT JOIN users u ON u.id = d.user_id";
    const params = [];
    if (status && status !== "all") { sql += " WHERE d.status = ?"; params.push(status); }
    sql += " ORDER BY d.id DESC LIMIT 300";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});
// ===============================
// القبول التلقائي عند نجاح التحقق
// ===============================
function autoApproveDeposit(depositId, adminId) {
    return new Promise((resolve) => {
        db.run("BEGIN IMMEDIATE", (beginErr) => {
            if (beginErr) {
                console.error(`[AUTO-APPROVE] BEGIN error:`, beginErr);
                return resolve(false);
            }

            const rollback = () => db.run("ROLLBACK", () => resolve(false));

            db.get("SELECT * FROM deposits WHERE id = ?", [depositId], (err, dep) => {
                if (err || !dep) {
                    console.error(`[AUTO-APPROVE] Deposit #${depositId} not found`);
                    return rollback();
                }
                if (dep.status !== "pending") {
                    console.log(`[AUTO-APPROVE] Deposit #${depositId} already processed (status=${dep.status})`);
                    return rollback();
                }

                db.run(
                    "UPDATE deposits SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'",
                    [adminId, depositId],
                    function (updErr) {
                        if (updErr || this.changes !== 1) {
                            console.error(`[AUTO-APPROVE] Update error:`, updErr);
                            return rollback();
                        }

                        db.get(
                            "SELECT u.total_deposits, u.plan_started_at, COALESCE(w.balance, 0) AS work_balance FROM users u LEFT JOIN account_work_wallets w ON w.user_id = u.id WHERE u.id = ?",
                            [dep.user_id],
                            (planErr, userRow) => {
                                if (planErr || !userRow) {
                                    console.error(`[AUTO-APPROVE] User plan fetch error:`, planErr);
                                    return rollback();
                                }

                                db.all("SELECT id, min_amount FROM plans WHERE active = 1 ORDER BY min_amount ASC", (plansErr, plans) => {
                                    if (plansErr) {
                                        console.error(`[AUTO-APPROVE] Plans fetch error:`, plansErr);
                                        return rollback();
                                    }

                                    const planList = Array.isArray(plans) ? plans : [];
                                    const beforeTotalDeposits = Number(userRow.total_deposits || 0);
                                    const workWallet = Number(userRow.work_balance || 0);
                                    const planBasisBefore = beforeTotalDeposits + workWallet;
                                    const planBasisAfter = planBasisBefore + Number(dep.amount);

                                    const levelBefore = getPlanLevel(planBasisBefore, planList);
                                    const levelAfter = getPlanLevel(planBasisAfter, planList);

                                    const oldStart = userRow.plan_started_at;
                                    const startNum = (oldStart !== null && oldStart !== undefined) ? Number(oldStart) : null;

                                    const isUpgrade = levelAfter > levelBefore;
                                    const isNewPlan = (startNum === 0) || (startNum === null);

                                    const newPlanStart = (isUpgrade || isNewPlan) ? Date.now() : oldStart;

                                    db.run(
                                        "UPDATE users SET balance = balance + ?, total_deposits = total_deposits + ?, plan_started_at = ? WHERE id = ?",
                                        [dep.amount, dep.amount, newPlanStart, dep.user_id],
                                        (balErr) => {
                                            if (balErr) {
                                                console.error(`[AUTO-APPROVE] Balance update error:`, balErr);
                                                return rollback();
                                            }

                                            db.run(
                                                "INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, 'deposit', ?)",
                                                [dep.user_id, dep.amount, "رصيد مُقبل تلقائياً من إيداع #" + depositId],
                                                (earnErr) => {
                                                    if (earnErr) {
                                                        console.error(`[AUTO-APPROVE] Earnings insert error:`, earnErr);
                                                        return rollback();
                                                    }

                                                    notifyUser(
                                                        dep.user_id,
                                                        "تم قبول الإيداع تلقائياً",
                                                        "تمت إضافة " + Number(dep.amount).toFixed(2) + " USDT إلى رصيدك.",
                                                        "success"
                                                    );

                                                    db.get("SELECT referrer_id FROM users WHERE id = ?", [dep.user_id], (refErr, refRow) => {
                                                        if (!refErr && refRow && refRow.referrer_id) {
                                                            creditReferral(refRow.referrer_id, dep.amount, dep.user_id);
                                                        }

                                                        db.run(
                                                            "INSERT INTO activity_logs (admin_id, admin_email, action, details) VALUES (?, ?, ?, ?)",
                                                            [null, "AUTO-SYSTEM", "قبول تلقائي لإيداع", "إيداع #" + depositId + " — $" + dep.amount + " — تحقق آلي ناجح"],
                                                            (logErr) => {
                                                                if (logErr) console.error(`[AUTO-APPROVE] Log insert error:`, logErr);

                                                                db.run("COMMIT", (commitErr) => {
                                                                    if (commitErr) {
                                                                        console.error(`[AUTO-APPROVE] COMMIT error:`, commitErr);
                                                                        return rollback();
                                                                    }
                                                                    if (process.env.NODE_ENV !== 'production') {
                                                                        console.log(`[AUTO-APPROVE] Deposit #${depositId} approved`);
                                                                    }
                                                                    resolve(true);
                                                                });
                                                            }
                                                        );
                                                    });
                                                }
                                            );
                                        }
                                    );
                                });
                            }
                        );
                    }
                );
            });
        });
    });
}

// ===============================
// نسب عمولات الإحالة
// ===============================
const REFERRAL_TIERS = [
    { min: 0,     max: 500,    rate: 8.2 },
    { min: 500,   max: 3000,   rate: 4.5 },
    { min: 3000,  max: 10000,  rate: 3.0 },
    { min: 10000, max: 30000,  rate: 2.8 },
    { min: 30000, max: 100000, rate: 2.3 }
];
const REFERRAL_WITHDRAW_RATE = 1.0;

// تحديد فهرس الشريحة التي يقع فيها المبلغ
// $500 → 0 | $1,000 → 1 | $3,000 → 1 | $10,000 → 2 | $30,000 → 3 | $100,000 → 4
function getReferralTierIndex(amount) {
    for (let i = 0; i < REFERRAL_TIERS.length; i++) {
        const t = REFERRAL_TIERS[i];
        if (amount >= t.min && amount <= t.max) return i;
    }
    return REFERRAL_TIERS.length - 1;
}

function creditReferral(referrerId, amount, referredId, isWithdraw) {
    if (!referrerId || !amount || amount <= 0) return;

    // ★ عمولة السحب: 1% دائماً (بدون تغيير)
    if (isWithdraw) {
        const commission = Math.round(amount * REFERRAL_WITHDRAW_RATE) / 100;
        if (commission <= 0) return;
        payReferral(referrerId, commission, referredId, `سحب (1%)`);
        return;
    }

    // ★ عمولة الإيداع: نظام تراكمي
    //   - الشرائح المكتملة (قبل الشريحة الحالية): نسبتها × عرضها الكامل
    //   - الشريحة الحالية: نسبتها × كامل مبلغ الإيداع
    const idx = getReferralTierIndex(amount);
    let totalCommission = 0;
    const parts = [];

    // الشرائح المكتملة
    for (let i = 0; i < idx; i++) {
        const t = REFERRAL_TIERS[i];
        const width = t.max - t.min;
        if (width > 0) {
            const amt = Math.round(width * t.rate) / 100;
            totalCommission += amt;
            parts.push(`$${width}×${t.rate}%`);
        }
    }

    // الشريحة الحالية: نسبة × كامل المبلغ
    const current = REFERRAL_TIERS[idx];
    const currentAmt = Math.round(amount * current.rate) / 100;
    totalCommission += currentAmt;
    parts.push(`$${amount}×${current.rate}%`);

    if (totalCommission <= 0) return;
    payReferral(referrerId, totalCommission, referredId, `إيداع (${parts.join(' + ')})`);
}

// دالة مساعدة: تحديث الرصيد + earnings + referrals + إشعار
function payReferral(referrerId, commission, referredId, label) {
    db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [commission, referrerId]);
    db.run("INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, 'referral', ?)",
        [referrerId, commission, `عمولة إحالة من ${label} المستخدم #${referredId}`]);
    db.run("UPDATE referrals SET commission = commission + ? WHERE referrer_id = ? AND referred_id = ?",
        [commission, referrerId, referredId]);
    notifyUser(
        referrerId,
        "عمولة إحالة جديدة",
        `حصلت على ${commission.toLocaleString('en-US')} USDT من ${label} المدعو.`,
        "referral"
    );
}

app.post("/api/admin/deposits/:id/approve", requireAdmin, (req, res) => {
    const id = Number(req.params.id);

    const fail = (msg, code) => {
        db.run("ROLLBACK", () => res.status(code).json({ status: "error", message: msg }));
    };

    db.run("BEGIN IMMEDIATE", (beginErr) => {
        if (beginErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

        db.get("SELECT * FROM deposits WHERE id = ?", [id], (err, dep) => {
            if (err) return fail("خطأ في الخادم", 500);
            if (!dep) return fail("الإيداع غير موجود", 404);
            if (dep.status !== "pending") return fail("تمت معالجة هذا الإيداع مسبقاً", 400);

            db.run(
                "UPDATE deposits SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'",
                [req.session.adminId, id],
                function (updErr) {
                    if (updErr || this.changes !== 1) return fail("تعذر التحديث", 500);

                    db.get(
                        "SELECT u.total_deposits, u.plan_started_at, COALESCE(w.balance, 0) AS work_balance FROM users u LEFT JOIN account_work_wallets w ON w.user_id = u.id WHERE u.id = ?",
                        [dep.user_id],
                        (planErr, userRow) => {
                            if (planErr || !userRow) {
                                console.error("APPROVE-DEPOSIT user fetch error:", planErr);
                                return fail("تعذر جلب بيانات المستخدم", 500);
                            }

                            db.all("SELECT id, min_amount FROM plans WHERE active = 1 ORDER BY min_amount ASC", (plansErr, plans) => {
                                if (plansErr) {
                                    console.error("APPROVE-DEPOSIT plans fetch error:", plansErr);
                                    return fail("تعذر جلب الخطط", 500);
                                }

                                const planList = Array.isArray(plans) ? plans : [];
                                const beforeTotalDeposits = Number(userRow.total_deposits || 0);
                                const workWallet = Number(userRow.work_balance || 0);
                                const planBasisBefore = beforeTotalDeposits + workWallet;
                                const planBasisAfter = planBasisBefore + Number(dep.amount);

                                const levelBefore = getPlanLevel(planBasisBefore, planList);
                                const levelAfter = getPlanLevel(planBasisAfter, planList);

                                const oldStart = userRow.plan_started_at;
                                const startNum = (oldStart !== null && oldStart !== undefined) ? Number(oldStart) : null;

                                const isUpgrade = levelAfter > levelBefore;
                                const isNewPlan = (startNum === 0) || (startNum === null);

                                const newPlanStart = (isUpgrade || isNewPlan) ? Date.now() : oldStart;

                                db.run(
                                    "UPDATE users SET balance = balance + ?, total_deposits = total_deposits + ?, plan_started_at = ? WHERE id = ?",
                                    [dep.amount, dep.amount, newPlanStart, dep.user_id],
                                    (balErr) => {
                                        if (balErr) return fail("تعذر تحديث رصيد المستخدم", 500);

                                        db.run(
                                            "INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, 'deposit', ?)",
                                            [dep.user_id, dep.amount, "رصيد محول من إيداع #" + dep.id],
                                            (earnErr) => {
                                                if (earnErr) return fail("تعذر تسجيل الرصيد", 500);

                                                notifyUser(dep.user_id, "تم قبول الإيداع", "تمت إضافة " + dep.amount.toLocaleString('en-US') + " USDT إلى رصيدك.", "success");

                                                db.get("SELECT referrer_id FROM users WHERE id = ?", [dep.user_id], (refErr, refRow) => {
                                                    if (!refErr && refRow && refRow.referrer_id) {
                                                        creditReferral(refRow.referrer_id, dep.amount, dep.user_id);
                                                    }

                                                    logActivity(req, "قبول إيداع", "إيداع #" + id + " بقيمة " + dep.amount);

                                                    db.run("COMMIT", (commitErr) => {
                                                        if (commitErr) return res.status(500).json({ status: "error", message: "تعذر إتمام العملية" });
                                                        res.json({ status: "success", message: "تم قبول الإيداع وإضافة الرصيد" });
                                                    });
                                                });
                                            }
                                        );
                                    }
                                );
                            });
                        }
                    );
                }
            );
        });
    });
});
// ===============================
// إعادة التحقق من الإيداع (يدوياً)
// ===============================
app.post("/api/admin/deposits/:id/reverify", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    db.get("SELECT * FROM deposits WHERE id = ?", [id], (err, dep) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!dep) return res.status(404).json({ status: "error", message: "الإيداع غير موجود" });
        if (!dep.txid) {
            return res.status(400).json({ status: "error", message: "لا يوجد TXID لهذا الطلب" });
        }

        getNetwork(dep.network, (nErr, net) => {
            if (nErr || !net) {
                return res.status(400).json({ status: "error", message: "شبكة غير مدعومة" });
            }

            verifyDeposit(dep.network, dep.txid, Number(dep.amount), net.address)
                .then(result => {
                    return saveVerificationResult(id, result).then(() => result);
                })
                .then(result => {
                    logActivity(req, "إعادة التحقق من إيداع", "إيداع #" + id + " → " + result.status);
                    res.json({
                        status: "success",
                        verification: result
                    });
                })
                .catch(e => {
                    console.error("reverify error:", e);
                    res.status(500).json({ status: "error", message: "خطأ أثناء التحقق" });
                });
        });
    });
});


app.post("/api/admin/deposits/:id/reject", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const rawReason = req.body && req.body.reason ? String(req.body.reason).trim() : "";
    const reason = rawReason || "لم يُذكر سبب محدد";
    db.get("SELECT * FROM deposits WHERE id = ?", [id], (err, dep) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!dep) return res.status(404).json({ status: "error", message: "الإيداع غير موجود" });
        if (dep.status !== "pending") return res.status(400).json({ status: "error", message: "تمت معالجة هذا الإيداع مسبقاً" });

        db.run("UPDATE deposits SET status = 'rejected', reviewed_by = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'",
            [req.session.adminId, id], function (updErr) {
                if (updErr || this.changes !== 1) return res.status(400).json({ status: "error", message: "تمت معالجة هذا الإيداع مسبقاً" });
                notifyUser(dep.user_id, "تم رفض الإيداع", "تم رفض إيداعك رقم #" + id + ". السبب: " + reason, "error");
                logActivity(req, "رفض إيداع", "إيداع #" + id + " — السبب: " + reason);
                res.json({ status: "success", message: "تم رفض الإيداع" });
            });
    });
});

// ===============================
// إدارة السحوبات
// ===============================
app.get("/api/admin/withdrawals", requireAdmin, (req, res) => {
    const status = req.query.status || "";
    let sql = "SELECT w.*, u.email AS user_email, u.fullname AS user_name FROM withdrawals w LEFT JOIN users u ON u.id = w.user_id";
    const params = [];
    if (status && status !== "all") { sql += " WHERE w.status = ?"; params.push(status); }
    sql += " ORDER BY w.id DESC LIMIT 300";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});

app.post("/api/admin/withdrawals/:id/approve", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    db.get("SELECT * FROM withdrawals WHERE id = ?", [id], (err, wd) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!wd) return res.status(404).json({ status: "error", message: "السحب غير موجود" });
        if (wd.status !== "pending") return res.status(400).json({ status: "error", message: "تمت معالجة الطلب مسبقاً" });

        db.run("UPDATE withdrawals SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'",
            [req.session.adminId, id], function (updErr) {
                if (updErr || this.changes !== 1) return res.status(400).json({ status: "error", message: "تمت معالجة الطلب مسبقاً" });
                notifyUser(
                    wd.user_id,
                    "تم قبول السحب",
                    "تمت الموافقة على سحبك رقم #" + id + " بمبلغ " + Number(wd.amount).toFixed(2) + " USDT، وسيصلك قريباً.",
                    "success"
                );

                // ★ عمولة السحب للمحيلين (5 مستويات)
                db.get("SELECT referrer_id FROM users WHERE id = ?", [wd.user_id], (refErr, refRow) => {
                    if (!refErr && refRow && refRow.referrer_id) {
                        creditReferral(refRow.referrer_id, wd.amount, wd.user_id, true);
                    }
                });

                logActivity(req, "قبول سحب", "سحب #" + id + " بقيمة " + wd.amount);
                res.json({ status: "success", message: "تمت الموافقة على السحب" });
            });
    });
});

app.post("/api/admin/withdrawals/:id/reject", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const rawReason = req.body && req.body.reason ? String(req.body.reason).trim() : "";
    const reason = rawReason || "لم يُذكر سبب محدد";
    db.get("SELECT * FROM withdrawals WHERE id = ?", [id], (err, wd) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        if (!wd) return res.status(404).json({ status: "error", message: "السحب غير موجود" });
        if (wd.status !== "pending") return res.status(400).json({ status: "error", message: "تمت معالجة الطلب مسبقاً" });

        db.run("UPDATE withdrawals SET status = 'rejected', reviewed_by = ?, reviewed_at = datetime('now') WHERE id = ? AND status = 'pending'",
            [req.session.adminId, id], function (updErr) {
                if (updErr || this.changes !== 1) return res.status(400).json({ status: "error", message: "تمت معالجة الطلب مسبقاً" });
                // إرجاع المبلغ للمستخدم (كان مخصوماً وقت تقديم الطلب)
                db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [wd.amount, wd.user_id]);
                notifyUser(wd.user_id, "تم رفض السحب", "تم رفض سحبك رقم #" + id + " وأُعيد المبلغ إلى رصيدك. السبب: " + reason, "error");
                logActivity(req, "رفض سحب", "سحب #" + id + " — السبب: " + reason);
                res.json({ status: "success", message: "تم رفض السحب وإرجاع المبلغ" });
            });
    });
});

// ===============================
// تفاصيل السحب الكاملة (للمدير)
// ===============================
app.get("/api/admin/withdrawals/:id/details", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    if (!id || isNaN(id)) {
        return res.status(400).json({ status: "error", message: "معرّف غير صحيح" });
    }

    db.get(
        `SELECT w.*, u.email AS user_email, u.fullname AS user_name,
                u.phone AS user_phone, u.created_at AS user_created_at,
                u.status AS user_status, u.blocked AS user_blocked
         FROM withdrawals w
         LEFT JOIN users u ON u.id = w.user_id
         WHERE w.id = ?`,
        [id],
        (err, wd) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            if (!wd) return res.status(404).json({ status: "error", message: "السحب غير موجود" });

            db.get(
                `SELECT COUNT(*) AS cnt, COALESCE(SUM(amount),0) AS total
                 FROM deposits WHERE user_id = ? AND status = 'approved'`,
                [wd.user_id],
                (e2, summary) => {
                    db.all(
                        `SELECT id, amount, network, status, created_at, txid
                         FROM deposits WHERE user_id = ?
                         ORDER BY id DESC`,
                        [wd.user_id],
                        (e3, deposits) => {
                            db.all(
                                `SELECT id, amount, fee, net_amount, network, address, status, created_at
                                 FROM withdrawals WHERE user_id = ?
                                 ORDER BY id DESC`,
                                [wd.user_id],
                                (e4, userWithdrawals) => {
                                    res.json({
                                        status: "success",
                                        withdrawal: {
                                            id: wd.id,
                                            amount: wd.amount,
                                            fee: wd.fee || 0,
                                            net_amount: wd.net_amount || 0,
                                            network: wd.network,
                                            address: wd.address,
                                            status: wd.status,
                                            created_at: wd.created_at,
                                            reviewed_at: wd.reviewed_at
                                        },
                                        user: {
                                            id: wd.user_id,
                                            email: wd.user_email || "—",
                                            fullname: wd.user_name || "—",
                                            phone: wd.user_phone || "—",
                                            created_at: wd.user_created_at,
                                            status: wd.user_status || "active",
                                            blocked: !!wd.user_blocked
                                        },
                                        depositsSummary: {
                                            count: (summary && summary.cnt) || 0,
                                            total: (summary && summary.total) || 0
                                        },
                                        deposits: deposits || [],
                                        userWithdrawals: userWithdrawals || []
                                    });
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

// ===============================
// إدارة الخطط
// ===============================
app.get("/api/admin/plans", requireAdmin, (req, res) => {
    db.all("SELECT * FROM plans ORDER BY min_amount ASC", (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});

app.post("/api/admin/plans", requireAdmin, (req, res) => {
    const { name, min_amount, max_amount, daily_percent, duration_days, active } = req.body;
    if (!name || !min_amount || !max_amount) return res.status(400).json({ status: "error", message: "بيانات غير مكتملة" });
    db.run(
        "INSERT INTO plans (name, min_amount, max_amount, daily_percent, duration_days, active) VALUES (?, ?, ?, ?, ?, ?)",
        [name, Number(min_amount), Number(max_amount), Number(daily_percent) || 5, Number(duration_days) || 0, active ? 1 : 1],
        function (err) {
            if (err) return res.status(500).json({ status: "error", message: "تعذر إنشاء الخطة" });
            logActivity(req, "إنشاء خطة", name);
            res.json({ status: "success", planId: this.lastID });
        }
    );
});

app.put("/api/admin/plans/:id", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const { name, min_amount, max_amount, daily_percent, duration_days, active } = req.body;
    const fields = [], params = [];
    if (name !== undefined) { fields.push("name = ?"); params.push(name); }
    if (min_amount !== undefined) { fields.push("min_amount = ?"); params.push(Number(min_amount)); }
    if (max_amount !== undefined) { fields.push("max_amount = ?"); params.push(Number(max_amount)); }
    if (daily_percent !== undefined) { fields.push("daily_percent = ?"); params.push(Number(daily_percent)); }
    if (duration_days !== undefined) { fields.push("duration_days = ?"); params.push(Number(duration_days)); }
    if (active !== undefined) { fields.push("active = ?"); params.push(active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ status: "error", message: "لا توجد بيانات" });
    params.push(id);
    db.run("UPDATE plans SET " + fields.join(", ") + " WHERE id = ?", params, function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر تحديث الخطة" });
        logActivity(req, "تعديل خطة", "خطة #" + id);
        res.json({ status: "success", message: "تم التحديث" });
    });
});

app.delete("/api/admin/plans/:id", requireAdmin, (req, res) => {
    db.run("DELETE FROM plans WHERE id = ?", [Number(req.params.id)], function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر حذف الخطة" });
        logActivity(req, "حذف خطة", "خطة #" + req.params.id);
        res.json({ status: "success", message: "تم الحذف" });
    });
});

// ===============================
// إدارة الأرباح
// ===============================
app.get("/api/admin/earnings", requireAdmin, (req, res) => {
    const type = req.query.type || "";
    let sql = "SELECT e.*, u.email AS user_email, u.fullname AS user_name FROM earnings e LEFT JOIN users u ON u.id = e.user_id";
    const params = [];
    if (type && type !== "all") { sql += " WHERE e.type = ?"; params.push(type); }
    sql += " ORDER BY e.id DESC LIMIT 300";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        db.get(
            "SELECT type, COALESCE(SUM(amount),0) AS total FROM earnings GROUP BY type",
            (e2, totals) => {
                res.json({ list: rows || [], totals: totals || { profit: 0, referral: 0 } });
            }
        );
    });
});

// ===============================
// إدارة الإحالات
// ===============================
app.get("/api/admin/referrals", requireAdmin, (req, res) => {
    db.all(
        `SELECT r.*, o.email AS referrer_email, o.fullname AS referrer_name, t.email AS referred_email, t.fullname AS referred_name
         FROM referrals r
         LEFT JOIN users o ON o.id = r.referrer_id
         LEFT JOIN users t ON t.id = r.referred_id
         ORDER BY r.id DESC LIMIT 300`,
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            db.all(
                `SELECT o.id, o.email, o.fullname, COUNT(r.id) AS total_referred, COALESCE(SUM(r.commission),0) AS total_commission
                 FROM users o LEFT JOIN referrals r ON r.referrer_id = o.id
                 GROUP BY o.id ORDER BY total_commission DESC, total_referred DESC LIMIT 20`,
                (e2, top) => {
                    res.json({ list: rows || [], top: top || [] });
                }
            );
        }
    );
});

// ===============================
// إدارة المحافظ
// ===============================
app.get("/api/admin/wallets", requireAdmin, (req, res) => {
    db.all("SELECT * FROM wallets ORDER BY id", (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});

app.post("/api/admin/wallets", requireAdmin, (req, res) => {
    const { network, address, status, confirmations_required, eta_minutes, min_amount, max_amount, fee_fixed } = req.body;
    if (!network || !address) return res.status(400).json({ status: "error", message: "الشبكة والعنوان مطلوبان" });
    db.run(
        "INSERT INTO wallets (network, address, status, confirmations_required, eta_minutes, min_amount, max_amount, fee_fixed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [network, address, status || "operational", Number(confirmations_required) || 3, Number(eta_minutes) || 20, Number(min_amount) || 50, Number(max_amount) || 30000, Number(fee_fixed) || 0],
        function (err) {
            if (err) return res.status(400).json({ status: "error", message: err.message.includes("UNIQUE") ? "الشبكة موجودة مسبقاً" : "تعذر إنشاء المحفظة" });
            logActivity(req, "إضافة محفظة", network);
            res.json({ status: "success", message: "تمت إضافة المحفظة" });
        }
    );
});

app.put("/api/admin/wallets/:id", requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const fields = [], params = [];
    const map = { address: "address", status: "status", confirmations_required: "confirmations_required", eta_minutes: "eta_minutes", min_amount: "min_amount", max_amount: "max_amount", fee_fixed: "fee_fixed" };
    Object.keys(map).forEach(k => {
        if (req.body[k] !== undefined) { fields.push(map[k] + " = ?"); params.push(req.body[k]); }
    });
    if (!fields.length) return res.status(400).json({ status: "error", message: "لا توجد بيانات" });
    params.push(id);
    db.run("UPDATE wallets SET " + fields.join(", ") + " WHERE id = ?", params, function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر التحديث" });
        logActivity(req, "تعديل محفظة", "محفظة #" + id);
        res.json({ status: "success", message: "تم التحديث" });
    });
});

app.delete("/api/admin/wallets/:id", requireAdmin, (req, res) => {
    db.run("DELETE FROM wallets WHERE id = ?", [Number(req.params.id)], function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر الحذف" });
        logActivity(req, "حذف محفظة", "محفظة #" + req.params.id);
        res.json({ status: "success", message: "تم الحذف" });
    });
});

// ===============================
// إدارة الإشعارات
// ===============================
app.get("/api/admin/notifications", requireAdmin, (req, res) => {
    db.all(
        `SELECT n.*, u.email AS user_email, u.fullname AS user_name FROM notifications n LEFT JOIN users u ON u.id = n.user_id ORDER BY n.id DESC LIMIT 200`,
        (err, rows) => {
            if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
            res.json(rows || []);
        }
    );
});

app.post("/api/admin/notifications", requireAdmin, (req, res) => {
    const { user_id, title, message, type, broadcast } = req.body;
    if (!title || !message) return res.status(400).json({ status: "error", message: "العنوان والنص مطلوبان" });
    const send = (uid, t, m, ty) => db.run("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)", [uid, t, m, ty || "info"]);

    if (broadcast) {
        db.all("SELECT id FROM users", (err, users) => {
            (users || []).forEach(u => send(u.id, title, message, type));
            logActivity(req, "إرسال إشعار جماعي", title);
            res.json({ status: "success", message: `تم الإرسال إلى ${(users || []).length} مستخدم` });
        });
    } else if (user_id) {
        send(Number(user_id), title, message, type);
        logActivity(req, "إرسال إشعار", "إلى المستخدم #" + user_id + " — " + title);
        res.json({ status: "success", message: "تم إرسال الإشعار" });
    } else {
        res.status(400).json({ status: "error", message: "حدد المستخدم أو فعّل البث الجماعي" });
    }
});

app.delete("/api/admin/notifications/:id", requireAdmin, (req, res) => {
    db.run("DELETE FROM notifications WHERE id = ?", [Number(req.params.id)], function (err) {
        if (err) return res.status(500).json({ status: "error", message: "تعذر الحذف" });
        res.json({ status: "success", message: "تم الحذف" });
    });
});

// ===============================
// الإعدادات
// ===============================
app.get("/api/admin/settings", requireAdmin, (req, res) => {
    db.all("SELECT * FROM settings ORDER BY key", (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});

app.put("/api/admin/settings", requireAdmin, (req, res) => {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ status: "error", message: "المفتاح مطلوب" });
    db.run(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, String(value ?? "")],
        function (err) {
            if (err) return res.status(500).json({ status: "error", message: "تعذر الحفظ" });
            logActivity(req, "تحديث إعدادات", key + " = " + value);
            res.json({ status: "success", message: "تم حفظ الإعداد" });
        }
    );
});

// ===============================
// سجل النشاطات
// ===============================
app.get("/api/admin/logs", requireAdmin, (req, res) => {
    const q = (req.query.q || "").trim();
    let sql = "SELECT l.*, COALESCE(l.admin_email,'') AS admin_email FROM activity_logs l";
    const params = [];
    if (q) { sql += " WHERE l.action LIKE ? OR l.details LIKE ?"; const like = "%" + q + "%"; params.push(like, like); }
    sql += " ORDER BY l.id DESC LIMIT 300";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        res.json(rows || []);
    });
});
// =====================================================
// API حساب ELITE - ربط account.html
// =====================================================

// بيانات المستخدم
app.get("/api/account/profile", requireAuth, (req, res) => {
    db.get(
        `SELECT id, email, fullname, status, last_login, referral_code, invite_code, created_at
         FROM users
         WHERE id = ?`,
        [req.session.userId],
        (err, user) => {
            if (err) {
                console.error("ACCOUNT PROFILE ERROR:", err);
                return res.status(500).json({
                    status: "error",
                    message: "خطأ في الخادم"
                });
            }

            if (!user) {
                return res.status(404).json({
                    status: "error",
                    message: "المستخدم غير موجود"
                });
            }

            ensureInviteCode(user.id, (code) => {
                res.json({
                    id: user.id,
                    name: user.fullname || user.email,
                    fullname: user.fullname || "",
                    email: user.email,
                    status: user.status || "active",
                    lastLogin: user.last_login || null,
                    joinedDate: user.created_at || null,
                    refCode: code || user.invite_code || user.referral_code || ""
                });
            });
        }
    );
});


// =====================================================
// المحافظ والأرصدة
// =====================================================

app.get("/api/account/wallet", requireAuth, (req, res) => {
    const userId = req.session.userId;

    db.get(
        `SELECT balance FROM users WHERE id = ?`,
        [userId],
        (err, user) => {
            if (err) {
                console.error("ACCOUNT WALLET ERROR:", err);
                return res.status(500).json({
                    status: "error",
                    message: "خطأ في الخادم"
                });
            }

            if (!user) {
                return res.status(404).json({
                    status: "error",
                    message: "المستخدم غير موجود"
                });
            }

            db.get(
                `SELECT COALESCE(SUM(amount), 0) AS referral
                 FROM earnings
                 WHERE user_id = ?
                 AND type = 'referral'`,
                [userId],
                (err, referralRow) => {
                    if (err) {
                        console.error("REFERRAL WALLET ERROR:", err);
                        return res.status(500).json({
                            status: "error",
                            message: "خطأ في الخادم"
                        });
                    }

                    db.get(
                        `SELECT balance, currency
                         FROM account_work_wallets
                         WHERE user_id = ?`,
                        [userId],
                        (err, work) => {
                            if (err) {
                                console.error("WORK WALLET ERROR:", err);
                                return res.status(500).json({
                                    status: "error",
                                    message: "خطأ في الخادم"
                                });
                            }

                            const balance = Number(user.balance || 0);
                            const referral = Number(
                                referralRow?.referral || 0
                            );

                            res.json({
                                trading: Math.max(balance - referral, 0),
                                referral: referral,
                                work: Number(work?.balance || 0),
                                currency: work?.currency || "USDT"
                            });
                        }
                    );
                }
            );
        }
    );
});


// =====================================================
// الإحالات
// =====================================================

app.get("/api/account/referrals", requireAuth, (req, res) => {
    // 1) جلب الخطط لحساب "مستوى الخطة" لكل صديق
    db.all("SELECT id, min_amount FROM plans WHERE active = 1 ORDER BY min_amount ASC", (pErr, plans) => {
        if (pErr) {
            console.error("ACCOUNT REFERRALS PLANS ERROR:", pErr);
            return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        }
        const planList = plans || [];

        // 2) جلب كل الأصدقاء + رصيد محفظة العمل
        db.all(
            `SELECT
                r.id,
                r.referred_id,
                r.commission,
                r.created_at,
                u.fullname,
                u.email,
                u.total_deposits,
                COALESCE(w.balance, 0) AS work_wallet
             FROM referrals r
             JOIN users u ON u.id = r.referred_id
             LEFT JOIN account_work_wallets w ON w.user_id = u.id
             WHERE r.referrer_id = ?
             ORDER BY r.id DESC`,
            [req.session.userId],
            (err, rows) => {
                if (err) {
                    console.error("ACCOUNT REFERRALS ERROR:", err);
                    return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
                }

                // 3) حساب "مستوى الخطة" لكل صديق (0 = معلّق)
                const all = (rows || []).map(r => {
                    const planBasis = Number(r.total_deposits || 0) + Number(r.work_wallet || 0);
                    let planLevel = 0;
                    for (let i = planList.length - 1; i >= 0; i--) {
                        if (planBasis >= planList[i].min_amount) {
                            planLevel = i + 1;
                            break;
                        }
                    }
                    return { ...r, planLevel };
                });

                // 4) الترتيب: L1 → L5 تصاعدي، ثم L0 (معلّقون) في النهاية
                all.sort((a, b) => {
                    const la = a.planLevel === 0 ? 999 : a.planLevel;
                    const lb = b.planLevel === 0 ? 999 : b.planLevel;
                    if (la !== lb) return la - lb;
                    return b.id - a.id;
                });

                // 5) التصنيف
                const pending = all.filter(r => r.planLevel === 0);
                const friends = all.filter(r => r.planLevel > 0);

                const referralProfit = all.reduce(
                    (sum, item) => sum + Number(item.commission || 0),
                    0
                );

                // 6) إحصائيات لكل مستوى خطة (L0 → L5)
                const levelStats = {
                    0: {
                        count: pending.length,
                        earnings: pending.reduce((s, r) => s + Number(r.commission || 0), 0)
                    }
                };
                for (let lvl = 1; lvl <= planList.length; lvl++) {
                    const levelRows = all.filter(r => r.planLevel === lvl);
                    levelStats[lvl] = {
                        count: levelRows.length,
                        earnings: levelRows.reduce((s, r) => s + Number(r.commission || 0), 0)
                    };
                }

                res.json({
                    friends: friends,
                    friendsCount: friends.length,
                    referralProfit: referralProfit,
                    pending: pending,
                    pendingCount: pending.length,
                    levelStats: levelStats,
                    allReferrals: all
                });
            }
        );
    });
});


// =====================================================
// عمليات الحساب
// =====================================================

app.get("/api/account/transactions", requireAuth, (req, res) => {
    const userId = req.session.userId;

    const sql = `
        SELECT id, title, type, amount, status, created_at FROM (
            -- 1) تحويلات محفظة العمل
            SELECT id,
                   title,
                   type,
                   amount,
                   status,
                   created_at
            FROM account_transactions
            WHERE user_id = ?

            UNION ALL

            -- 2) الإيداعات
            SELECT id,
                   CASE status
                        WHEN 'approved' THEN 'إيداع — مقبول'
                        WHEN 'rejected' THEN 'إيداع — مرفوض'
                        ELSE 'إيداع — قيد المراجعة'
                   END AS title,
                   'deposit' AS type,
                   amount,
                   status,
                   created_at
            FROM deposits
            WHERE user_id = ?

            UNION ALL

            -- 3) السحوبات
            SELECT id,
                   CASE status
                        WHEN 'approved' THEN 'سحب — مقبول'
                        WHEN 'rejected' THEN 'سحب — مرفوض'
                        ELSE 'سحب — قيد المراجعة'
                   END AS title,
                   'withdraw' AS type,
                   amount,
                   status,
                   created_at
            FROM withdrawals
            WHERE user_id = ?

            UNION ALL

            -- 4) أرباح التداول + عمولات الإحالة
            SELECT id,
                   CASE type
                        WHEN 'profit'   THEN 'أرباح تداول'
                        WHEN 'referral' THEN 'عمولة إحالة'
                        ELSE 'أرباح'
                   END AS title,
                   type,
                   amount,
                   'completed' AS status,
                   created_at
            FROM earnings
            WHERE user_id = ? AND type IN ('profit','referral')
        )
        ORDER BY datetime(created_at) DESC
        LIMIT 100
    `;

    db.all(sql, [userId, userId, userId, userId], (err, rows) => {
        if (err) {
            console.error("ACCOUNT TRANSACTIONS ERROR:", err);
            return res.status(500).json({
                status: "error",
                message: "خطأ في الخادم"
            });
        }

        res.json(rows || []);
    });
});


// =====================================================
// تحويل من الرصيد الرئيسي إلى محفظة العمل
// =====================================================

app.post("/api/account/transfer", requireAuth, (req, res) => {
    const userId = req.session.userId;
    const amount = Number(req.body.amount);
    const idempotencyKey = req.headers["x-idempotency-key"];
    const transferSource = (req.body.source === 'ref') ? 'ref' : 'work';

    if (!idempotencyKey) {
        return res.status(400).json({ status: "error", message: "مفتاح العملية مفقود" });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ status: "error", message: "المبلغ غير صحيح" });
    }

    const fail = (msg, code) => {
        db.run("ROLLBACK", () => res.status(code).json({ status: "error", message: msg }));
    };

    db.run("BEGIN IMMEDIATE", (beginErr) => {
        if (beginErr) return res.status(500).json({ status: "error", message: "خطأ في الخادم" });

        db.get(
            `SELECT id, status FROM account_transfers WHERE idempotency_key = ?`,
            [idempotencyKey],
            (err, existing) => {
                if (err) return fail("خطأ في الخادم", 500);

                if (existing) {
                    return db.run("COMMIT", () => res.json({
                        status: "success",
                        success: true,
                        message: "العملية منفذة مسبقًا"
                    }));
                }

                db.get(
                    `SELECT u.balance, u.total_deposits, u.plan_started_at,
                            COALESCE(w.balance, 0) AS work_balance,
                            COALESCE((SELECT SUM(amount) FROM earnings WHERE user_id = u.id AND type IN ('profit','referral','withdraw','withdraw_reverse','transfer_out','transfer_out_work','transfer_out_ref')), 0) AS withdrawable
                     FROM users u
                     LEFT JOIN account_work_wallets w ON w.user_id = u.id
                     WHERE u.id = ?`,
                    [userId],
                    (err, user) => {
                        if (err) return fail("خطأ في الخادم", 500);
                        if (!user) return fail("المستخدم غير موجود", 404);

                        const balance = Number(user.balance || 0);
                        const withdrawable = Number(user.withdrawable || 0);

                        if (amount > withdrawable) {
                            return fail("الرصيد القابل للسحب غير كافٍ. المتاح: " + withdrawable.toFixed(2) + " USDT", 400);
                        }
                        if (amount > balance) {
                            return fail("الرصيد غير كافٍ", 400);
                        }

                        db.all("SELECT id, min_amount FROM plans WHERE active = 1 ORDER BY min_amount ASC", (plansErr, plans) => {
                            if (plansErr) {
                                console.error("TRANSFER plans fetch error:", plansErr);
                                return fail("تعذر جلب الخطط", 500);
                            }

                            const planList = Array.isArray(plans) ? plans : [];
                            const beforeTotalDeposits = Number(user.total_deposits || 0);
                            const workWallet = Number(user.work_balance || 0);
                            const planBasisBefore = beforeTotalDeposits + workWallet;
                            const planBasisAfter = planBasisBefore + amount;

                            const levelBefore = getPlanLevel(planBasisBefore, planList);
                            const levelAfter = getPlanLevel(planBasisAfter, planList);

                            const oldStart = user.plan_started_at;
                            const startNum = (oldStart !== null && oldStart !== undefined) ? Number(oldStart) : null;

                            const isUpgrade = levelAfter > levelBefore;
                            const isNewPlan = (startNum === 0) || (startNum === null);

                            const newPlanStart = (isUpgrade || isNewPlan) ? Date.now() : oldStart;

                            db.run(
                                `UPDATE users
                                 SET balance = balance - ?,
                                     plan_started_at = ?
                                 WHERE id = ?
                                 AND balance >= ?`,
                                [amount, newPlanStart, userId, amount],
                                function (updErr) {
                                    if (updErr) return fail("فشل التحويل", 500);
                                    if (this.changes !== 1) return fail("الرصيد غير كافٍ", 400);

                                    db.run(
                                        `INSERT INTO account_work_wallets (user_id, balance, currency)
                                         VALUES (?, ?, 'USDT')
                                         ON CONFLICT(user_id)
                                         DO UPDATE SET balance = balance + excluded.balance, updated_at = CURRENT_TIMESTAMP`,
                                        [userId, amount],
                                        (workErr) => {
                                            if (workErr) return fail("فشل تحديث محفظة العمل", 500);

                                            const outType = transferSource === 'ref' ? 'transfer_out_ref' : 'transfer_out_work';
                                            const outNote = transferSource === 'ref'
                                                ? "تحويل أرباح الإحالة إلى محفظة العمل"
                                                : "تحويل أرباح العمل إلى محفظة العمل";

                                            db.run(
                                                `INSERT INTO earnings (user_id, amount, type, note) VALUES (?, ?, ?, ?)`,
                                                [userId, -amount, outType, outNote],
                                                (earnErr) => {
                                                    if (earnErr) return fail("فشل تسجيل حركة التحويل", 500);

                                                    db.run(
                                                        `INSERT INTO account_transfers (user_id, amount, source, target, idempotency_key, status)
                                                         VALUES (?, ?, 'main_wallet', 'work_wallet', ?, 'completed')`,
                                                        [userId, amount, idempotencyKey],
                                                        (trErr) => {
                                                            if (trErr) return fail("فشل تسجيل التحويل", 500);

                                                            db.run(
                                                                `INSERT INTO account_transactions (user_id, title, type, amount, status)
                                                                 VALUES (?, ?, ?, ?, ?)`,
                                                                [userId, "تحويل إلى محفظة العمل", "transfer", amount, "completed"],
                                                                (acErr) => {
                                                                    if (acErr) return fail("فشل تسجيل العملية", 500);

                                                                    db.run("COMMIT", (commitErr) => {
                                                                        if (commitErr) return res.status(500).json({ status: "error", message: "تعذر إتمام العملية" });
                                                                        res.json({
                                                                            status: "success",
                                                                            success: true,
                                                                            message: "تم التحويل بنجاح"
                                                                        });
                                                                    });
                                                                }
                                                            );
                                                        }
                                                    );
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        });
                    }
                );
            }
        );
    });
});


// =====================================================
// تغيير كلمة المرور
// =====================================================
app.post("/api/account/change-password", requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({
            status: "error",
            message: "يرجى إدخال كلمة المرور الحالية والجديدة"
        });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            status: "error",
            message: "كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل"
        });
    }

    db.get("SELECT password FROM users WHERE id = ?", [req.session.userId], async (err, user) => {
        if (err) {
            console.error("CHANGE PW DB ERROR:", err);
            return res.status(500).json({ status: "error", message: "خطأ في الخادم" });
        }
        if (!user) {
            return res.status(404).json({ status: "error", message: "المستخدم غير موجود" });
        }

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(400).json({
                status: "error",
                message: "كلمة المرور الحالية غير صحيحة"
            });
        }

        const hashed = await bcrypt.hash(newPassword, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashed, req.session.userId], function (updErr) {
            if (updErr) {
                console.error("CHANGE PW UPDATE ERROR:", updErr);
                return res.status(500).json({ status: "error", message: "تعذر تحديث كلمة المرور" });
            }
            res.json({ status: "success", message: "تم تغيير كلمة المرور بنجاح" });
        });
    });
});

// =====================================================
// تسجيل الخروج الخاص بـ account.html
// =====================================================

app.post("/api/auth/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("LOGOUT ERROR:", err);
            return res.status(500).json({
                status: "error",
                message: "فشل تسجيل الخروج"
            });
        }

        res.json({
            status: "success",
            success: true
        });
    });
});
// ===============================
// Global error handling
// ===============================
app.use((err, req, res, next) => {
    console.error("[UNCAUGHT ERROR]", err && err.stack ? err.stack : err);
    if (res.headersSent) return next(err);
    res.status(500).json({ status: "error", message: "حدث خطأ غير متوقع" });
});

process.on("unhandledRejection", (reason) => {
    console.error("[UNHANDLED REJECTION]", reason);
});

process.on("uncaughtException", (err) => {
    console.error("[UNCAUGHT EXCEPTION]", err && err.stack ? err.stack : err);
});

app.listen(PORT, () => {
    console.log("ELITE TRADING SERVER STARTED");
    console.log(`http://localhost:${PORT}`);
});
