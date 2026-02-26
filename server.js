// server.js
require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const csrf = require("csurf");
const rateLimit = require("express-rate-limit");

const { decrypt, encrypt } = require("./src/utils/cryptoBox"); // KODE KAMU
const { emailLogin } = require("./src/services/gobizAuth");   // file di atas
const { getMerchantId, getMutasi } = require("./src/services/gobiz"); // KODE KAMU

// =====================
// ENV
// =====================
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = String(process.env.NODE_ENV || "development").toLowerCase();
const IS_PROD = NODE_ENV === "production";

const COOKIE_SECRET = process.env.COOKIE_SECRET || process.env.SESSION_SECRET; // boleh salah satu
if (!COOKIE_SECRET || COOKIE_SECRET.length < 32) {
  throw new Error("Missing/weak env: COOKIE_SECRET (or SESSION_SECRET) min 32 chars");
}

const APP_NAME = process.env.APP_NAME || "GoBiz Wallet";
const COOKIE_NAME = "gobiz_acc";

// =====================
// APP
// =====================
const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({ contentSecurityPolicy: false })); // karena pakai CDN fonts/icons
app.use(compression());
app.use(morgan(IS_PROD ? "combined" : "dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "300kb" }));
app.use(cookieParser(COOKIE_SECRET));
app.use("/public", express.static(path.join(__dirname, "public")));

app.use((req, res, next) => {
  res.locals.APP_NAME = APP_NAME;
  res.locals.path = req.path;
  next();
});

// =====================
// CSRF (cookie-based)
// =====================
const csrfProtect = csrf({
  cookie: {
    httpOnly: true,
    secure: IS_PROD,  // HARUS true di production (HTTPS)
    sameSite: "lax",
    path: "/",
  },
});

// =====================
// Rate limit
// =====================
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const appLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 240,
  standardHeaders: true,
  legacyHeaders: false,
});

// =====================
// Cookie session helpers (encrypted)
// =====================
function cookieOpts() {
  return {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 hari
  };
}

function uaHash(req) {
  const ua = String(req.headers["user-agent"] || "");
  return crypto.createHash("sha256").update(ua).digest("hex");
}

function buildAccFromReq(req) {
  return {
    uniqueId: crypto.randomUUID(),
    userAgent: String(req.headers["user-agent"] || "Mozilla/5.0"),

    tokenExpiry: 0,
    accessTokenEnc: null,
    refreshTokenEnc: null,

    merchantId: null,
    merchantName: null,

    async save() {
      // no-op (tanpa DB)
    },
  };
}

function setAccCookie(res, req, acc) {
  const payload = {
    v: 1,
    uaHash: uaHash(req),

    uniqueId: acc.uniqueId,
    userAgent: acc.userAgent,

    tokenExpiry: Number(acc.tokenExpiry || 0),
    accessTokenEnc: acc.accessTokenEnc || null,
    refreshTokenEnc: acc.refreshTokenEnc || null,

    merchantId: acc.merchantId || null,
    merchantName: acc.merchantName || null,
  };

  const b64 = encrypt(JSON.stringify(payload));
  res.cookie(COOKIE_NAME, b64, cookieOpts());
}

function clearAccCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function getAccFromCookie(req) {
  const b64 = req.cookies?.[COOKIE_NAME];
  if (!b64) return null;

  const raw = decrypt(b64);
  if (!raw) return null;

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!data?.uaHash || data.uaHash !== uaHash(req)) return null;

  return {
    uniqueId: data.uniqueId,
    userAgent: data.userAgent || String(req.headers["user-agent"] || "Mozilla/5.0"),

    tokenExpiry: Number(data.tokenExpiry || 0),
    accessTokenEnc: data.accessTokenEnc || null,
    refreshTokenEnc: data.refreshTokenEnc || null,

    merchantId: data.merchantId || null,
    merchantName: data.merchantName || null,

    async save() {
      // no-op
    },
  };
}

function requireAuth(req, res, next) {
  const acc = getAccFromCookie(req);
  if (!acc || !acc.refreshTokenEnc) return res.redirect("/login");
  req.acc = acc;
  next();
}

// =====================
// ROUTES
// =====================
app.get("/", (req, res) => {
  const acc = getAccFromCookie(req);
  if (acc?.refreshTokenEnc) return res.redirect("/app");
  return res.redirect("/login");
});

// ---- LOGIN (EMAIL)
app.get("/login", csrfProtect, (req, res) => {
  res.render("auth/login", { csrfToken: req.csrfToken(), err: null });
});

app.post("/login", authLimiter, csrfProtect, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res
        .status(400)
        .render("auth/login", { csrfToken: req.csrfToken(), err: "Email & password wajib diisi." });
    }

    const acc = buildAccFromReq(req);

    // login -> token tersimpan encrypted dalam acc.*Enc
    await emailLogin(acc, email, password);

    // optional: ambil merchant info biar dashboard langsung siap
    try {
      await getMerchantId(acc);
    } catch {
      // ok, nanti bisa kebaca saat getMutasi
    }

    // simpan ke cookie encrypted
    setAccCookie(res, req, acc);

    return res.redirect("/app");
  } catch (e) {
    return res
      .status(400)
      .render("auth/login", { csrfToken: req.csrfToken(), err: "Login gagal. Cek email/password." });
  }
});

app.post("/logout", csrfProtect, (req, res) => {
  clearAccCookie(res);
  res.redirect("/login");
});

// ---- DASHBOARD
app.get("/app", appLimiter, requireAuth, csrfProtect, async (req, res) => {
  const acc = req.acc;

  try {
    // tanggal hari ini (Asia/Jakarta)
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    const ymd = `${y}-${m}-${d}`;

    const tx = await getMutasi(acc, ymd, 50);

    // PENTING: gobiz.js kamu bisa refresh token & update acc fields.
    // karena tanpa DB, kita update cookie setiap kali sukses.
    setAccCookie(res, req, acc);

    res.render("app/dashboard", {
      csrfToken: req.csrfToken(),
      merchantName: acc.merchantName || "Merchant",
      merchantId: acc.merchantId || "-",
      dateYmd: ymd,
      tx,
    });
  } catch (e) {
    // kalau refresh gagal / token invalid -> logout paksa
    clearAccCookie(res);
    return res.redirect("/login");
  }
});

// ---- Error handler CSRF
app.use((err, req, res, next) => {
  if (err && err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("CSRF token invalid. Refresh halaman dan coba lagi.");
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`✅ ${APP_NAME} running on http://localhost:${PORT} (${NODE_ENV})`);
});
