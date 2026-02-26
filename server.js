require("dotenv").config();

const path = require("path");
const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const { buildAccFromReq, setAccCookie, clearAccCookie, getAccFromCookie } = require("./src/web/cookies");
const { requireAuth, csrfProtect, injectLocals } = require("./src/web/middleware");

const { requestOtp, verifyOtp } = require("./src/services/gobizAuth");
const { getMerchantId, getMutasi } = require("./src/services/gobiz");

const PORT = Number(process.env.PORT || 3000);
const COOKIE_SECRET = process.env.COOKIE_SECRET;
if (!COOKIE_SECRET || COOKIE_SECRET.length < 32) throw new Error("Missing/weak env: COOKIE_SECRET (>=32 chars)");

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({
  contentSecurityPolicy: false // karena kita pakai CDN font/icon. kalau mau CSP ketat nanti aku rapikan
}));
app.use(compression());
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser(COOKIE_SECRET));
app.use("/public", express.static(path.join(__dirname, "public")));

app.use(injectLocals);

const authLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const appLimiter = rateLimit({ windowMs: 60 * 1000, limit: 240, standardHeaders: true, legacyHeaders: false });

// =====================
// ROUTES
// =====================
app.get("/", (req, res) => {
  const acc = getAccFromCookie(req);
  if (acc?.refreshTokenEnc) return res.redirect("/app");
  return res.redirect("/login");
});

// ---- AUTH UI
app.get("/login", csrfProtect, (req, res) => {
  res.render("auth/login", { csrfToken: req.csrfToken(), err: null });
});

app.post("/login", authLimiter, csrfProtect, async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    if (!phone) return res.status(400).render("auth/login", { csrfToken: req.csrfToken(), err: "Nomor wajib diisi." });

    // bikin acc sementara dan simpan di cookie (tanpa token dulu)
    const acc = buildAccFromReq(req);
    acc.phone = phone;

    await requestOtp(acc, phone);

    // simpan state sementara untuk verify (phone + uniqueId)
    setAccCookie(res, acc, req);

    return res.redirect("/verify");
  } catch (e) {
    return res.status(400).render("auth/login", { csrfToken: req.csrfToken(), err: "Gagal minta OTP. Coba lagi." });
  }
});

app.get("/verify", csrfProtect, (req, res) => {
  const acc = getAccFromCookie(req);
  if (!acc) return res.redirect("/login");
  res.render("auth/verify", { csrfToken: req.csrfToken(), err: null });
});

app.post("/verify", authLimiter, csrfProtect, async (req, res) => {
  try {
    const acc = getAccFromCookie(req);
    if (!acc) return res.redirect("/login");

    const phone = String(req.body.phone || "").trim(); // user input ulang (simple)
    const otp = String(req.body.otp || "").trim();
    if (!phone || !otp) {
      return res.status(400).render("auth/verify", { csrfToken: req.csrfToken(), err: "Phone & OTP wajib diisi." });
    }

    // verify -> token encrypted masuk acc
    await verifyOtp(acc, phone, otp);

    // prefetch merchant info (opsional)
    try { await getMerchantId(acc); } catch {}

    // simpan acc final ke cookie
    setAccCookie(res, acc, req);

    return res.redirect("/app");
  } catch (e) {
    return res.status(400).render("auth/verify", { csrfToken: req.csrfToken(), err: "OTP salah / expired." });
  }
});

app.post("/logout", csrfProtect, (req, res) => {
  clearAccCookie(res);
  res.redirect("/login");
});

// ---- APP
app.get("/app", appLimiter, requireAuth, csrfProtect, async (req, res) => {
  try {
    const acc = req.acc;

    // mutasi hari ini
    const d = new Date();
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const ymd = `${yyyy}-${mm}-${dd}`;

    const tx = await getMutasi(acc, ymd, 50);

    // gobiz.js kamu bisa refresh token & update acc fields.
    // Karena tanpa DB, kita harus set ulang cookie setelah request selesai.
    res.on("finish", () => {});
    setAccCookie(res, acc, req);

    res.render("app/dashboard", {
      csrfToken: req.csrfToken(),
      merchantName: acc.merchantName || "Merchant",
      merchantId: acc.merchantId || "-",
      dateYmd: ymd,
      tx
    });
  } catch (e) {
    // kalau token invalid / refresh gagal -> logout paksa
    clearAccCookie(res);
    return res.redirect("/login");
  }
});

app.listen(PORT, () => console.log(`✅ running http://localhost:${PORT}`));
