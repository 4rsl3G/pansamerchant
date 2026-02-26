const crypto = require("crypto");
const { encrypt, decrypt } = require("../utils/cryptoBox");

const COOKIE_NAME = "gobiz_acc";

function isProd() {
  return String(process.env.NODE_ENV || "").toLowerCase() === "production";
}

function cookieOpts() {
  return {
    httpOnly: true,
    secure: isProd(),       // wajib true di production (HTTPS)
    sameSite: "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 hari
  };
}

function uaHash(req) {
  const ua = String(req.headers["user-agent"] || "");
  // hash biar tidak simpan UA mentah panjang2, dan untuk deteksi hijack basic
  return crypto.createHash("sha256").update(ua).digest("hex");
}

function buildAccFromReq(req) {
  // uniqueId stabil di cookie; kalau belum ada, dibuat saat login sukses
  return {
    uniqueId: crypto.randomUUID(),
    userAgent: String(req.headers["user-agent"] || "Mozilla/5.0"),
    tokenExpiry: 0,
    accessTokenEnc: null,
    refreshTokenEnc: null,
    merchantId: null,
    merchantName: null,

    // agar kompatibel dengan gobiz.js kamu yang memanggil acc.save() (opsional)
    async save() { /* no-op (tanpa DB) */ }
  };
}

function setAccCookie(res, acc, req) {
  const payload = {
    v: 1,
    uniqueId: acc.uniqueId,
    userAgent: acc.userAgent,
    uaHash: uaHash(req),

    tokenExpiry: acc.tokenExpiry || 0,
    accessTokenEnc: acc.accessTokenEnc || null,
    refreshTokenEnc: acc.refreshTokenEnc || null,

    merchantId: acc.merchantId || null,
    merchantName: acc.merchantName || null
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

  // basic hijack guard: UA hash harus match
  if (!data?.uaHash || data.uaHash !== uaHash(req)) return null;

  const acc = {
    uniqueId: data.uniqueId,
    userAgent: data.userAgent || String(req.headers["user-agent"] || "Mozilla/5.0"),

    tokenExpiry: Number(data.tokenExpiry || 0),
    accessTokenEnc: data.accessTokenEnc || null,
    refreshTokenEnc: data.refreshTokenEnc || null,

    merchantId: data.merchantId || null,
    merchantName: data.merchantName || null,

    async save() { /* no-op */ }
  };

  return acc;
}

module.exports = {
  COOKIE_NAME,
  buildAccFromReq,
  setAccCookie,
  clearAccCookie,
  getAccFromCookie
};
