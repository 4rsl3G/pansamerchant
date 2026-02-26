// src/services/gobizAuth.js
const axios = require("axios");
const { encrypt } = require("../utils/cryptoBox");
const { baseHeaders } = require("./gobiz");

const BASE_URL = process.env.GOBIZ_API_BASE || "https://api.gobiz.co.id";

const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  validateStatus: () => true,
});

function pickMsg(data) {
  if (!data) return null;
  if (typeof data === "string") return data.slice(0, 200);
  return (
    data.message ||
    data.error ||
    data.msg ||
    (Array.isArray(data.errors) && data.errors[0] && (data.errors[0].message || data.errors[0].msg)) ||
    null
  );
}

function makeErr(res, label) {
  const msg = pickMsg(res?.data);
  const e = new Error(`${label}:${res?.status || 0}${msg ? `:${msg}` : ""}`);
  e.status = res?.status || 0;
  e.upstream = res?.data;
  return e;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Login GoBiz pakai EMAIL + PASSWORD (tanpa OTP)
 * - Tidak menyimpan password
 * - Mengisi acc.accessTokenEnc / acc.refreshTokenEnc / acc.tokenExpiry (encrypted)
 */
async function emailLogin(acc, email, password) {
  const em = String(email || "").trim().toLowerCase();
  const pw = String(password || "");
  if (!em || !pw) {
    const e = new Error("EMAIL_LOGIN_INVALID_INPUT");
    e.status = 400;
    throw e;
  }

  // STEP 1: login request (beberapa flow butuh ini)
  const r1 = await http.post(
    "/goid/login/request",
    { email: em, login_type: "password", client_id: "go-biz-web-new" },
    { headers: baseHeaders(acc) }
  );

  if (r1.status < 200 || r1.status >= 300) throw makeErr(r1, "EMAIL_LOGIN_REQUEST_FAILED");

  // kasih jeda kecil biar stabil (sesuai pola yang kamu pakai)
  await sleep(800);

  // STEP 2: exchange token
  const r2 = await http.post(
    "/goid/token",
    {
      client_id: "go-biz-web-new",
      grant_type: "password",
      data: { email: em, password: pw, user_type: "merchant" },
    },
    { headers: baseHeaders(acc) }
  );

  if (r2.status < 200 || r2.status >= 300) throw makeErr(r2, "EMAIL_LOGIN_TOKEN_FAILED");

  const access = r2.data?.access_token;
  const refresh = r2.data?.refresh_token;
  const exp = Date.now() + Number(r2.data?.expires_in || 3600) * 1000;

  if (!access || !refresh) {
    const e = new Error("EMAIL_LOGIN_NO_TOKEN");
    e.status = 502;
    e.upstream = r2.data;
    throw e;
  }

  acc.accessTokenEnc = encrypt(access);
  acc.refreshTokenEnc = encrypt(refresh);
  acc.tokenExpiry = exp;

  if (typeof acc.save === "function") await acc.save(); // no-op untuk cookie-only
  return { exp, raw: r2.data };
}

module.exports = { emailLogin };
