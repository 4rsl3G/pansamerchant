// src/services/gobiz.js
const axios = require("axios");
const { decrypt, encrypt } = require("../utils/cryptoBox");

const BASE_URL = process.env.GOBIZ_API_BASE || "https://api.gobiz.co.id";

const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  validateStatus: () => true
});

// =====================
// Headers
// =====================
function baseHeaders(acc) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json, text/plain, */*",
    "Accept-Language": "id",
    Origin: "https://portal.gofoodmerchant.co.id",
    Referer: "https://portal.gofoodmerchant.co.id/",
    "Authentication-Type": "go-id",
    "Gojek-Country-Code": "ID",
    "Gojek-Timezone": "Asia/Jakarta",
    "X-Appid": "go-biz-web-dashboard",
    "X-Appversion": "platform-v3.97.0-b986b897",
    "X-Deviceos": "Web",
    "X-Phonemake": "Windows 10 64-bit",
    "X-Phonemodel": "Chrome 143.0.0.0 on Windows 10 64-bit",
    "X-Platform": "Web",
    "X-Uniqueid": acc.uniqueId,
    "X-User-Type": "merchant",
    "User-Agent": acc.userAgent
  };
}

// =====================
// Helpers
// =====================
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function jitter(ms) {
  return Math.floor(ms * (0.75 + Math.random() * 0.5)); // 75%..125%
}
function isRetryableStatus(status) {
  return status === 429 || status === 502 || status === 503 || status === 504;
}
function toNum(v) {
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isFinite(n) ? n : NaN;
  }
  return NaN;
}

function makeHttpError(res, label = "UPSTREAM_ERROR") {
  const status = res?.status;
  const data = res?.data;
  const msg =
    (data && (data.message || data.error || data.errors?.[0]?.message)) ||
    (typeof data === "string" ? data.slice(0, 200) : null) ||
    null;

  const err = new Error(`${label}:${status || "NO_STATUS"}${msg ? `:${msg}` : ""}`);
  err.status = status || 0;
  err.upstream = data;
  return err;
}

// =====================
// Single-flight refresh per account (anti race)
// =====================
const refreshLocks = new Map(); // key -> Promise<string>

function lockKey(acc) {
  return String(acc.id || acc._id || acc.uniqueId || "acc");
}

// =====================
// Token refresh
// =====================
async function refreshToken(acc) {
  const key = lockKey(acc);
  if (refreshLocks.has(key)) return refreshLocks.get(key);

  const p = (async () => {
    const refresh = decrypt(acc.refreshTokenEnc);
    if (!refresh) throw new Error("NO_REFRESH_TOKEN");

    const res = await http.post(
      "/goid/token",
      {
        client_id: "go-biz-web-new",
        grant_type: "refresh_token",
        data: { refresh_token: refresh, user_type: "merchant" }
      },
      { headers: baseHeaders(acc) }
    );

    if (res.status < 200 || res.status >= 300) throw makeHttpError(res, "REFRESH_FAILED");

    const access = res.data?.access_token;
    const newRefresh = res.data?.refresh_token || refresh;
    const expiresIn = toNum(res.data?.expires_in);
    const exp = Date.now() + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000;

    if (!access) {
      const e = new Error("REFRESH_NO_ACCESS_TOKEN");
      e.upstream = res.data;
      throw e;
    }

    acc.accessTokenEnc = encrypt(access);
    acc.refreshTokenEnc = encrypt(newRefresh);
    acc.tokenExpiry = exp;

    if (typeof acc.save === "function") await acc.save(); // ok untuk DB / no-op untuk cookie-only
    return access;
  })();

  refreshLocks.set(key, p);

  try {
    return await p;
  } finally {
    refreshLocks.delete(key);
  }
}

async function getAccessToken(acc) {
  const exp = Number(acc.tokenExpiry || 0);
  const access = decrypt(acc.accessTokenEnc);

  // refresh 5 menit sebelum expired
  if (access && exp && Date.now() < exp - 5 * 60 * 1000) return access;
  return refreshToken(acc);
}

// =====================
// Auth request with retry + auto refresh
// =====================
async function authRequest(acc, method, url, data, extraHeaders = {}) {
  const maxRetry = 2;

  async function doReq(access) {
    return http.request({
      method,
      url: url.startsWith("http") ? url : url, // kalau kamu kirim "/path" juga aman
      data,
      headers: { ...baseHeaders(acc), Authorization: `Bearer ${access}`, ...extraHeaders }
    });
  }

  let access = await getAccessToken(acc);

  for (let attempt = 0; attempt <= maxRetry; attempt++) {
    let res;
    try {
      res = await doReq(access);
    } catch (e) {
      // network / timeout
      if (attempt < maxRetry) {
        await sleep(jitter(400 * Math.pow(2, attempt)));
        continue;
      }
      const err = new Error(`NETWORK_ERROR:${e.message || "unknown"}`);
      err.cause = e;
      throw err;
    }

    // token invalid → refresh sekali
    if (res.status === 401) {
      access = await refreshToken(acc);
      const res2 = await doReq(access);
      if (res2.status < 200 || res2.status >= 300) throw makeHttpError(res2);
      return res2.data;
    }

    // retryable upstream
    if (isRetryableStatus(res.status) && attempt < maxRetry) {
      const retryAfterHeader = res.headers?.["retry-after"];
      const retryAfterMs = retryAfterHeader ? Math.max(0, Number(retryAfterHeader) * 1000) : 0;
      const backoff = retryAfterMs || jitter(500 * Math.pow(2, attempt));
      await sleep(backoff);
      continue;
    }

    if (res.status < 200 || res.status >= 300) throw makeHttpError(res);
    return res.data;
  }

  throw new Error("REQUEST_RETRY_EXHAUSTED");
}

// =====================
// Normalize tx
// =====================
function toRupiahFromSen(valueSen) {
  const n = toNum(valueSen);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n / 100);
}

function pickAmountSen(tx) {
  const t = tx?.metadata?.transaction || {};
  const v =
    t.gross_amount ??
    t.amount ??
    t.total_amount ??
    t.gopay_amount ??
    t.gopay?.amount ??
    t.gopay?.gross_amount ??
    t.details?.amount ??
    t.details?.gross_amount;

  return toNum(v);
}

function normalizeTx(tx) {
  const t = tx?.metadata?.transaction || {};
  const amountSen = pickAmountSen(tx);
  const amount = toRupiahFromSen(amountSen);

  const id =
    tx?.id ||
    tx?._id ||
    t?.order_id ||
    t?.transaction_id ||
    null;

  const time =
    t?.transaction_time ||
    tx?.time ||
    tx?.created_at ||
    null;

  return {
    id,
    time,
    status: t?.status || tx?.status || null,
    paymentType: t?.payment_type || t?.payment_type_id || null,
    amount,
    raw: tx
  };
}

// =====================
// Merchant & Mutasi
// =====================
async function getMerchantId(acc) {
  const r = await authRequest(
    acc,
    "POST",
    "/v1/merchants/search",
    { from: 0, to: 1, _source: ["id", "name"] }
  );

  const m = r?.hits?.[0];
  if (m?.id) {
    acc.merchantId = m.id;
    acc.merchantName = m.name || acc.merchantName;
    if (typeof acc.save === "function") await acc.save();
  }
  return acc.merchantId || null;
}

async function getMutasi(acc, dateYmd, size = 50) {
  const fromISO = `${dateYmd}T00:00:00+07:00`;
  const toISO = `${dateYmd}T23:59:59+07:00`;

  const merchantId = acc.merchantId || (await getMerchantId(acc));
  if (!merchantId) throw new Error("MERCHANT_NOT_FOUND");

  const r = await authRequest(
    acc,
    "POST",
    "/journals/search",
    {
      from: 0,
      size,
      sort: { time: { order: "desc" } },
      included_categories: { incoming: ["transaction_share", "action"] },
      query: [
        {
          op: "and",
          clauses: [
            { field: "metadata.transaction.merchant_id", op: "equal", value: merchantId },
            { field: "metadata.transaction.transaction_time", op: "gte", value: fromISO },
            { field: "metadata.transaction.transaction_time", op: "lte", value: toISO }
          ]
        }
      ]
    },
    { Accept: "application/json, application/vnd.journal.v1+json" }
  );

  return (r?.hits || []).map(normalizeTx);
}

module.exports = {
  BASE_URL,
  baseHeaders,
  authRequest,
  getMerchantId,
  getMutasi,

  // optional exports (kalau kamu butuh)
  refreshToken,
  getAccessToken,
  normalizeTx
};
