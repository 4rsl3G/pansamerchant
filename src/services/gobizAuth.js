const axios = require("axios");
const crypto = require("crypto");
const { encrypt } = require("../utils/cryptoBox");
const { baseHeaders } = require("./gobiz");

const BASE_URL = process.env.GOBIZ_API_BASE || "https://api.gobiz.co.id";

const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  validateStatus: () => true
});

// request OTP
async function requestOtp(acc, phone) {
  const res = await http.post(
    "/goid/login/request",
    {
      // sebagian implementasi memakai "phone_number" atau "phone"
      phone_number: phone,
      user_type: "merchant"
    },
    { headers: baseHeaders(acc) }
  );

  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`OTP_REQUEST_FAILED:${res.status}`);
    err.upstream = res.data;
    throw err;
  }
  return res.data;
}

// verify OTP -> dapat access_token + refresh_token
async function verifyOtp(acc, phone, otp) {
  const res = await http.post(
    "/goid/token",
    {
      client_id: "go-biz-web-new",
      // beberapa sistem pakai "otp" / "password". ini yang paling umum di wrapper merchant.
      grant_type: "password",
      data: {
        phone_number: phone,
        otp: String(otp),
        user_type: "merchant"
      }
    },
    { headers: baseHeaders(acc) }
  );

  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`OTP_VERIFY_FAILED:${res.status}`);
    err.upstream = res.data;
    throw err;
  }

  const access = res.data?.access_token;
  const refresh = res.data?.refresh_token;
  const exp = Date.now() + (Number(res.data?.expires_in || 3600) * 1000);

  if (!access || !refresh) {
    const err = new Error("OTP_VERIFY_NO_TOKEN");
    err.upstream = res.data;
    throw err;
  }

  // simpan encrypted token ke acc (cookie-only)
  acc.accessTokenEnc = encrypt(access);
  acc.refreshTokenEnc = encrypt(refresh);
  acc.tokenExpiry = exp;

  return { access, refresh, exp, raw: res.data };
}

module.exports = { requestOtp, verifyOtp };
