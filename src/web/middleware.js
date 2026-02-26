const csrf = require("csurf");
const { getAccFromCookie } = require("./cookies");

function requireAuth(req, res, next) {
  const acc = getAccFromCookie(req);
  if (!acc || !acc.refreshTokenEnc) return res.redirect("/login");
  req.acc = acc;
  next();
}

// CSRF: aman untuk form POST EJS
const csrfProtect = csrf({
  cookie: {
    httpOnly: true,
    secure: String(process.env.NODE_ENV || "").toLowerCase() === "production",
    sameSite: "lax",
    path: "/"
  }
});

function injectLocals(req, res, next) {
  res.locals.APP_NAME = process.env.APP_NAME || "GoBiz Wallet";
  res.locals.path = req.path;
  next();
}

module.exports = { requireAuth, csrfProtect, injectLocals };
