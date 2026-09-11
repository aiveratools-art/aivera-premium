const ACCESS_COOKIE = "aivera_premium";
const PHONE_COOKIE = "aivera_verified_phone";
const ACCESS_SECONDS = 60 * 60 * 24 * 30;
const PHONE_SECONDS = 60 * 60 * 2;
const OTP_SECONDS = 10 * 60;
const OTP_COOKIE = "aivera_2factor_otp";
const PREMIUM_AMOUNT = 9900;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "POST" && url.pathname === "/api/send-otp") return await sendOtp2Factor(request, env);
      if (request.method === "POST" && url.pathname === "/api/verify-otp") return await verifyOtp2Factor(request, env);
      if (request.method === "POST" && url.pathname === "/api/create-order") return await createOrder(request, env);
      if (request.method === "POST" && url.pathname === "/api/verify-payment") return await verifyPayment(request, env);
      if (request.method === "POST" && url.pathname === "/api/razorpay-webhook") return await webhook(request, env);

      if (url.pathname === "/directory.html" || url.pathname === "/tools.json" || url.pathname === "/AIvera-Premium-10K.pdf") {
        if (!(await validAccess(request.headers.get("Cookie") || "", env))) {
          return Response.redirect(new URL("/", request.url).toString(), 302);
        }
      }

      return await env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "Server error", message: String(error?.message || error) }, 500);
    }
  }
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers }
  });
}

function basic(key, secret) {
  return "Basic " + btoa(`${key}:${secret}`);
}

function cookieValue(header, name) {
  const m = header.match(new RegExp("(?:^|;\\s*)" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]+)"));
  return m ? m[1] : "";
}

function normalizePhone(value) {
  const digits = String(value || "").replace(/\D/g, "");
  if (digits.length === 10) return "91" + digits;
  if (digits.length === 12 && digits.startsWith("91")) return digits;
  return "";
}

async function sendOtp2Factor(request, env) {
  if (!env.TWOFACTOR_API_KEY || !env.ACCESS_TOKEN_SECRET || !env.DB) {
    return json({ error: "2Factor/D1 server configuration is incomplete." }, 503);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON request." }, 400); }

  const phone = normalizePhone(body?.phone);
  if (!phone) return json({ error: "Please enter a valid 10-digit mobile number." }, 400);

  const url = `https://2factor.in/API/V1/${encodeURIComponent(env.TWOFACTOR_API_KEY)}/SMS/${encodeURIComponent(phone)}/AUTOGEN`;
  const r = await fetch(url, { method: "GET" });
  const text = await r.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}

  if (!r.ok || String(data?.Status || "").toLowerCase() !== "success" || !data?.Details) {
    console.error("2Factor send OTP failed:", r.status, text);
    return json({ error: "OTP could not be sent. Please try again.", provider_status: r.status }, 502);
  }

  const now = Math.floor(Date.now() / 1000);
  const otpToken = await makeToken(
    { sub: "otp_session", phone, sid: String(data.Details), exp: now + OTP_SECONDS },
    env.ACCESS_TOKEN_SECRET
  );

  return json(
    { ok: true, message: "OTP sent successfully." },
    200,
    { "Set-Cookie": `${OTP_COOKIE}=${otpToken}; Max-Age=${OTP_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax` }
  );
}
async function verifyOtp2Factor(request, env) {
  if (!env.TWOFACTOR_API_KEY || !env.ACCESS_TOKEN_SECRET || !env.DB) {
    return json({ error: "2Factor/D1 server configuration is incomplete." }, 503);
  }

  const otpCookie = cookieValue(request.headers.get("Cookie") || "", OTP_COOKIE);
  const session = await readToken(otpCookie, env.ACCESS_TOKEN_SECRET);
  if (!session || session.sub !== "otp_session" || !session.phone || !session.sid) {
    return json({ error: "OTP session expired. Please send OTP again." }, 401);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON request." }, 400); }
  const otp = String(body?.otp || "").replace(/\D/g, "");
  if (!otp) return json({ error: "Please enter the OTP." }, 400);

  const url = `https://2factor.in/API/V1/${encodeURIComponent(env.TWOFACTOR_API_KEY)}/SMS/VERIFY/${encodeURIComponent(session.sid)}/${encodeURIComponent(otp)}`;
  const r = await fetch(url, { method: "GET" });
  const text = await r.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}

  if (!r.ok || String(data?.Status || "").toLowerCase() !== "success") {
    return json({ error: "Incorrect or expired OTP. Please try again." }, 401);
  }

  const phone = normalizePhone(session.phone);
  const row = await env.DB.prepare(
    "SELECT premium FROM users WHERE phone = ?1 LIMIT 1"
  ).bind(phone).first();

  const now = Math.floor(Date.now() / 1000);
  const phoneToken = await makeToken(
    { sub: "verified_phone", phone, exp: now + PHONE_SECONDS },
    env.ACCESS_TOKEN_SECRET
  );
  const response = json({ premium: Number(row?.premium) === 1 });
  response.headers.append("Set-Cookie", `${PHONE_COOKIE}=${phoneToken}; Max-Age=${PHONE_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  response.headers.append("Set-Cookie", `${OTP_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`);

  if (Number(row?.premium) === 1) {
    const premiumToken = await makeToken(
      { sub: "premium", phone, exp: now + ACCESS_SECONDS },
      env.ACCESS_TOKEN_SECRET
    );
    response.headers.append("Set-Cookie", `${ACCESS_COOKIE}=${premiumToken}; Max-Age=${ACCESS_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  }

  return response;
}

async function getVerifiedPhone(request, env) {
  if (!env.ACCESS_TOKEN_SECRET || !env.DB) return "";

  const token = cookieValue(
    request.headers.get("Cookie") || "",
    PHONE_COOKIE
  );

  const data = await readToken(token, env.ACCESS_TOKEN_SECRET);
  if (!data || data.sub !== "verified_phone" || !data.phone) return "";

  return normalizePhone(data.phone);
}

async function createOrder(request, env) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET || !env.ACCESS_TOKEN_SECRET || !env.DB) {
    return json({ error: "Payment/D1 server configuration is incomplete." }, 503);
  }

  const phone = await getVerifiedPhone(request, env);
  if (!phone) return json({ error: "Please verify your mobile with OTP first." }, 401);

  const existing = await env.DB.prepare(
    "SELECT premium FROM users WHERE phone = ?1 LIMIT 1"
  ).bind(phone).first();

  if (Number(existing?.premium) === 1) {
    const token = await makeToken(
      { sub: "premium", phone, exp: Math.floor(Date.now() / 1000) + ACCESS_SECONDS },
      env.ACCESS_TOKEN_SECRET
    );

    return json(
      { premium: true },
      200,
      {
        "Set-Cookie":
          `${ACCESS_COOKIE}=${token}; Max-Age=${ACCESS_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax`
      }
    );
  }

  const paymentMode = String(env.PAYMENT_MODE || "test");

  if (
    paymentMode === "test" &&
    !String(env.RAZORPAY_KEY_ID).startsWith("rzp_test_")
  ) {
    return json({ error: "TEST MODE requires a Razorpay Test Key ID." }, 500);
  }

  const receipt =
    "aivera_" + crypto.randomUUID().replaceAll("-", "").slice(0, 24);
  const response = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      Authorization: basic(env.RAZORPAY_KEY_ID, env.RAZORPAY_KEY_SECRET),
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      amount: PREMIUM_AMOUNT,
      currency: "INR",
      receipt,
      notes: {
        product: "AIvera Premium 10K",
        phone
      }
    })
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    return json(
      {
        error: "Razorpay order creation failed",
        razorpay_status: response.status,
        razorpay_code: data?.error?.code || null,
        razorpay_description: data?.error?.description || null
      },
      502
    );
  }

  return json({
    key_id: env.RAZORPAY_KEY_ID,
    order_id: data.id,
    amount: data.amount,
    currency: data.currency,
    mode: paymentMode
  });
}

async function verifyPayment(request, env) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET || !env.ACCESS_TOKEN_SECRET || !env.DB) {
    return json({ error: "Payment/D1 server configuration is incomplete." }, 503);
  }

  const phone = await getVerifiedPhone(request, env);
  if (!phone) return json({ error: "Mobile verification expired. Please verify OTP again." }, 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON request." }, 400);
  }

  const {
    razorpay_payment_id,
    razorpay_order_id,
    razorpay_signature
  } = body || {};

  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return json({ error: "Missing payment verification fields." }, 400);
  }

  const expectedSignature = await hmacHex(
    env.RAZORPAY_KEY_SECRET,
    `${razorpay_order_id}|${razorpay_payment_id}`
  );

  if (!timingSafeEqual(expectedSignature, razorpay_signature)) {
    return json({ error: "Invalid payment signature." }, 400);
  }

  const response = await fetch(
    `https://api.razorpay.com/v1/payments/${encodeURIComponent(razorpay_payment_id)}`,
    {
      headers: {
        Authorization: basic(env.RAZORPAY_KEY_ID, env.RAZORPAY_KEY_SECRET)
      }
    }
  );

  const payment = await response.json().catch(() => null);

  if (!response.ok) {
    return json({ error: "Unable to verify payment with Razorpay." }, 502);
  }

  if (
    payment.order_id !== razorpay_order_id ||
    payment.amount !== PREMIUM_AMOUNT ||
    payment.currency !== "INR" ||
    payment.status !== "captured"
  ) {
    return json({ error: "Payment is not captured/valid yet." }, 400);
  }

  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO payments
      (phone, razorpay_payment_id, razorpay_order_id, amount, currency, status, created_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT(razorpay_payment_id) DO UPDATE SET
      phone = excluded.phone,
      razorpay_order_id = excluded.razorpay_order_id,
      amount = excluded.amount,
      currency = excluded.currency,
      status = excluded.status
  `).bind(
    phone,
    razorpay_payment_id,
    razorpay_order_id,
    PREMIUM_AMOUNT,
    "INR",
    "captured",
    now
  ).run();
  await env.DB.prepare(`
    INSERT INTO users
      (phone, premium, payment_id, created_at, updated_at)
    VALUES (?1, 1, ?2, ?3, ?3)
    ON CONFLICT(phone) DO UPDATE SET
      premium = 1,
      payment_id = excluded.payment_id,
      updated_at = excluded.updated_at
  `).bind(
    phone,
    razorpay_payment_id,
    now
  ).run();

  const token = await makeToken(
    {
      sub: "premium",
      phone,
      payment: razorpay_payment_id,
      exp: now + ACCESS_SECONDS
    },
    env.ACCESS_TOKEN_SECRET
  );

  return json(
    {
      ok: true,
      premium: true,
      message: "Payment verified successfully."
    },
    200,
    {
      "Set-Cookie":
        `${ACCESS_COOKIE}=${token}; Max-Age=${ACCESS_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax`
    }
  );
}

async function webhook(request, env) {
  if (!env.RAZORPAY_WEBHOOK_SECRET) {
    return json({ error: "Webhook secret not configured." }, 503);
  }

  const raw = await request.text();
  const signature = request.headers.get("x-razorpay-signature") || "";

  const expected = await hmacHex(
    env.RAZORPAY_WEBHOOK_SECRET,
    raw
  );

  if (!timingSafeEqual(expected, signature)) {
    return json({ error: "Invalid webhook signature." }, 400);
  }

  try {
    const event = JSON.parse(raw);
    const paymentEntity = event?.payload?.payment?.entity;

    if (
      paymentEntity?.id &&
      paymentEntity?.order_id &&
      paymentEntity?.amount &&
      paymentEntity?.currency
    ) {
      const phone = normalizePhone(paymentEntity?.notes?.phone);

      if (phone) {
        const now = Math.floor(Date.now() / 1000);
        const status = String(paymentEntity.status || event.event || "unknown");

        await env.DB.prepare(`
          INSERT INTO payments
            (phone, razorpay_payment_id, razorpay_order_id, amount, currency, status, created_at)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
          ON CONFLICT(razorpay_payment_id) DO UPDATE SET
            phone = excluded.phone,
            razorpay_order_id = excluded.razorpay_order_id,
            amount = excluded.amount,
            currency = excluded.currency,
            status = excluded.status
        `).bind(
          phone,
          paymentEntity.id,
          paymentEntity.order_id,
          Number(paymentEntity.amount),
          String(paymentEntity.currency),
          status,
          now
        ).run();

        if (
          event.event === "payment.captured" &&
          Number(paymentEntity.amount) === PREMIUM_AMOUNT &&
          String(paymentEntity.currency) === "INR"
        ) {
          await env.DB.prepare(`
            INSERT INTO users
              (phone, premium, payment_id, created_at, updated_at)
            VALUES (?1, 1, ?2, ?3, ?3)
            ON CONFLICT(phone) DO UPDATE SET
              premium = 1,
              payment_id = excluded.payment_id,
              updated_at = excluded.updated_at
          `).bind(
            phone,
            paymentEntity.id,
            now
          ).run();
        }
      }
    }
  } catch (error) {
    console.error("Webhook processing error:", error);
  }

  return new Response("ok");
}
async function validAccess(cookieHeader, env) {
  if (!env.ACCESS_TOKEN_SECRET || !env.DB) return false;

  const token = cookieValue(cookieHeader, ACCESS_COOKIE);
  const data = await readToken(token, env.ACCESS_TOKEN_SECRET);

  if (!data || data.sub !== "premium" || !data.phone) return false;
  if (data.exp <= Math.floor(Date.now() / 1000)) return false;

  const row = await env.DB.prepare(
    "SELECT premium FROM users WHERE phone = ?1 LIMIT 1"
  ).bind(normalizePhone(data.phone)).first();

  return Number(row?.premium) === 1;
}

async function readToken(token, secret) {
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, mac] = parts;
  const expected = await hmacHex(secret, payload);

  if (!timingSafeEqual(expected, mac)) return null;

  try {
    const base64 = payload.replaceAll("-", "+").replaceAll("_", "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

async function makeToken(data, secret) {
  const payload = b64url(JSON.stringify(data));
  return `${payload}.${await hmacHex(secret, payload)}`;
}

function b64url(value) {
  return btoa(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}
