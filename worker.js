const ACCESS_COOKIE = "aivera_premium";
const ACCESS_SECONDS = 60 * 60 * 24 * 365;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "POST" && url.pathname === "/api/create-order") {
        return await createOrder(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/verify-payment") {
        return await verifyPayment(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/razorpay-webhook") {
        return await webhook(request, env);
      }

      if (
        url.pathname === "/directory.html" ||
        url.pathname === "/tools.json" ||
        url.pathname === "/AIvera-1,000-Plus-Free-PDF.pdf"
      ) {
        const cookie = request.headers.get("Cookie") || "";

        if (!(await validAccess(cookie, env))) {
          return Response.redirect(new URL("/", request.url).toString(), 302);
        }
      }

      return await env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Worker error:", error);

      return json(
        {
          error: "Server error",
          message: String(error?.message || error)
        },
        500
      );
    }
  }
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function basic(key, secret) {
  return "Basic " + btoa(`${key}:${secret}`);
}

async function createOrder(request, env) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json(
      { error: "Razorpay keys are not configured on the server." },
      503
    );
  }

  const paymentMode = String(env.PAYMENT_MODE || "test");

  if (
    paymentMode === "test" &&
    !String(env.RAZORPAY_KEY_ID).startsWith("rzp_test_")
  ) {
    return json(
      {
        error:
          "TEST MODE requires a Razorpay Test Key ID starting with rzp_test_."
      },
      500
    );
  }

  const receipt =
    "aivera_" +
    crypto.randomUUID().replaceAll("-", "").slice(0, 24);

  try {
    const response = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        Authorization: basic(env.RAZORPAY_KEY_ID, env.RAZORPAY_KEY_SECRET),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        amount: 2000,
        currency: "INR",
        receipt,
        notes: {
          product: "AIvera Premium Access",
          source: "website"
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
  } catch (error) {
    return json(
      {
        error: "Unable to connect to Razorpay.",
        message: String(error?.message || error)
      },
      502
    );
  }
}

async function verifyPayment(request, env) {
  if (
    !env.RAZORPAY_KEY_ID ||
    !env.RAZORPAY_KEY_SECRET ||
    !env.ACCESS_TOKEN_SECRET
  ) {
    return json(
      { error: "Payment secrets are not configured on the server." },
      503
    );
  }

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
  } = body;

  if (
    !razorpay_payment_id ||
    !razorpay_order_id ||
    !razorpay_signature
  ) {
    return json(
      { error: "Missing payment verification fields." },
      400
    );
  }

  const expectedSignature = await hmacHex(
    env.RAZORPAY_KEY_SECRET,
    `${razorpay_order_id}|${razorpay_payment_id}`
  );

  if (!timingSafeEqual(expectedSignature, razorpay_signature)) {
    return json({ error: "Invalid payment signature." }, 400);
  }

  try {
    const response = await fetch(
      `https://api.razorpay.com/v1/payments/${encodeURIComponent(
        razorpay_payment_id
      )}`,
      {
        method: "GET",
        headers: {
          Authorization: basic(
            env.RAZORPAY_KEY_ID,
            env.RAZORPAY_KEY_SECRET
          )
        }
      }
    );

    const payment = await response.json().catch(() => null);

    if (!response.ok) {
      return json(
        { error: "Unable to verify payment with Razorpay." },
        502
      );
    }

    if (
      payment.order_id !== razorpay_order_id ||
      payment.amount !== 2000 ||
      payment.currency !== "INR" ||
      payment.status !== "captured"
    ) {
      return json(
        { error: "Payment is not captured/valid yet." },
        400
      );
    }

    const token = await makeToken(
      {
        sub: "premium",
        payment: razorpay_payment_id,
        exp: Math.floor(Date.now() / 1000) + ACCESS_SECONDS
      },
      env.ACCESS_TOKEN_SECRET
    );

    return json(
      {
        ok: true,
        message: "Payment verified successfully."
      },
      200,
      {
        "Set-Cookie":
          `${ACCESS_COOKIE}=${token}; ` +
          `Max-Age=${ACCESS_SECONDS}; ` +
          `Path=/; ` +
          `Secure; ` +
          `HttpOnly; ` +
          `SameSite=Lax`
      }
    );
  } catch (error) {
    return json(
      {
        error: "Payment verification failed.",
        message: String(error?.message || error)
      },
      502
    );
  }
}

async function webhook(request, env) {
  if (!env.RAZORPAY_WEBHOOK_SECRET) {
    return json({ error: "Webhook secret not configured." }, 503);
  }

  const raw = await request.text();
  const signature = request.headers.get("x-razorpay-signature") || "";
  const expected = await hmacHex(env.RAZORPAY_WEBHOOK_SECRET, raw);

  if (!timingSafeEqual(expected, signature)) {
    return json({ error: "Invalid webhook signature." }, 400);
  }

  return new Response("ok");
}

async function validAccess(cookieHeader, env) {
  if (!env.ACCESS_TOKEN_SECRET) {
    return false;
  }

  const match = cookieHeader.match(
    new RegExp("(?:^|;\\s*)" + ACCESS_COOKIE + "=([^;]+)")
  );

  if (!match) {
    return false;
  }

  const token = match[1];
  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [payload, mac] = parts;

  const expected = await hmacHex(env.ACCESS_TOKEN_SECRET, payload);

  if (!timingSafeEqual(expected, mac)) {
    return false;
  }

  try {
    const base64 =
      payload.replaceAll("-", "+").replaceAll("_", "/");

    const padded =
      base64 + "=".repeat((4 - (base64.length % 4)) % 4);

    const data = JSON.parse(atob(padded));

    return (
      data.sub === "premium" &&
      data.exp > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

async function makeToken(data, secret) {
  const payload = b64url(JSON.stringify(data));
  const mac = await hmacHex(secret, payload);
  return `${payload}.${mac}`;
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
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}
