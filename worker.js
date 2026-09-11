const ACCESS_COOKIE = "aivera_premium";
const ACCESS_SECONDS = 60 * 60 * 24 * 365;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // =========================
      // PAYMENT API ROUTES
      // =========================

      if (
        request.method === "POST" &&
        url.pathname === "/api/create-order"
      ) {
        return await createOrder(request, env);
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/verify-payment"
      ) {
        return await verifyPayment(request, env);
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/razorpay-webhook"
      ) {
        return await webhook(request, env);
      }

      // =========================
      // PREMIUM PROTECTED FILES
      // =========================

      if (
        url.pathname === "/directory.html" ||
        url.pathname === "/tools.json" ||
        url.pathname === "/AIvera-1,000-Plus-Free-PDF.pdf"
      ) {
        const cookie = request.headers.get("Cookie") || "";

        if (!(await validAccess(cookie, env))) {
          return Response.redirect(
            new URL("/", request.url).toString(),
            302
          );
        }
      }

      // =========================
      // FRONTEND ASSETS
      // =========================

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


// ======================================================
// JSON RESPONSE HELPER
// ======================================================

function json(data, status = 200, headers = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        ...headers
      }
    }
  );
}


// ======================================================
// RAZORPAY BASIC AUTH
// ======================================================

function basic(key, secret) {
  return "Basic " + btoa(`${key}:${secret}`);
}


// ======================================================
// CREATE RAZORPAY ORDER
// ======================================================

async function createOrder(request, env) {

  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json(
      {
        error: "Razorpay keys are not configured on the server."
      },
      503
    );
  }

  const paymentMode = String(env.PAYMENT_MODE || "test");

  // TEST mode must use TEST key
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
    crypto.randomUUID()
      .replaceAll("-", "")
      .slice(0, 24);

  try {

    const response = await fetch(
      "https://api.razorpay.com/v1/orders",
      {
        method: "POST",

        headers: {
          "Authorization": basic(
            env.RAZORPAY_KEY_ID,
            env.RAZORPAY_KEY_SECRET
          ),

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
      }
    );

    const data = await response.json().catch(() => null);

    if (!response.ok) {

      return json(
        {
          error: "Razorpay order creation failed",

          razorpay_status: response.status,

          razorpay_code:
            data?.error?.code || null,

          razorpay_description:
            data?.error?.description || null
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

        message:
          String(error?.message || error)
      },
      502
    );
  }
}


// ======================================================
// VERIFY RAZORPAY PAYMENT
// ======================================================

async function verifyPayment(request, env) {

  if (
    !env.RAZORPAY_KEY_ID ||
    !env.RAZORPAY_KEY_SECRET ||
    !env.ACCESS_TOKEN_SECRET
  ) {
    return json(
      {
        error:
          "Payment secrets are not configured on the server."
      },
      503
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "Invalid JSON request."
      },
      400
    );
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
      {
        error:
          "Missing payment verification fields."
      },
      400
    );
  }

  // ----------------------------------------------------
  // Verify Razorpay signature
  // ----------------------------------------------------

  const expectedSignature = await hmacHex(
    env.RAZORPAY_KEY_SECRET,
    `${razorpay_order_id}|${razorpay_payment_id}`
  );

  if (
    !timingSafeEqual(
      expectedSignature,
      razorpay_signature
    )
  ) {
    return json(
      {
        error:
          "Invalid payment signature."
      },
      400
    );
  }

  // ----------------------------------------------------
  // Fetch payment details from Razorpay
  // ----------------------------------------------------

  try {

    const response = await fetch(
      `https://api.razorpay.com/v1/payments/${encodeURIComponent(
        razorpay_payment_id
      )}`,
      {
        method: "GET",

        headers: {
          "Authorization": basic(
            env.RAZORPAY_KEY_ID,
            env.RAZORPAY_KEY_SECRET
          )
        }
      }
    );

    const payment = await response.json().catch(() => null);

    if (!response.ok) {
      return json(
        {
          error:
            "Unable to verify payment with Razorpay."
        },
        502
      );
    }

    // --------------------------------------------------
    // Check payment is actually valid
    // --------------------------------------------------

    if (
      payment.order_id !== razorpay_order_id ||
      payment.amount !== 2000 ||
      payment.currency !== "INR" ||
      payment.status !== "captured"
    ) {
      return json(
        {
          error:
            "Payment
