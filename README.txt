AIvéra Premium — ₹20 / 1,000+ AI Apps

WHAT THIS BUILD DOES
- Premium landing page at /
- ₹20 Razorpay Standard Checkout
- Server-side Razorpay order creation
- Server-side signature verification (HMAC-SHA256)
- Server-side payment-status check: captured + INR 2000 + matching order
- Signed HttpOnly premium access cookie
- /directory.html, /tools.json and the 1,000+ app PDF are protected
- Razorpay webhook endpoint included for production reconciliation

IMPORTANT
This package is production-ready code, but it is NOT live until you add your own Razorpay credentials and deploy the Worker. No secret key is included in the files.

DEPLOY
1. Install Cloudflare Wrangler.
2. Run: wrangler login
3. From this folder run: wrangler secret put RAZORPAY_KEY_ID
4. Run: wrangler secret put RAZORPAY_KEY_SECRET
5. Run: wrangler secret put ACCESS_TOKEN_SECRET
6. Run: wrangler secret put RAZORPAY_WEBHOOK_SECRET
7. Run: wrangler deploy

RAZORPAY
Use separate Test and Live keys. Test the full checkout first, then switch to Live keys. Configure payment capture in Razorpay and add the deployed /api/razorpay-webhook URL in Razorpay Dashboard.

SECURITY
Never put RAZORPAY_KEY_SECRET in browser JavaScript. The browser only receives the public Key ID and the server-created order ID.


=== RAZORPAY TEST MODE ===
This package is locked to Razorpay TEST mode. It rejects a live key ID (rzp_live_...) and requires a Test Key ID beginning with rzp_test_. No real money should be charged in Test Mode.

1. In Razorpay Dashboard, switch to Test Mode and generate Test API Keys.
2. In this project folder run:
   wrangler secret put RAZORPAY_KEY_ID
   wrangler secret put RAZORPAY_KEY_SECRET
   wrangler secret put ACCESS_TOKEN_SECRET
   wrangler secret put RAZORPAY_WEBHOOK_SECRET
3. Deploy:
   wrangler deploy
4. Open the deployed AIvera site and press “Pay ₹20”.
5. Use Razorpay's official Test Mode payment credentials shown in its Test Mode documentation/checkout.

IMPORTANT: Do not paste secret keys into the website HTML or commit them to the ZIP.
