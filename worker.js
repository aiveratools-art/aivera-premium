const ACCESS_COOKIE = 'aivera_premium';
const ACCESS_SECONDS = 60 * 60 * 24 * 365;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === 'POST' && url.pathname === '/api/create-order') return createOrder(request, env);
      if (request.method === 'POST' && url.pathname === '/api/verify-payment') return verifyPayment(request, env);
      if (request.method === 'POST' && url.pathname === '/api/razorpay-webhook') return webhook(request, env);

      if (url.pathname === '/directory.html' || url.pathname === '/tools.json' || url.pathname === '/AIvera-1,000-Plus-Free-PDF.pdf') {
        const cookie = request.headers.get('Cookie') || '';
        if (!(await validAccess(cookie, env))) return Response.redirect(new URL('/', request.url).toString(), 302);
      }
      return env.ASSETS.fetch(request);
    } catch (e) {
      return json({error: 'Server error'}, 500);
    }
  }
};

function json(data, status=200, headers={}) { return new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8', ...headers}}); }
function basic(key, secret) { return 'Basic ' + btoa(`${key}:${secret}`); }

async function createOrder(request, env) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) return json({error:'Razorpay TEST keys are not configured on the server.'},503);
  if ((env.PAYMENT_MODE || 'test') === 'test' && !String(env.RAZORPAY_KEY_ID).startsWith('rzp_test_')) return json({error:'TEST MODE requires a Razorpay Test Key ID starting with rzp_test_.'},500);
  const body = await request.json().catch(()=>({}));
  const receipt = 'aivera_' + crypto.randomUUID().replaceAll('-','').slice(0,24);
  const r = await fetch('https://api.razorpay.com/v1/orders', {
    method:'POST', headers:{'Authorization':basic(env.RAZORPAY_KEY_ID,env.RAZORPAY_KEY_SECRET),'Content-Type':'application/json'},
    body:JSON.stringify({amount:2000,currency:'INR',receipt,notes:{product:'AIvera Premium Access',source:'website'}})
  });
  const d = await r.json();
  if (!r.ok) return json({
    error:'Razorpay order creation failed',
    razorpay_status:r.status,
    razorpay_code:d?.error?.code || null,
    razorpay_description:d?.error?.description || null
  },502);
  return json({key_id:env.RAZORPAY_KEY_ID,order_id:d.id,amount:d.amount,currency:d.currency,mode:env.PAYMENT_MODE || 'test'});
}

async function verifyPayment(request, env) {
  if (!env.RAZORPAY_KEY_SECRET || !env.ACCESS_TOKEN_SECRET) return json({error:'Payment secrets are not configured on the server.'},503);
  const {razorpay_payment_id,razorpay_order_id,razorpay_signature} = await request.json();
  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) return json({error:'Missing payment verification fields.'},400);
  const expected = await hmacHex(env.RAZORPAY_KEY_SECRET, `${razorpay_order_id}|${razorpay_payment_id}`);
  if (!timingSafeEqual(expected, razorpay_signature)) return json({error:'Invalid payment signature.'},400);

  const r = await fetch(`https://api.razorpay.com/v1/payments/${encodeURIComponent(razorpay_payment_id)}`, {headers:{'Authorization':basic(env.RAZORPAY_KEY_ID,env.RAZORPAY_KEY_SECRET)}});
  const p = await r.json();
  if (!r.ok || p.order_id !== razorpay_order_id || p.amount !== 2000 || p.currency !== 'INR' || p.status !== 'captured') return json({error:'Payment is not captured/valid yet.'},400);

  const token = await makeToken({sub:'premium',payment:razorpay_payment_id,exp:Math.floor(Date.now()/1000)+ACCESS_SECONDS},env.ACCESS_TOKEN_SECRET);
  return json({ok:true},{headers:{'set-cookie':`${ACCESS_COOKIE}=${token}; Max-Age=${ACCESS_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax`}});
}

async function webhook(request, env) {
  if (!env.RAZORPAY_WEBHOOK_SECRET) return json({error:'Webhook secret not configured.'},503);
  const raw = await request.text();
  const sig = request.headers.get('x-razorpay-signature') || '';
  const expected = await hmacHex(env.RAZORPAY_WEBHOOK_SECRET, raw);
  if (!timingSafeEqual(expected,sig)) return json({error:'Invalid webhook signature.'},400);
  return new Response('ok');
}

async function validAccess(cookieHeader, env) {
  if (!env.ACCESS_TOKEN_SECRET) return false;
  const m = cookieHeader.match(new RegExp('(?:^|;\\s*)'+ACCESS_COOKIE+'=([^;]+)'));
  if (!m) return false;
  const parts = m[1].split('.'); if (parts.length!==2) return false;
  const [payload,mac] = parts;
  const expected = await hmacHex(env.ACCESS_TOKEN_SECRET,payload);
  if (!timingSafeEqual(expected,mac)) return false;
  try { const d=JSON.parse(atob(payload.replaceAll('-','+').replaceAll('_','/'))); return d.sub==='premium' && d.exp > Math.floor(Date.now()/1000); } catch { return false; }
}
async function makeToken(data, secret) { const payload=b64url(JSON.stringify(data)); return payload+'.'+await hmacHex(secret,payload); }
function b64url(s){return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
async function hmacHex(secret, data){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);const b=await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(data));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function timingSafeEqual(a,b){if(a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i);return x===0}
