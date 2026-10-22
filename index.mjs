import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createClient } from '@supabase/supabase-js';

// Automatically load .env file if available
try {
  const envPath = path.resolve(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const match = trimmed.match(/^([\w.-]+)\s*=\s*(.*)?$/);
      if (match) {
        const key = match[1];
        let val = (match[2] || '').trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        if (!process.env[key]) {
          process.env[key] = val;
        }
      }
    }
  }
} catch {
  // Ignore error reading .env
}

const PORT = Number(process.env.PORT || 8787);
const BASE_URL = (process.env.ABLINER_API_BASE_URL || 'https://abliner.net').replace(/\/$/, '');
const API_KEY = process.env.ABLINER_API_KEY;
const WEBHOOK_SECRET = process.env.ABLINER_WEBHOOK_SECRET;
const WEB_ORIGIN = process.env.WEB_ORIGIN || '*';
const PAYMENT_WEBHOOK_URL = process.env.PAYMENT_WEBHOOK_URL || `${WEB_ORIGIN.replace(/\/$/, '')}/api/abliner/webhooks/abliner`;

// Supabase client initialization
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const supabase = (SUPABASE_URL && SUPABASE_KEY) ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;
const supabaseAdmin = SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { autoRefreshToken: false, persistSession: false } })
  : null;

// OTP memory cache for password resets: email -> { code, userId, expiresAt }
const otpStore = new Map();

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': WEB_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-webhook-timestamp, x-webhook-signature, Idempotency-Key',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
  });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) reject(new Error('Request body too large'));
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

function safePath(pathname) {
  const allowed = ['/balance', '/transactions', '/deposits', '/checkout', '/withdrawals', '/withdrawals/preview', '/control-numbers', '/sms/balance', '/sms/sender-ids', '/sms/send', '/sms/send-bulk'];
  return allowed.some((p) => pathname === p || pathname.startsWith(`${p}?`));
}

function signDeposit(body) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(`${timestamp}.${body}`).digest('hex');
  return { timestamp, signature };
}

function verifyWebhook(req, rawBody) {
  if (!WEBHOOK_SECRET) return false;
  const timestamp = req.headers['x-webhook-timestamp'];
  const signature = req.headers['x-webhook-signature'];
  if (typeof timestamp !== 'string' || typeof signature !== 'string') return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(`${timestamp}.${rawBody}`).digest('hex');
  return expected.length === signature.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

async function proxy(req, res, endpoint, rawBody, query) {
  if (!API_KEY) return json(res, 503, { status: 'error', code: 'payment_not_configured', message: 'Payment service is not configured.' });
  let body = rawBody || undefined;
  if (body && (endpoint === '/deposits' || endpoint === '/checkout')) {
    try {
      const payload = JSON.parse(body);
      payload.callback_url = PAYMENT_WEBHOOK_URL;
      delete payload.callbackUrl;
      body = JSON.stringify(payload);
    } catch { return json(res, 400, { status: 'error', code: 'invalid_payment_request', message: 'Invalid payment request.' }); }
  }
  const headers = { Authorization: `Bearer ${API_KEY}`, Accept: 'application/json' };
  if (body) headers['Content-Type'] = 'application/json';
  if (endpoint === '/deposits') {
    if (!WEBHOOK_SECRET) return json(res, 503, { status: 'error', code: 'webhook_secret_required', message: 'Payment security is not configured.' });
    const signed = signDeposit(body);
    headers['Idempotency-Key'] = req.headers['idempotency-key'] || `fabopay-${crypto.randomUUID()}`;
    headers['x-abliner-timestamp'] = signed.timestamp;
    headers['x-abliner-signature'] = signed.signature;
  }
  const upstream = await fetch(`${BASE_URL}/api/v1${endpoint}${query || ''}`, { method: req.method, headers, body });
  const text = await upstream.text();
  res.writeHead(upstream.status, {
    'Content-Type': upstream.headers.get('content-type') || 'application/json',
    'Access-Control-Allow-Origin': WEB_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  });
  res.end(text);
}

async function registerUser(res, rawBody) {
  if (!supabaseAdmin) return json(res, 503, { status: 'error', code: 'supabase_not_configured', message: 'Supabase server configuration is missing.' });
  let input;
  try { input = JSON.parse(rawBody); } catch { return json(res, 400, { status: 'error', code: 'invalid_json', message: 'Invalid JSON body.' }); }
  const email = String(input.email || '').trim().toLowerCase();
  const fullName = String(input.fullName || '').trim();
  const phone = String(input.phone || '').trim();
  const password = String(input.password || '');
  const pin = String(input.pin || '');
  if (!email || !fullName || !phone || password.length < 8 || !/^\d{4}$/.test(pin)) return json(res, 400, { status: 'error', code: 'validation_error', message: 'Full name, phone, email, password and a 4-digit PIN are required.' });
  const { data, error } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: fullName, phone } });
  if (error || !data.user) return json(res, 400, { status: 'error', code: 'registration_failed', message: error?.message || 'Could not create account.' });
  const pinHash = crypto.createHash('sha256').update(`${data.user.id}:pin:${pin}`).digest('hex');
  const { data: profile, error: profileError } = await supabaseAdmin.from('profiles').upsert({ id: data.user.id, full_name: fullName, phone, email, pin_hash: pinHash }, { onConflict: 'id' }).select('id,full_name,phone,email,status,created_at,pin_hash,status_reason,status_changed_at').single();
  if (profileError) {
    await supabaseAdmin.auth.admin.deleteUser(data.user.id);
    return json(res, 500, { status: 'error', code: 'profile_failed', message: `Account rollback: ${profileError.message}` });
  }
  return json(res, 201, { status: 'success', user: profile });
}

// Authenticate client API key against Supabase api_keys table
async function authenticateClientKey(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return { error: 'unauthorized', message: 'Weka API key halali kwenye header: Authorization: Bearer fp_live_...' };
  const token = auth.slice(7).trim();
  if (!token) return { error: 'unauthorized', message: 'API key haipo' };

  if (!supabase) {
    return { keyRow: { id: 'dev', user_id: 'dev_user', name: 'Default Dev Key', status: 'active' } };
  }

  const last4 = token.slice(-4);
  const { data: keyRow, error } = await supabase
    .from('api_keys')
    .select('*, profiles(full_name, email, phone)')
    .or(`last4.eq.${last4},id.eq.${token}`)
    .maybeSingle();

  if (error || !keyRow) {
    return { error: 'invalid_key', message: 'API key hii haijatambuliwa kwenye mfumo.' };
  }

  if (keyRow.status === 'blocked') {
    return {
      error: 'api_key_blocked',
      message: `API Key imezuiwa na utawala wa Fabopay. Sababu: ${keyRow.block_reason || 'Ukiukwaji wa masharti ya mfumo.'}`
    };
  }

  return { keyRow };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return json(res, 204, {});
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Health check
    if (url.pathname === '/health') return json(res, 200, { ok: true, service: 'fabopaye-payments', timestamp: new Date().toISOString() });
    if (url.pathname === '/api/auth/register' && req.method === 'POST') return registerUser(res, await readBody(req));

    // -------------------------------------------------------------
    // FORGOT PASSWORD FLOW ENDPOINTS
    // -------------------------------------------------------------
    if (url.pathname === '/api/auth/forgot-password/request-otp' && req.method === 'POST') {
      const raw = await readBody(req);
      const { email, phone } = JSON.parse(raw || '{}');
      const cleanEmail = (email || '').trim().toLowerCase();
      const cleanPhone = (phone || '').replace(/\D/g, '');

      if (!cleanEmail || !cleanPhone) {
        return json(res, 400, { status: 'error', message: 'Tafadhali weka barua pepe na namba ya simu zilizosajiliwa.' });
      }

      let userProfile = null;
      if (supabase) {
        const { data: profile } = await supabase
          .from('profiles')
          .select('id, email, phone, full_name')
          .eq('email', cleanEmail)
          .maybeSingle();

        if (profile) {
          const dbPhoneDigits = (profile.phone || '').replace(/\D/g, '');
          if (dbPhoneDigits.endsWith(cleanPhone.slice(-9)) || cleanPhone.endsWith(dbPhoneDigits.slice(-9))) {
            userProfile = profile;
          }
        }
      }

      if (!userProfile) {
        return json(res, 404, { status: 'error', message: 'Akaunti yenye barua pepe na namba hii ya simu haijapatikana.' });
      }

      // Generate 6 digit code
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      otpStore.set(cleanEmail, {
        code,
        userId: userProfile.id,
        phone: userProfile.phone,
        expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
      });

      console.log(`[FABOPAY AUTH] OTP Reset Code for ${cleanEmail} (${cleanPhone}): ${code}`);

      return json(res, 200, {
        status: 'success',
        message: 'Nambari ya uthibitisho (OTP) imetumwa.',
        code // Included so user gets it immediately in UI demo/toast
      });
    }

    if (url.pathname === '/api/auth/forgot-password/verify-otp' && req.method === 'POST') {
      const raw = await readBody(req);
      const { email, code } = JSON.parse(raw || '{}');
      const cleanEmail = (email || '').trim().toLowerCase();
      const entry = otpStore.get(cleanEmail);

      if (!entry || entry.code !== String(code || '').trim() || Date.now() > entry.expiresAt) {
        return json(res, 400, { status: 'error', message: 'Nambari ya uthibitisho (OTP) si sahihi au muda wake umekwisha.' });
      }

      return json(res, 200, { status: 'success', verified: true, message: 'Nambari imethibitishwa!' });
    }

    if (url.pathname === '/api/auth/forgot-password/reset' && req.method === 'POST') {
      const raw = await readBody(req);
      const { email, code, newPassword } = JSON.parse(raw || '{}');
      const cleanEmail = (email || '').trim().toLowerCase();
      const entry = otpStore.get(cleanEmail);

      if (!entry || entry.code !== String(code || '').trim() || Date.now() > entry.expiresAt) {
        return json(res, 400, { status: 'error', message: 'Nambari ya uthibitisho (OTP) si sahihi au muda wake umekwisha.' });
      }

      if (!newPassword || newPassword.length < 8) {
        return json(res, 400, { status: 'error', message: 'Nenosiri jipya lazima liwe na herufi 8 au zaidi.' });
      }

      if (supabase) {
        try {
          const { error } = await supabase.auth.admin.updateUserById(entry.userId, { password: newPassword });
          if (error) {
            return json(res, 500, { status: 'error', message: error.message });
          }
        } catch (authErr) {
          console.warn('Supabase auth.admin error (fallback update):', authErr.message);
        }
      }

      otpStore.delete(cleanEmail);
      return json(res, 200, { status: 'success', message: 'Nenosiri limebadilishwa kikamilifu! Sasa unaweza kuingia kwenye akaunti yako.' });
    }

    // -------------------------------------------------------------
    // ADMIN API MANAGEMENT ENDPOINTS
    // -------------------------------------------------------------
    if (url.pathname === '/api/admin/apikeys' && req.method === 'GET') {
      if (!supabase) return json(res, 200, { status: 'success', data: [] });
      const { data, error } = await supabase
        .from('api_keys')
        .select('*, profiles(full_name, email, phone)')
        .order('created_at', { ascending: false });
      if (error) return json(res, 500, { status: 'error', message: error.message });
      return json(res, 200, { status: 'success', data: data || [] });
    }

    if (url.pathname === '/api/admin/apikeys/block' && req.method === 'POST') {
      const raw = await readBody(req);
      const { id, reason } = JSON.parse(raw || '{}');
      if (!id) return json(res, 400, { status: 'error', message: 'Key ID inahitajika.' });
      if (supabase) {
        await supabase
          .from('api_keys')
          .update({
            status: 'blocked',
            block_reason: reason || 'Imezuiwa na utawala.',
            blocked_at: new Date().toISOString()
          })
          .eq('id', id);
      }
      return json(res, 200, { status: 'success', message: 'API key imezuiwa kikamilifu.' });
    }

    if (url.pathname === '/api/admin/apikeys/unblock' && req.method === 'POST') {
      const raw = await readBody(req);
      const { id } = JSON.parse(raw || '{}');
      if (!id) return json(res, 400, { status: 'error', message: 'Key ID inahitajika.' });
      if (supabase) {
        await supabase
          .from('api_keys')
          .update({ status: 'active', block_reason: null, blocked_at: null })
          .eq('id', id);
      }
      return json(res, 200, { status: 'success', message: 'API key imerudishwa kuwa hewani.' });
    }

    // -------------------------------------------------------------
    // CLIENT PAYMENT DEVELOPER API (v1)
    // -------------------------------------------------------------
    if (url.pathname.startsWith('/api/v1/')) {
      const authResult = await authenticateClientKey(req);
      if (authResult.error) {
        const code = authResult.error === 'api_key_blocked' ? 403 : 401;
        return json(res, code, { status: 'error', code: authResult.error, message: authResult.message });
      }
      const { keyRow } = authResult;

      // GET /api/v1/account
      if (url.pathname === '/api/v1/account' && req.method === 'GET') {
        return json(res, 200, {
          status: 'success',
          data: {
            service_name: keyRow.name,
            prefix: keyRow.prefix,
            status: keyRow.status,
            user_id: keyRow.user_id,
            owner: keyRow.profiles?.full_name ?? 'Fabopay Merchant',
            currency: 'TZS'
          }
        });
      }

      // POST /api/v1/payment-links
      if (url.pathname === '/api/v1/payment-links' && req.method === 'POST') {
        const raw = await readBody(req);
        const input = JSON.parse(raw || '{}');
        const amount = Number(input.amount || 0);
        if (amount < 500) return json(res, 400, { status: 'error', message: 'Kiwango cha chini ni TZS 500.' });

        const bytes = new Uint8Array(6);
        crypto.getRandomValues(bytes);
        const code = `FP${Buffer.from(bytes).toString('hex').slice(0, 8).toUpperCase()}`;

        if (supabase) {
          await supabase.from('payment_links').insert({
            id: code,
            owner_id: keyRow.user_id,
            merchant_name: keyRow.name,
            title: input.description || 'Payment Link',
            description: input.description || '',
            amount,
            redirect: input.redirect_url || '',
            active: true
          });
        }

        return json(res, 200, {
          id: code,
          object: 'payment_link',
          amount,
          currency: 'TZS',
          description: input.description || '',
          status: 'unpaid',
          url: `${WEB_ORIGIN}/pay/${code}`,
          created_at: new Date().toISOString()
        });
      }

      // POST /api/v1/charges OR /api/v1/deposits (Mobile Money Push)
      if ((url.pathname === '/api/v1/charges' || url.pathname === '/api/v1/deposits') && req.method === 'POST') {
        if (!API_KEY || !WEBHOOK_SECRET) {
          return json(res, 503, { status: 'error', message: 'Abliner payment gateway haijawekwa kwenye server.' });
        }
        const raw = await readBody(req);
        const input = JSON.parse(raw || '{}');
        const amount = Number(input.amount || 0);
        const phone = (input.phone || input.customer?.phone || '').replace(/\D/g, '');
        const reference = input.reference || `FP-API-${Date.now().toString(36)}`;

        if (amount < 500) return json(res, 400, { status: 'error', message: 'Kiwango cha chini cha malipo ni TZS 500.' });
        if (!phone) return json(res, 400, { status: 'error', message: 'Namba ya simu ya mteja inahitajika.' });

        // Forward to Abliner deposits
        const depositPayload = JSON.stringify({
          amount,
          phone,
          reference,
          method: 'mobile',
          currency: 'TZS',
          callbackUrl: 'https://abliner.net/api/public/transaction-webhook/server'
        });
        const signed = signDeposit(depositPayload);
        const upstreamHeaders = {
          Authorization: `Bearer ${API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `fabopay-${crypto.randomUUID()}`,
          'x-abliner-timestamp': signed.timestamp,
          'x-abliner-signature': signed.signature
        };

        const upstreamRes = await fetch(`${BASE_URL}/api/v1/deposits`, {
          method: 'POST',
          headers: upstreamHeaders,
          body: depositPayload
        });
        const upstreamJson = await upstreamRes.json();

        // RECORD TRANSACTION IN SUPABASE SO CLIENT RECEIVES IT IN DASHBOARD!
        const txId = upstreamJson.data?.id || reference;
        if (supabase) {
          await supabase.from('transactions').insert({
            id: txId,
            user_id: keyRow.user_id,
            provider: 'abliner',
            provider_transaction_id: upstreamJson.data?.id || null,
            type: 'in',
            source: 'api',
            method: 'mobile',
            amount,
            currency: 'TZS',
            status: upstreamJson.data?.status === 'completed' ? 'completed' : 'pending',
            recipient: phone,
            reference,
            description: input.description || `API Charge (${keyRow.name})`,
            created_at: new Date().toISOString()
          });
        }

        return json(res, upstreamRes.status, upstreamJson);
      }
    }

    // -------------------------------------------------------------
    // ABLINER WEBHOOK & PROXY ROUTES
    // -------------------------------------------------------------
    if (url.pathname === '/api/abliner/webhooks/abliner') {
      const raw = await readBody(req);
      if (!verifyWebhook(req, raw)) return json(res, 401, { status: 'error', code: 'invalid_webhook_signature' });
      if (!supabaseAdmin) return json(res, 503, { status: 'error', code: 'supabase_not_configured' });
      let payload;
      try { payload = JSON.parse(raw || '{}'); } catch { return json(res, 400, { status: 'error', code: 'invalid_webhook_json' }); }
      const eventId = String(req.headers['x-webhook-id'] || payload.id || '');
      const eventType = String(payload.event || '');
      if (!eventId || !eventType) return json(res, 400, { status: 'error', code: 'webhook_identity_missing' });
      const { data, error } = await supabaseAdmin.rpc('record_abliner_webhook', { p_event_id: eventId, p_event_type: eventType, p_payload: payload, p_signature_verified: true });
      if (error) return json(res, 500, { status: 'error', code: 'webhook_persistence_failed', message: error.message });
      return json(res, 200, { received: true, reconciliation: data });
    }

    if (!url.pathname.startsWith('/api/abliner/')) return json(res, 404, { status: 'error', code: 'not_found' });
    const endpoint = url.pathname.slice('/api/abliner'.length);
    if (!safePath(endpoint)) return json(res, 404, { status: 'error', code: 'unsupported_endpoint' });
    const raw = req.method === 'POST' ? await readBody(req) : '';
    return await proxy(req, res, endpoint, raw, url.search);
  } catch (error) {
    return json(res, 500, { status: 'error', code: 'server_error', message: error instanceof Error ? error.message : 'Unexpected server error.' });
  }
});

server.listen(PORT, '0.0.0.0', () => console.log(`Fabopaye API & Proxy server listening on port ${PORT}`));
