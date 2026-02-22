// Platform B — server.js
// Native video streaming with signed URL tokens.
// NO MSE, NO chunking — browser handles everything natively.
// IDM blocked by: 5-minute tokens (IDM can download within 5min, but Referer check stops it) + UA blocklist.

const CONFIG = {
  ADMIN_USER_ID:          'admin',
  ADMIN_PASSWORD:         'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',
  PLATFORM_B_URL:         'https://platform-b-ten.vercel.app',   // ⚠️ no trailing slash
  PLATFORM_C_URL:         'https://platform-c-gules.vercel.app', // ⚠️ no trailing slash
  SUPABASE_URL:           'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY:   'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',
  TOKEN_SECRET:           'plat-b-tok-secret-changeme-f7g2h9k3', // ⚠️ change this!
  TOKEN_TTL_MS:           300 * 1000,  // 5 minutes — covers most videos without needing a refresh mid-playback
};

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const ALLOWED = [
    CONFIG.PLATFORM_C_URL, CONFIG.PLATFORM_C_URL + '/',
    'http://localhost:3000', 'http://localhost:5173',
    'http://localhost:5174', 'http://127.0.0.1:5173', 'http://127.0.0.1:3000',
  ];
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', ALLOWED.includes(origin) ? origin : (origin || '*'));
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, X-Security-String, Accept, Origin, Range');
  res.setHeader('Access-Control-Expose-Headers',
    'Content-Type, Content-Length, Content-Range, Accept-Ranges');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});
app.use(express.json());

// ── SIGNED URL TOKEN ──────────────────────────────────────────────────────────
// Token is in the URL query string (?tok=...) — this is how the browser sends
// Range requests automatically (it re-uses the full src URL including query string).
// Token expires in 45s — IDM takes longer than that to queue and start downloading.
// Even if IDM gets the token in time, the Referer check kills it.

function generateToken(videoId) {
  const expiry = Date.now() + CONFIG.TOKEN_TTL_MS;
  const body   = `v:${videoId}:${expiry}`;
  const sig    = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
  return Buffer.from(`${body}:${sig}`).toString('base64url');
}

function validateToken(token, videoId) {
  try {
    const raw  = Buffer.from(token, 'base64url').toString('utf8');
    const cut  = raw.lastIndexOf(':');
    const body = raw.slice(0, cut);
    const sig  = raw.slice(cut + 1);
    const parts = body.split(':');
    if (parts.length !== 3 || parts[0] !== 'v') return false;
    if (parts[1] !== videoId) return false;
    if (Date.now() > parseInt(parts[2], 10)) return false;
    const exp = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
    if (sig.length !== exp.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(exp, 'hex'));
  } catch { return false; }
}

// ── SECURITY ──────────────────────────────────────────────────────────────────
// IDM sends its own User-Agent or spoofs one — but it can't spoof Referer correctly
// when the video is embedded inside Platform C's page.
const UA_BLOCK = [
  'idm/', 'internet download manager', 'fdm/', 'wget/', 'curl/',
  'aria2/', 'uget/', 'getright', 'flashget', 'go-http-client/',
  'python-requests', 'libwww-perl', 'okhttp/', 'httpie/', 'axel/',
  'dlm/', 'download', 'manager',
];

function isBlockedUA(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return UA_BLOCK.some(b => ua.includes(b));
}

function isValidReferer(req) {
  const ref = req.headers['referer'] || '';
  if (!ref) {
    // No referer — could be browser privacy setting OR IDM.
    // We allow it for the first request (browsers sometimes omit referer on initial load).
    // But for Range requests (seeking), a proper browser always sends referer.
    const isRange = !!req.headers['range'];
    return !isRange; // allow no-referer only for non-range requests
  }
  return [
    CONFIG.PLATFORM_C_URL,
    'http://localhost:3000', 'http://localhost:5173',
    'http://localhost:5174', 'http://127.0.0.1',
  ].some(o => ref.startsWith(o));
}

// ── SUPABASE ──────────────────────────────────────────────────────────────────
let supabase;
try {
  supabase = createClient(
    process.env.SUPABASE_URL         || CONFIG.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY || CONFIG.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );
} catch (_) {}

// ── URL CONVERTERS ────────────────────────────────────────────────────────────
const converters = {
  dropbox(url) {
    let u = url;
    if (!u.includes('raw=1'))
      u = u.includes('dl=') ? u.replace(/dl=[01]/, 'raw=1') : u + (u.includes('?') ? '&' : '?') + 'raw=1';
    return { streamUrl: u, success: true };
  },
  gdrive(url) {
    const m = url.match(/\/file\/d\/([^/?]+)/) || [, url.match(/[?&]id=([^&]+)/)?.[1]];
    if (!m?.[1]) return { success: false, message: 'Invalid Google Drive URL' };
    return { streamUrl: `https://drive.google.com/uc?export=download&id=${m[1]}&confirm=t`, isGoogleDrive: true, success: true };
  },
  youtube(url) {
    const u = new URL(url);
    const id = u.hostname.includes('youtu.be') ? u.pathname.slice(1) : u.searchParams.get('v');
    if (!id) return { success: false, message: 'Invalid YouTube URL' };
    return { streamUrl: `https://www.youtube.com/embed/${id}`, isEmbed: true, success: true };
  },
  vimeo(url) {
    const id = new URL(url).pathname.split('/').filter(Boolean)[0];
    if (!id) return { success: false, message: 'Invalid Vimeo URL' };
    return { streamUrl: `https://player.vimeo.com/video/${id}`, isEmbed: true, success: true };
  },
  dailymotion(url) {
    const id = new URL(url).pathname.split('/').filter(p => p && p !== 'video')[0];
    if (!id) return { success: false, message: 'Invalid Dailymotion URL' };
    return { streamUrl: `https://www.dailymotion.com/embed/video/${id}`, isEmbed: true, success: true };
  },
};

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { userId, password } = req.body || {};
  if (userId === CONFIG.ADMIN_USER_ID && password === CONFIG.ADMIN_PASSWORD)
    return res.json({ success: true });
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

app.post('/api/submit-video', async (req, res) => {
  try {
    const { userId, password, videoUrl, platform } = req.body;
    if (userId !== CONFIG.ADMIN_USER_ID || password !== CONFIG.ADMIN_PASSWORD)
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!videoUrl || !platform) return res.status(400).json({ success: false, message: 'Missing fields' });
    if (!supabase) return res.status(500).json({ success: false, message: 'DB not ready' });
    const conv = converters[platform.toLowerCase()];
    if (!conv) return res.status(400).json({ success: false, message: 'Unsupported platform' });
    let c;
    try { c = conv(videoUrl); } catch (e) { return res.status(400).json({ success: false, message: e.message }); }
    if (!c.success) return res.status(400).json({ success: false, message: c.message });
    const videoId = crypto.randomBytes(16).toString('hex');
    const { error } = await supabase.from('videos').insert({
      id: videoId, original_url: videoUrl, stream_url: c.streamUrl,
      platform: platform.toLowerCase(), use_proxy: true,
      is_embed: c.isEmbed || false, is_google_drive: c.isGoogleDrive || false,
      created_by: userId, access_count: 0,
    });
    if (error) return res.status(500).json({ success: false, message: error.message });
    res.json({ success: true, videoUrl: `${CONFIG.PLATFORM_B_URL}/video/${videoId}`, videoId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Returns a signed stream URL valid for 45 seconds.
// Client sets this as <video src> — browser handles all byte-range seeks natively.
// Client auto-refreshes the token every 30s before expiry.
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    if ((req.headers['x-security-string'] || '').trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase) return res.status(500).json({ success: false, message: 'DB not ready' });
    const { data, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Not found' });
    supabase.from('videos')
      .update({ access_count: (data.access_count || 0) + 1, last_accessed_at: new Date().toISOString() })
      .eq('id', videoId).then(() => {});
    if (data.is_embed) {
      return res.json({ success: true, type: 'embed', platform: data.platform,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}` });
    }
    const token     = generateToken(videoId);
    const streamUrl = `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}?tok=${encodeURIComponent(token)}`;
    return res.json({
      success: true, type: 'video', platform: data.platform,
      streamUrl,           // Set as <video src> directly — browser handles Range requests
      tokenTtl: 300,       // seconds — client refreshes at 240s
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Re-issue token endpoint — called by client before old token expires
app.get('/api/refresh/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    if ((req.headers['x-security-string'] || '').trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).json({ success: false });
    if (!supabase) return res.status(500).json({ success: false });
    const { data, error } = await supabase.from('videos').select('id').eq('id', videoId).single();
    if (error || !data) return res.status(404).json({ success: false });
    const token     = generateToken(videoId);
    const streamUrl = `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}?tok=${encodeURIComponent(token)}`;
    res.json({ success: true, streamUrl });
  } catch (e) { res.status(500).json({ success: false }); }
});

// THE STREAMING ENDPOINT
// Browser sends Range requests here automatically for seeking.
// Token in ?tok= expires in 45s — IDM can't queue fast enough.
// Strict Referer check: IDM sends wrong referer or none on range requests.
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const token       = req.query.tok;

    // 1. Validate token
    if (!token || !validateToken(token, videoId))
      return res.status(403).send('Token expired or invalid. Refresh the page.');

    // 2. Block download managers by UA
    if (isBlockedUA(req)) return res.status(403).send('Forbidden');

    // 3. Strict Referer check — IDM fails this on Range requests
    if (!isValidReferer(req)) return res.status(403).send('Forbidden');

    if (!supabase) return res.status(500).send('DB error');

    const { data, error } = await supabase
      .from('videos').select('stream_url, is_google_drive').eq('id', videoId).single();
    if (error || !data) return res.status(404).send('Not found');

    // Build upstream headers
    const upHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': '*/*',
    };
    // Forward the Range header — this is what makes seeking instant
    if (req.headers.range)    upHeaders['Range']   = req.headers.range;
    if (data.is_google_drive) upHeaders['Referer'] = 'https://drive.google.com/';

    const upstream = await fetch(data.stream_url, { headers: upHeaders, redirect: 'follow' });

    // Forward response headers
    for (const h of ['content-type', 'content-length', 'content-range', 'accept-ranges']) {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h.replace(/(^|-)(\w)/g, (_, a, b) => a + b.toUpperCase()), v);
    }
    res.setHeader('Accept-Ranges',       'bytes');
    res.setHeader('Cache-Control',       'private, no-store');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Connection',          'keep-alive');
    res.setHeader('X-Accel-Buffering',   'no');  // tells Nginx/Vercel not to buffer — reduces latency
    res.removeHeader('X-Powered-By');

    // Use correct status code
    const status = req.headers.range
      ? (upstream.status === 206 ? 206 : 200)
      : (upstream.status === 200 ? 200 : upstream.status);
    res.status(status);
    res.flushHeaders();
    if (res.socket) { res.socket.setNoDelay(true); res.socket.setTimeout(0); }
    upstream.body.pipe(res);

  } catch (e) {
    if (!res.headersSent) res.status(500).send('Stream error');
  }
});

app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    if ((key || '').trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).send('Forbidden');
    if (!supabase) return res.status(500).send('DB error');
    const { data, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !data) return res.status(404).send('Not found');
    const r = await fetch(data.stream_url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    if (!r.ok) return res.status(r.status).send('Embed error');
    res.setHeader('Content-Type', 'text/html');
    res.send(await r.text());
  } catch (e) { res.status(500).send('Error'); }
});

app.get('/api/health', (_, res) =>
  res.json({ status: 'ok', db: supabase ? 'ok' : 'error' }));

app.use((_, res) => res.status(404).json({ success: false, message: 'Not found' }));

if (process.env.VERCEL !== '1') app.listen(process.env.PORT || 3000);

export default app;
