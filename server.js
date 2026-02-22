// Platform B — server.js
// Byte-range proxy. Session token goes in X-Session-Token header (IDM cannot send custom headers).
// <video src> is a blob:// URL — IDM sees nothing to intercept.

const CONFIG = {
  ADMIN_USER_ID:          'admin',
  ADMIN_PASSWORD:         'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',
  PLATFORM_B_URL:         'https://platform-b-ten.vercel.app',   // ⚠️ no trailing slash
  PLATFORM_C_URL:         'https://platform-c-gules.vercel.app', // ⚠️ no trailing slash
  SUPABASE_URL:           'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY:   'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',
  TOKEN_SECRET:           'plat-b-tok-secret-changeme-f7g2h9k3',
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
  res.setHeader('Access-Control-Allow-Origin',  ALLOWED.includes(origin) ? origin : (origin || '*'));
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, X-Security-String, X-Session-Token, Authorization, Accept, Origin, Range');
  res.setHeader('Access-Control-Expose-Headers',
    'Content-Type, Content-Length, Content-Range, Accept-Ranges, X-Video-Size, X-Video-Duration');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});
app.use(express.json());

// ── SESSION TOKEN ─────────────────────────────────────────────────────────────
// Sent as X-Session-Token header — IDM cannot send custom headers, only copies URLs.
// Valid 2 hours, HMAC-signed, tied to videoId.

function generateSessionToken(videoId) {
  const sid    = crypto.randomBytes(8).toString('hex');
  const expiry = Date.now() + 2 * 60 * 60 * 1000;
  const body   = `s:${videoId}:${sid}:${expiry}`;
  const sig    = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
  return Buffer.from(`${body}:${sig}`).toString('base64url');
}

function validateSessionToken(token, videoId) {
  try {
    const raw  = Buffer.from(token, 'base64url').toString('utf8');
    const cut  = raw.lastIndexOf(':');
    const body = raw.slice(0, cut), sig = raw.slice(cut + 1);
    const parts = body.split(':');
    if (parts.length !== 4 || parts[0] !== 's') return false;
    if (parts[1] !== videoId) return false;
    if (Date.now() > parseInt(parts[3], 10)) return false;
    const exp = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
    if (sig.length !== exp.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(exp, 'hex'));
  } catch { return false; }
}

// ── SECURITY HELPERS ──────────────────────────────────────────────────────────
const UA_BLOCKLIST = [
  'idm/', 'internet download manager', 'fdm/', 'free download manager',
  'wget/', 'curl/', 'aria2/', 'uget/', 'getright', 'flashget', 'dap/',
  'download accelerator', 'go-http-client/', 'python-urllib', 'python-requests',
  'libwww-perl', 'java/', 'okhttp/', 'httpie/', 'axel/',
];
const isBlockedUA     = req => UA_BLOCKLIST.some(b => (req.headers['user-agent'] || '').toLowerCase().includes(b));
const isAllowedOrigin = req => {
  const ref = req.headers['referer'] || req.headers['origin'] || '';
  if (!ref) return true;
  return [CONFIG.PLATFORM_C_URL, 'http://localhost', 'http://127.0.0.1'].some(o => ref.startsWith(o));
};

// ── SUPABASE ──────────────────────────────────────────────────────────────────
let supabase;
try {
  supabase = createClient(
    process.env.SUPABASE_URL     || CONFIG.SUPABASE_URL,
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
    if (!supabase)              return res.status(500).json({ success: false, message: 'DB not ready' });

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

// Returns a session token — never the original URL
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

    const sessionToken = generateSessionToken(videoId);
    return res.json({
      success: true, type: 'video', platform: data.platform,
      streamEndpoint: `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}`,
      sessionToken,   // sent as X-Session-Token header, never in a URL
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Core streaming endpoint — accepts any Range header, proxies to source
// IDM-proof: requires X-Session-Token custom header (IDM cannot send custom headers)
// Blob URL on client: IDM cannot see the actual stream URL at all
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const token = req.headers['x-session-token'];

    if (!token || !validateSessionToken(token, videoId)) return res.status(403).send('Forbidden');
    if (isBlockedUA(req))      return res.status(403).send('Forbidden');
    if (!isAllowedOrigin(req)) return res.status(403).send('Forbidden');
    if (!supabase)             return res.status(500).send('DB error');

    const { data, error } = await supabase
      .from('videos').select('stream_url, is_google_drive').eq('id', videoId).single();
    if (error || !data) return res.status(404).send('Not found');

    const upHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': '*/*',
    };
    if (req.headers.range)     upHeaders['Range']   = req.headers.range;
    if (data.is_google_drive)  upHeaders['Referer'] = 'https://drive.google.com/';

    const upstream = await fetch(data.stream_url, { headers: upHeaders, redirect: 'follow' });

    // Relay relevant response headers
    ['content-type', 'content-length', 'content-range', 'accept-ranges'].forEach(h => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h.replace(/(^|-)(\w)/g, (_, a, b) => a + b.toUpperCase()), v);
    });
    res.setHeader('Accept-Ranges',       'bytes');
    res.setHeader('Cache-Control',       'private, no-store');
    res.setHeader('Content-Disposition', 'inline');
    res.removeHeader('X-Powered-By');

    const status = req.headers.range ? (upstream.status === 206 ? 206 : 200) : 200;
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
  res.json({ status: 'ok', database: supabase ? 'connected' : 'disconnected' }));

app.use((_, res) => res.status(404).json({ success: false, message: 'Not found' }));

if (process.env.VERCEL !== '1') app.listen(process.env.PORT || 3000);

export default app;
