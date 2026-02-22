// server.js - Platform B — True byte-range streaming proxy
// Architecture: browser <video> src points to /api/stream/:videoId?t=SIGNED_TOKEN
// Browser sends native Range requests → server forwards them to source → instant seeking
// Token is HMAC-signed, 2-hour expiry, verified server-side
// IDM blocked via: referer check + UA block + token expiry (can't use after session ends)

const CONFIG = {
  ADMIN_USER_ID:          'admin',
  ADMIN_PASSWORD:         'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',
  PLATFORM_B_URL:         'https://platform-b-ten.vercel.app',   // ⚠️ no trailing slash
  PLATFORM_C_URL:         'https://platform-c-gules.vercel.app', // ⚠️ no trailing slash
  SUPABASE_URL:           'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY:   'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',
  TOKEN_SECRET:           'plat-b-tok-secret-changeme-f7g2h9k3', // ⚠️ change this
};

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const allowed = [
    CONFIG.PLATFORM_C_URL, CONFIG.PLATFORM_C_URL + '/',
    'http://localhost:3000', 'http://localhost:5173',
    'http://localhost:5174', 'http://127.0.0.1:5173', 'http://127.0.0.1:3000',
  ];
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', allowed.includes(origin) ? origin : (origin || '*'));
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, Authorization, Accept, Origin, Range');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

app.use(express.json());

// ── STREAM TOKEN ──────────────────────────────────────────────────────────────
// Signed token embedded in the stream URL query string.
// Valid for 2 hours. Encodes videoId so it can't be reused for other videos.
// Format (base64url): "st:{videoId}:{expiry}:{hmac}"
//
// Why URL token instead of header? Because <video src="..."> is set directly —
// the browser sends Range requests automatically with no JS in the loop.
// Security comes from: short expiry + referer check + UA block.
// IDM can copy the URL but: (a) it expires in 2h, (b) referer block stops it,
// (c) UA block stops headless tools.

function generateStreamToken(videoId) {
  const expiry  = Date.now() + 2 * 60 * 60 * 1000;           // 2 hours
  const body    = `st:${videoId}:${expiry}`;
  const sig     = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
  return Buffer.from(`${body}:${sig}`).toString('base64url');
}

function validateStreamToken(token, videoId) {
  try {
    const decoded  = Buffer.from(token, 'base64url').toString('utf8');
    const lastColon = decoded.lastIndexOf(':');
    const body      = decoded.substring(0, lastColon);
    const sig       = decoded.substring(lastColon + 1);
    const parts     = body.split(':');
    if (parts.length !== 3 || parts[0] !== 'st') return false;
    if (parts[1] !== videoId) return false;
    if (Date.now() > parseInt(parts[2], 10)) return false;
    const expected = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(body).digest('hex');
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// ── SECURITY HELPERS ──────────────────────────────────────────────────────────
const BLOCKED_UA = [
  'idm/', 'internet download manager', 'fdm', 'free download manager',
  'wget', 'curl/', 'aria2', 'uget', 'getright', 'flashget', 'dap/',
  'download accelerator', 'go-http-client', 'python-requests', 'libwww',
  'java/', 'okhttp', 'httpie',
];
function isBlockedUA(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return BLOCKED_UA.some(b => ua.includes(b));
}

function isAllowedReferer(req) {
  const ref = req.headers['referer'] || req.headers['origin'] || '';
  if (!ref) return true; // allow missing referer (some browsers strip it)
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
    process.env.SUPABASE_URL     || CONFIG.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY || CONFIG.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );
} catch (_) {}

// ── URL CONVERTERS ────────────────────────────────────────────────────────────
function convertDropboxUrl(url) {
  try {
    let u = url;
    if (!u.includes('raw=1'))
      u = u.includes('dl=') ? u.replace(/dl=[01]/, 'raw=1') : u + (u.includes('?') ? '&' : '?') + 'raw=1';
    return { streamUrl: u, success: true };
  } catch (e) { return { success: false, message: e.message }; }
}
function convertGoogleDriveUrl(url) {
  try {
    const m = url.match(/\/file\/d\/([^/?]+)/) || [null, url.match(/[?&]id=([^&]+)/)?.[1]];
    if (m?.[1]) return { streamUrl: `https://drive.google.com/uc?export=download&id=${m[1]}&confirm=t`, isGoogleDrive: true, success: true };
    return { success: false, message: 'Invalid Google Drive URL' };
  } catch (e) { return { success: false, message: e.message }; }
}
function convertYouTubeUrl(url) {
  try {
    const u = new URL(url);
    const id = u.hostname.includes('youtu.be') ? u.pathname.slice(1) : u.searchParams.get('v');
    if (id) return { streamUrl: `https://www.youtube.com/embed/${id}`, isEmbed: true, success: true };
    return { success: false, message: 'Invalid YouTube URL' };
  } catch (e) { return { success: false, message: e.message }; }
}
function convertVimeoUrl(url) {
  try {
    const id = new URL(url).pathname.split('/').filter(Boolean)[0];
    if (id) return { streamUrl: `https://player.vimeo.com/video/${id}`, isEmbed: true, success: true };
    return { success: false, message: 'Invalid Vimeo URL' };
  } catch (e) { return { success: false, message: e.message }; }
}
function convertDailymotionUrl(url) {
  try {
    const id = new URL(url).pathname.split('/').filter(p => p && p !== 'video')[0];
    if (id) return { streamUrl: `https://www.dailymotion.com/embed/video/${id}`, isEmbed: true, success: true };
    return { success: false, message: 'Invalid Dailymotion URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { userId, password } = req.body || {};
  if (!userId || !password) return res.status(400).json({ success: false, message: 'Required' });
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

    const converters = {
      dropbox: convertDropboxUrl, gdrive: convertGoogleDriveUrl,
      youtube: convertYouTubeUrl, vimeo:  convertVimeoUrl, dailymotion: convertDailymotionUrl,
    };
    const convert = converters[platform.toLowerCase()];
    if (!convert) return res.status(400).json({ success: false, message: 'Unsupported platform' });
    const c = convert(videoUrl);
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

// /api/video/:videoId  — returns a signed stream URL, never the original
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const sec = req.headers['x-security-string'];
    if (!sec || sec.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase) return res.status(500).json({ success: false, message: 'DB not ready' });

    const { data, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Not found' });

    // Fire-and-forget access count
    supabase.from('videos')
      .update({ access_count: data.access_count + 1, last_accessed_at: new Date().toISOString() })
      .eq('id', videoId).then(() => {});

    if (data.is_embed) {
      return res.json({
        success: true, type: 'embed', platform: data.platform,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}`,
      });
    }

    // Generate a signed stream token valid for 2 hours
    const token = generateStreamToken(videoId);

    // The stream URL is set directly as <video src> — browser handles all Range requests
    // natively, giving instant seeking with zero JavaScript involvement
    const streamUrl = `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}?t=${encodeURIComponent(token)}`;

    return res.json({
      success: true, type: 'video', platform: data.platform,
      streamUrl,                  // browser sets this as video.src directly
      tokenExpiresIn: 7200,       // 2 hours in seconds (for UI info only)
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// /api/stream/:videoId  — THE core streaming endpoint
// Browser sends Range requests here. We validate token, forward range to source, pipe back.
// This is how YouTube/Netflix work: native HTTP range proxy.
// Seeking is instant because the browser's video engine handles byte offsets natively.
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const token       = req.query.t;

    // Security checks
    if (!token || !validateStreamToken(token, videoId))
      return res.status(403).send('Forbidden');
    if (isBlockedUA(req))       return res.status(403).send('Forbidden');
    if (!isAllowedReferer(req)) return res.status(403).send('Forbidden');
    if (!supabase)              return res.status(500).send('DB error');

    const { data, error } = await supabase
      .from('videos').select('stream_url, is_google_drive').eq('id', videoId).single();
    if (error || !data) return res.status(404).send('Not found');

    // Forward the browser's native Range header to the source
    const range = req.headers.range;
    const fh = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept':     '*/*',
    };
    if (range)                  fh['Range']   = range;
    if (data.is_google_drive)   fh['Referer'] = 'https://drive.google.com/';

    const upstream = await fetch(data.stream_url, { headers: fh, redirect: 'follow' });

    // Pass through all relevant headers from upstream
    const passHeaders = ['content-type', 'content-length', 'content-range', 'accept-ranges'];
    passHeaders.forEach(h => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h.split('-').map(p => p[0].toUpperCase() + p.slice(1)).join('-'), v);
    });

    // Force Accept-Ranges so browser knows it can seek
    res.setHeader('Accept-Ranges',       'bytes');
    res.setHeader('Cache-Control',       'no-store, private');
    res.setHeader('Content-Disposition', 'inline');
    res.removeHeader('X-Powered-By');

    // Use 206 Partial Content for range requests, 200 for full
    res.status(range && upstream.status === 206 ? 206 : upstream.status === 200 ? 200 : upstream.status);
    res.flushHeaders();

    if (res.socket) { res.socket.setNoDelay(true); res.socket.setTimeout(0); }
    upstream.body.pipe(res);

  } catch (e) {
    if (!res.headersSent) res.status(500).send('Stream error');
  }
});

// /api/embed/:videoId — YouTube/Vimeo/Dailymotion proxy
app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    if (!key || key.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
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

app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', database: supabase ? 'connected' : 'disconnected' }));

app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));

if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT);
}

export default app;
