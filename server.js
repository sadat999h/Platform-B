// server.js - Platform B Backend
// Anti-piracy: chunked streaming with per-chunk HMAC tokens.
// Students stream smoothly via MSE (blob URL). IDM/downloaders cannot
// reassemble because each chunk token expires in 30s and the next token
// is only revealed inside the server response — never in the URL.

const CONFIG = {
  ADMIN_USER_ID: 'admin',
  ADMIN_PASSWORD: 'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',

  // ⚠️ Your actual Vercel deployment URLs (no trailing slash)
  PLATFORM_B_URL: 'https://platform-b-ten.vercel.app',
  PLATFORM_C_URL: 'https://platform-c-gules.vercel.app',

  SUPABASE_URL: 'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',

  TOKEN_SECRET: 'plat-b-tok-secret-changeme-f7g2h9k3',

  // 8 MB chunks — smooth for students, too large for IDM partial-download tricks
  CHUNK_SIZE: 8 * 1024 * 1024
};

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const allowedOrigins = [
    CONFIG.PLATFORM_C_URL,
    CONFIG.PLATFORM_C_URL + '/',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:3000'
  ];

  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    // same-origin or server-to-server — allow
    res.setHeader('Access-Control-Allow-Origin', CONFIG.PLATFORM_C_URL);
  } else {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, X-Security-String, X-Stream-Token, X-Chunk-Token, Authorization, Accept, Origin, X-Requested-With');
  res.setHeader('Access-Control-Expose-Headers',
    'X-Next-Chunk-Token, X-Is-Last-Chunk, X-Chunk-Index, X-Total-Size, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

app.use(express.json());

// ─── TOKEN HELPERS ───────────────────────────────────────────────────────────

// Stream token: valid 5 min, used to fetch /api/info
function generateStreamToken(videoId) {
  const expiry = Date.now() + 5 * 60 * 1000;
  const payload = `stream:${videoId}:${expiry}`;
  const sig = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

function validateStreamToken(token, videoId) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length !== 4 || parts[0] !== 'stream') return false;
    const [, vid, expiry, sig] = parts;
    if (vid !== videoId) return false;
    if (Date.now() > parseInt(expiry, 10)) return false;
    const expected = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET)
      .update(`stream:${vid}:${expiry}`).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// Chunk token: valid 30s, grants access to exactly ONE specific chunk.
// The token for chunk N+1 is only revealed in the response headers of chunk N.
// This makes parallel downloading impossible for IDM.
function generateChunkToken(videoId, chunkIndex) {
  const expiry = Date.now() + 30 * 1000;
  const payload = `chunk:${videoId}:${chunkIndex}:${expiry}`;
  const sig = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

function validateChunkToken(token, videoId, chunkIndex) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length !== 5 || parts[0] !== 'chunk') return false;
    const [, vid, idx, expiry, sig] = parts;
    if (vid !== videoId) return false;
    if (parseInt(idx, 10) !== chunkIndex) return false;
    if (Date.now() > parseInt(expiry, 10)) return false;
    const expected = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET)
      .update(`chunk:${vid}:${idx}:${expiry}`).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// ─── SUPABASE ─────────────────────────────────────────────────────────────────
let supabase;
try {
  supabase = createClient(
    process.env.SUPABASE_URL || CONFIG.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY || CONFIG.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );
} catch (_) {}

// ─── ANTI-PIRACY CHECKS ──────────────────────────────────────────────────────

// Block known download managers by User-Agent.
// IDM often spoofs as IE (Trident) — real modern browsers never send Trident/.
function isBlockedUA(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();

  // Empty UA is a red flag
  if (ua.length < 10) return true;

  // Known download tool signatures
  const blockedSignatures = [
    'idm/', 'internet download manager',
    'fdm', 'free download manager',
    'wget/', 'curl/', 'aria2', 'uget',
    'getright', 'flashget', 'dap/',
    'download accelerator', 'go-http-client',
    'python-requests', 'python-urllib',
    'libwww-perl', 'java/', 'okhttp',
    'httpie', 'axel/', 'xdm/'
  ];
  if (blockedSignatures.some(s => ua.includes(s))) return true;

  // IDM's classic IE/Trident spoof — no real browser sends Trident/ anymore
  if (ua.includes('trident/') && !ua.includes('windows phone')) return true;

  return false;
}

// Block requests that don't come from Platform C.
// IDM intercepts downloads and strips the Origin/Referer header.
// Real browser fetch() calls from Platform C always include Origin.
function isAllowedOrigin(req) {
  const origin  = req.headers['origin']  || '';
  const referer = req.headers['referer'] || '';
  const source  = origin || referer;

  // No origin at all — block unless it's from the same host (Platform B's own pages)
  if (!source) {
    const host = (req.headers['host'] || '').toLowerCase();
    const ownHost = CONFIG.PLATFORM_B_URL.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
    return host === ownHost || host.startsWith('localhost') || host.startsWith('127.');
  }

  const allowed = [
    CONFIG.PLATFORM_C_URL,
    CONFIG.PLATFORM_B_URL,
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://127.0.0.1'
  ];
  return allowed.some(o => source.startsWith(o));
}

// Rate limiter: max 30 chunk requests per IP per 10 seconds.
// Prevents brute-force token guessing and mass parallel downloads.
const _ipMap = new Map();
function isRateLimited(req) {
  const ip  = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
              || (req.socket && req.socket.remoteAddress) || 'unknown';
  const now = Date.now();
  const win = 10_000; // 10s window
  const max = 30;

  const rec = _ipMap.get(ip) || { n: 0, t: now };
  if (now - rec.t > win) { rec.n = 1; rec.t = now; }
  else rec.n++;
  _ipMap.set(ip, rec);

  // Cleanup stale entries occasionally
  if (_ipMap.size > 1000) {
    for (const [k, v] of _ipMap) {
      if (now - v.t > win * 3) _ipMap.delete(k);
    }
  }
  return rec.n > max;
}

// ─── URL CONVERTERS ───────────────────────────────────────────────────────────
function convertDropboxUrl(url) {
  try {
    let u = url;
    if (!u.includes('raw=1')) {
      u = u.includes('dl=0') ? u.replace('dl=0', 'raw=1')
        : u.includes('dl=1') ? u.replace('dl=1', 'raw=1')
        : u + (u.includes('?') ? '&' : '?') + 'raw=1';
    }
    return { streamUrl: u, useProxy: true, success: true };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertGoogleDriveUrl(url) {
  try {
    const m1 = url.match(/\/file\/d\/([^/?]+)/);
    const m2 = url.match(/[?&]id=([^&]+)/);
    const fileId = m1?.[1] ?? m2?.[1] ?? null;
    if (fileId) {
      return {
        streamUrl: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
        fileId, useProxy: true, isGoogleDrive: true, success: true
      };
    }
    return { success: false, message: 'Invalid Google Drive URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertYouTubeUrl(url) {
  try {
    const u = new URL(url);
    const videoId = u.hostname.includes('youtu.be') ? u.pathname.slice(1) : u.searchParams.get('v');
    if (videoId) return { streamUrl: `https://www.youtube.com/embed/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    return { success: false, message: 'Invalid YouTube URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertVimeoUrl(url) {
  try {
    const u = new URL(url);
    const videoId = u.pathname.split('/').filter(Boolean)[0];
    if (videoId) return { streamUrl: `https://player.vimeo.com/video/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    return { success: false, message: 'Invalid Vimeo URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertDailymotionUrl(url) {
  try {
    const u = new URL(url);
    const videoId = u.pathname.split('/').filter(p => p && p !== 'video')[0];
    if (videoId) return { streamUrl: `https://www.dailymotion.com/embed/video/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    return { success: false, message: 'Invalid Dailymotion URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { userId, password } = req.body;
    if (!userId || !password)
      return res.status(400).json({ success: false, message: 'User ID and password required' });
    if (userId === CONFIG.ADMIN_USER_ID && password === CONFIG.ADMIN_PASSWORD)
      return res.json({ success: true, message: 'Login successful' });
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Submit video
app.post('/api/submit-video', async (req, res) => {
  try {
    const { userId, password, videoUrl, platform } = req.body;
    if (userId !== CONFIG.ADMIN_USER_ID || password !== CONFIG.ADMIN_PASSWORD)
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!videoUrl || !platform)
      return res.status(400).json({ success: false, message: 'Video URL and platform required' });
    if (!supabase)
      return res.status(500).json({ success: false, message: 'Database not initialized' });

    const converters = {
      dropbox: convertDropboxUrl,
      gdrive: convertGoogleDriveUrl,
      youtube: convertYouTubeUrl,
      vimeo: convertVimeoUrl,
      dailymotion: convertDailymotionUrl
    };
    const converter = converters[platform.toLowerCase()];
    if (!converter) return res.status(400).json({ success: false, message: 'Unsupported platform' });

    const converted = converter(videoUrl);
    if (!converted.success) return res.status(400).json({ success: false, message: converted.message });

    const videoId = crypto.randomBytes(16).toString('hex');
    const { error } = await supabase.from('videos').insert({
      id: videoId,
      original_url: videoUrl,
      stream_url: converted.streamUrl,
      platform: platform.toLowerCase(),
      use_proxy: converted.useProxy || false,
      is_embed: converted.isEmbed || false,
      is_google_drive: converted.isGoogleDrive || false,
      created_by: userId,
      access_count: 0
    });

    if (error) return res.status(500).json({ success: false, message: error.message });

    res.json({
      success: true,
      videoUrl: `${CONFIG.PLATFORM_B_URL}/video/${videoId}`,
      videoId,
      platform: platform.toLowerCase()
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Get video metadata — called by Platform C player.
// Returns stream + first chunk tokens. Never returns the real source URL.
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const secKey = req.headers['x-security-string'];

    if (!secKey || secKey.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase)
      return res.status(500).json({ success: false, message: 'Database not initialized' });

    const { data: video, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();

    if (error || !video)
      return res.status(404).json({ success: false, message: 'Video not found' });

    // Update access count (fire and forget)
    supabase.from('videos').update({
      access_count: (video.access_count || 0) + 1,
      last_accessed_at: new Date().toISOString()
    }).eq('id', videoId).then(() => {});

    if (video.is_embed) {
      return res.json({
        success: true,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}`,
        platform: video.platform,
        type: 'embed'
      });
    }

    const streamToken     = generateStreamToken(videoId);
    const firstChunkToken = generateChunkToken(videoId, 0);

    return res.json({
      success: true,
      chunkUrl: `${CONFIG.PLATFORM_B_URL}/api/chunk/${videoId}`,
      streamToken,
      firstChunkToken,
      platform: video.platform,
      type: 'video'
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Get video info (size + chunk count) — requires stream token
app.get('/api/info/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const token = req.headers['x-stream-token'] || req.query.token;

    if (!token || !validateStreamToken(token, videoId))
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (isBlockedUA(req))
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!isAllowedOrigin(req))
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase)
      return res.status(500).json({ success: false, message: 'Database error' });

    const { data: video, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !video) return res.status(404).json({ success: false, message: 'Not found' });

    const fetchHeaders = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' };
    if (video.is_google_drive) fetchHeaders['Referer'] = 'https://drive.google.com/';

    const headRes = await fetch(video.stream_url, { method: 'HEAD', headers: fetchHeaders, redirect: 'follow' });
    const totalSize  = parseInt(headRes.headers.get('content-length') || '0', 10);
    const contentType = headRes.headers.get('content-type') || 'video/mp4';
    const totalChunks = totalSize > 0 ? Math.ceil(totalSize / CONFIG.CHUNK_SIZE) : null;

    res.json({ success: true, totalSize, totalChunks, chunkSize: CONFIG.CHUNK_SIZE, contentType });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Serve one video chunk — the core anti-piracy endpoint.
//
// HOW IT STOPS IDM:
// 1. Each chunk needs a HMAC token that expires in 30s (token in X-Chunk-Token HEADER, not URL)
// 2. The token for chunk N+1 is only revealed inside the response of chunk N
//    → IDM cannot pre-fetch chunks in parallel — it literally cannot get chunk 2's token
//      until chunk 1 finishes downloading
// 3. Origin check — IDM strips Origin/Referer headers → gets 403
// 4. UA check — IDM's default and spoofed UAs are blocked
// 5. Rate limiting — prevents brute-force parallel attempts
// 6. No Accept-Ranges header in response → IDM doesn't know it can resume/download the file
app.get('/api/chunk/:videoId', async (req, res) => {
  try {
    const { videoId }   = req.params;
    const chunkIndex    = parseInt(req.query.chunk || '0', 10);

    // Token MUST come from the header — never the URL query string.
    // IDM reads URLs; it cannot read JS-only response headers from the previous chunk.
    const chunkToken = req.headers['x-chunk-token'];
    if (!chunkToken || !validateChunkToken(chunkToken, videoId, chunkIndex))
      return res.status(403).send('Forbidden');

    if (isBlockedUA(req))      return res.status(403).send('Forbidden');
    if (!isAllowedOrigin(req)) return res.status(403).send('Forbidden');
    if (isRateLimited(req))    return res.status(429).send('Too many requests');
    if (!supabase)             return res.status(500).send('Database error');

    const { data: video, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !video) return res.status(404).send('Not found');

    const byteStart = chunkIndex * CONFIG.CHUNK_SIZE;
    const byteEnd   = byteStart + CONFIG.CHUNK_SIZE - 1;

    const fetchHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Range': `bytes=${byteStart}-${byteEnd}`
    };
    if (video.is_google_drive) fetchHeaders['Referer'] = 'https://drive.google.com/';

    const upstream = await fetch(video.stream_url, { headers: fetchHeaders, redirect: 'follow' });

    // 416 = past end of file → signal done
    if (upstream.status === 416) return res.status(204).send();

    if (!upstream.ok && upstream.status !== 206)
      return res.status(upstream.status).send('Source error');

    const contentRange  = upstream.headers.get('content-range')  || '';
    const contentLength = upstream.headers.get('content-length') || '';
    const contentType   = upstream.headers.get('content-type')   || 'video/mp4';

    // Work out if this is the final chunk
    let isLastChunk = false;
    if (contentRange) {
      const m = contentRange.match(/bytes \d+-(\d+)\/(\d+)/);
      if (m) isLastChunk = parseInt(m[1], 10) >= parseInt(m[2], 10) - 1;
    }

    // Generate the NEXT chunk's token — it goes in the response HEADER.
    // The browser JS (MSE player) reads it and uses it for the next fetch().
    // IDM never reads response headers from inside an MSE stream — it only sees blob URLs.
    const nextChunkToken = isLastChunk ? '' : generateChunkToken(videoId, chunkIndex + 1);

    // ── Response headers ──────────────────────────────────────────────────────
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Content-Disposition', 'inline');

    // Anti-piracy: do NOT expose Accept-Ranges — this is the signal IDM uses
    // to detect a resumable/downloadable file. Without it, IDM sees a plain response.
    res.removeHeader('Accept-Ranges');

    // Pass next-chunk token only in a header (not the URL)
    res.setHeader('X-Next-Chunk-Token', nextChunkToken);
    res.setHeader('X-Is-Last-Chunk', String(isLastChunk));
    res.setHeader('X-Chunk-Index', String(chunkIndex));

    // Send Content-Length so MSE knows how many bytes to expect per chunk
    if (contentLength) res.setHeader('Content-Length', contentLength);

    // Remove server fingerprint
    res.removeHeader('X-Powered-By');

    res.status(206);
    res.flushHeaders();

    if (res.socket) {
      res.socket.setNoDelay(true);
      res.socket.setTimeout(0);
    }

    upstream.body.pipe(res);

  } catch (e) {
    if (!res.headersSent) res.status(500).send('Chunk error');
  }
});

// Embed proxy — YouTube / Vimeo / Dailymotion
app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    if (!key || key.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).send('Forbidden');
    if (!supabase) return res.status(500).send('Database error');

    const { data: video, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !video) return res.status(404).send('Not found');

    const upstream = await fetch(video.stream_url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    if (!upstream.ok) return res.status(upstream.status).send('Embed error');

    res.setHeader('Content-Type', 'text/html');
    res.send(await upstream.text());
  } catch (e) { res.status(500).send('Error'); }
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', database: supabase ? 'connected' : 'error' });
});

// 404
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Not found' });
});

// Local dev only (not on Vercel)
if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Platform B running on port ${PORT}`));
}

export default app;
