// server.js - Platform B Backend with Supabase
// Chunked streaming — IDM cannot intercept or reassemble chunks

const CONFIG = {
  ADMIN_USER_ID: 'admin',
  ADMIN_PASSWORD: 'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',

  // ⚠️ CHANGE THIS to your actual Vercel deployment URL (no trailing slash)
  PLATFORM_B_URL: 'https://platform-b-ten.vercel.app',

  // ⚠️ CHANGE THIS to your actual Platform C URL (no trailing slash)
  PLATFORM_C_URL: 'https://platform-c-gules.vercel.app',

  SUPABASE_URL: 'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',

  // Secret used to sign all tokens — change this to any long random string
  TOKEN_SECRET: 'plat-b-tok-secret-changeme-f7g2h9k3',

  // Chunk size in bytes (8MB — large enough for smooth buffering, small enough IDM can't use partials)
  CHUNK_SIZE: 8 * 1024 * 1024
};

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// ============================================
// CORS — must be first
// ============================================
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
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, X-Stream-Token, X-Chunk-Token, Authorization, Accept, Origin, X-Requested-With, Range');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges, X-Next-Chunk-Token, X-Total-Size, X-Chunk-Index, X-Is-Last-Chunk');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

app.use(express.json());

// ============================================
// TOKEN HELPERS
// ============================================

// Stream token — grants access to start a chunked stream session (5 min expiry)
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
    // format: stream:videoId:expiry:sig
    if (parts.length !== 4 || parts[0] !== 'stream') return false;
    const [, vid, expiry, sig] = parts;
    if (vid !== videoId) return false;
    if (Date.now() > parseInt(expiry, 10)) return false;
    const expected = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET)
      .update(`stream:${vid}:${expiry}`).digest('hex');
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// Chunk token — grants access to ONE specific chunk only (30 second expiry)
// Each chunk response includes the token for the NEXT chunk
// This means IDM cannot pre-fetch or download all chunks in parallel
function generateChunkToken(videoId, chunkIndex) {
  const expiry = Date.now() + 30 * 1000; // 30 seconds — just enough to fetch one chunk
  const payload = `chunk:${videoId}:${chunkIndex}:${expiry}`;
  const sig = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

function validateChunkToken(token, videoId, chunkIndex) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parts = decoded.split(':');
    // format: chunk:videoId:chunkIndex:expiry:sig
    if (parts.length !== 5 || parts[0] !== 'chunk') return false;
    const [, vid, idx, expiry, sig] = parts;
    if (vid !== videoId) return false;
    if (parseInt(idx, 10) !== chunkIndex) return false;
    if (Date.now() > parseInt(expiry, 10)) return false;
    const expected = crypto.createHmac('sha256', CONFIG.TOKEN_SECRET)
      .update(`chunk:${vid}:${idx}:${expiry}`).digest('hex');
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// ============================================
// SUPABASE INIT
// ============================================
let supabase;
try {
  const supabaseUrl = process.env.SUPABASE_URL || CONFIG.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_KEY || CONFIG.SUPABASE_SERVICE_KEY;
  supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
} catch (_) {}

// ============================================
// HELPERS
// ============================================
function isAllowedUA(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const blocked = [
    'idm/', 'internet download manager', 'fdm', 'free download manager',
    'wget', 'curl/', 'aria2', 'uget', 'getright', 'flashget', 'dap/',
    'download accelerator', 'go-http-client', 'python-requests', 'libwww',
    'java/', 'okhttp', 'httpie'
  ];
  return !blocked.some(b => ua.includes(b));
}

function isAllowedReferer(req) {
  const referer = req.headers['referer'] || req.headers['origin'] || '';
  if (!referer) return true; // allow direct (e.g. server-side)
  const allowed = [
    CONFIG.PLATFORM_C_URL,
    'http://localhost:3000', 'http://localhost:5173',
    'http://localhost:5174', 'http://127.0.0.1'
  ];
  return allowed.some(o => referer.startsWith(o));
}

// ============================================
// URL CONVERTERS
// ============================================
function convertDropboxUrl(url) {
  try {
    let directUrl = url;
    if (!url.includes('raw=1')) {
      if (url.includes('dl=0'))      directUrl = url.replace('dl=0', 'raw=1');
      else if (url.includes('dl=1')) directUrl = url.replace('dl=1', 'raw=1');
      else                           directUrl = url + (url.includes('?') ? '&' : '?') + 'raw=1';
    }
    return { streamUrl: directUrl, useProxy: true, success: true };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertGoogleDriveUrl(url) {
  try {
    const matchFile = url.match(/\/file\/d\/([^/?]+)/);
    const matchOpen = url.match(/[?&]id=([^&]+)/);
    const fileId = matchFile ? matchFile[1] : matchOpen ? matchOpen[1] : null;
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
    const urlObj = new URL(url);
    const videoId = urlObj.hostname.includes('youtu.be')
      ? urlObj.pathname.slice(1)
      : urlObj.searchParams.get('v');
    if (videoId) {
      return { streamUrl: `https://www.youtube.com/embed/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    }
    return { success: false, message: 'Invalid YouTube URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertVimeoUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(Boolean)[0];
    if (videoId) {
      return { streamUrl: `https://player.vimeo.com/video/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    }
    return { success: false, message: 'Invalid Vimeo URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertDailymotionUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(p => p && p !== 'video')[0];
    if (videoId) {
      return { streamUrl: `https://www.dailymotion.com/embed/video/${videoId}`, videoId, useProxy: true, isEmbed: true, success: true };
    }
    return { success: false, message: 'Invalid Dailymotion URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

// ============================================
// ROUTES
// ============================================

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
      dropbox: convertDropboxUrl, gdrive: convertGoogleDriveUrl,
      youtube: convertYouTubeUrl, vimeo: convertVimeoUrl, dailymotion: convertDailymotionUrl
    };
    const converter = converters[platform.toLowerCase()];
    if (!converter) return res.status(400).json({ success: false, message: 'Unsupported platform' });

    const converted = converter(videoUrl);
    if (!converted.success) return res.status(400).json({ success: false, message: converted.message });

    const videoId = crypto.randomBytes(16).toString('hex');
    const { error } = await supabase.from('videos').insert({
      id: videoId, original_url: videoUrl, stream_url: converted.streamUrl,
      platform: platform.toLowerCase(), use_proxy: converted.useProxy || false,
      is_embed: converted.isEmbed || false, is_google_drive: converted.isGoogleDrive || false,
      created_by: userId, access_count: 0
    });

    if (error) return res.status(500).json({ success: false, message: error.message });

    res.json({
      success: true,
      videoUrl: `${CONFIG.PLATFORM_B_URL}/video/${videoId}`,
      videoId, platform: platform.toLowerCase()
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Get video metadata — returns a stream token, never the original URL
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const secKey = req.headers['x-security-string'];

    if (!secKey || secKey.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase)
      return res.status(500).json({ success: false, message: 'Database not initialized' });

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();

    if (error || !videoData)
      return res.status(404).json({ success: false, message: 'Video not found' });

    // Fire-and-forget access count update
    supabase.from('videos').update({
      access_count: videoData.access_count + 1,
      last_accessed_at: new Date().toISOString()
    }).eq('id', videoId).then(() => {});

    if (videoData.is_embed) {
      return res.json({
        success: true,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}`,
        platform: videoData.platform,
        type: 'embed'
      });
    }

    // For video: return a stream token + the chunk endpoint URL
    // The client must use /api/chunk/:videoId to fetch chunks
    const streamToken = generateStreamToken(videoId);

    // Also pre-generate the token for chunk 0 so the client can start immediately
    const firstChunkToken = generateChunkToken(videoId, 0);

    return res.json({
      success: true,
      chunkUrl: `${CONFIG.PLATFORM_B_URL}/api/chunk/${videoId}`,
      streamToken,       // used to get total size info
      firstChunkToken,   // used to fetch chunk 0
      platform: videoData.platform,
      type: 'video'
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Get video info (total size) — requires stream token
// Client calls this first to know how many chunks to expect
app.get('/api/info/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const token = req.headers['x-stream-token'] || req.query.token;

    if (!token || !validateStreamToken(token, videoId))
      return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!isAllowedUA(req)) return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!isAllowedReferer(req)) return res.status(403).json({ success: false, message: 'Forbidden' });
    if (!supabase) return res.status(500).json({ success: false, message: 'Database error' });

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !videoData) return res.status(404).json({ success: false, message: 'Not found' });

    // HEAD request to get total file size from the source
    const fetchHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    };
    if (videoData.is_google_drive) fetchHeaders['Referer'] = 'https://drive.google.com/';

    const headRes = await fetch(videoData.stream_url, { method: 'HEAD', headers: fetchHeaders, redirect: 'follow' });
    const totalSize = parseInt(headRes.headers.get('content-length') || '0', 10);
    const contentType = headRes.headers.get('content-type') || 'video/mp4';
    const totalChunks = totalSize > 0 ? Math.ceil(totalSize / CONFIG.CHUNK_SIZE) : null;

    res.json({
      success: true,
      totalSize,
      totalChunks,
      chunkSize: CONFIG.CHUNK_SIZE,
      contentType
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Serve a single chunk — the CORE anti-IDM endpoint
// Each chunk requires its own token valid for 30 seconds
// The response includes the token for the NEXT chunk in a response header
// IDM cannot pre-fetch chunks because it doesn't have the next token until it processes each response
app.get('/api/chunk/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const chunkIndex = parseInt(req.query.chunk || '0', 10);

    // Validate the per-chunk token
    const chunkToken = req.headers['x-chunk-token'] || req.query.chunkToken;
    if (!chunkToken || !validateChunkToken(chunkToken, videoId, chunkIndex))
      return res.status(403).send('Forbidden');

    if (!isAllowedUA(req)) return res.status(403).send('Forbidden');
    if (!isAllowedReferer(req)) return res.status(403).send('Forbidden');
    if (!supabase) return res.status(500).send('Database error');

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !videoData) return res.status(404).send('Not found');

    const byteStart = chunkIndex * CONFIG.CHUNK_SIZE;
    const byteEnd   = byteStart + CONFIG.CHUNK_SIZE - 1;

    const fetchHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Range': `bytes=${byteStart}-${byteEnd}`
    };
    if (videoData.is_google_drive) fetchHeaders['Referer'] = 'https://drive.google.com/';

    const response = await fetch(videoData.stream_url, { headers: fetchHeaders, redirect: 'follow' });

    if (!response.ok && response.status !== 206 && response.status !== 416) {
      return res.status(response.status).send('Source error');
    }

    // 416 = Range Not Satisfiable — means we've gone past end of file
    if (response.status === 416) {
      return res.status(204).send(); // No content — client knows stream is done
    }

    const contentRange  = response.headers.get('content-range');
    const contentLength = response.headers.get('content-length');
    const contentType   = response.headers.get('content-type') || 'video/mp4';

    // Determine if this is the last chunk
    let isLastChunk = false;
    if (contentRange) {
      const match = contentRange.match(/bytes (\d+)-(\d+)\/(\d+)/);
      if (match) {
        const totalSize = parseInt(match[3], 10);
        isLastChunk = byteEnd >= totalSize - 1;
      }
    }

    // Generate the token for the NEXT chunk and send it in a response header
    // Without this token the client (and IDM) cannot fetch the next chunk
    const nextChunkToken = isLastChunk ? '' : generateChunkToken(videoId, chunkIndex + 1);

    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('X-Next-Chunk-Token', nextChunkToken);
    res.setHeader('X-Chunk-Index', String(chunkIndex));
    res.setHeader('X-Is-Last-Chunk', String(isLastChunk));
    if (contentLength) res.setHeader('Content-Length', contentLength);
    if (contentRange)  res.setHeader('Content-Range', contentRange);
    res.removeHeader('X-Powered-By');

    res.status(206);
    res.flushHeaders();

    if (res.socket) {
      res.socket.setNoDelay(true);
      res.socket.setTimeout(0);
    }

    response.body.pipe(res);

  } catch (e) {
    if (!res.headersSent) res.status(500).send('Chunk error');
  }
});

// Embed proxy — YouTube, Vimeo, Dailymotion
app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    if (!key || key.trim() !== CONFIG.MASTER_SECURITY_STRING.trim())
      return res.status(403).send('Forbidden');
    if (!supabase) return res.status(500).send('Database error');

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();
    if (error || !videoData) return res.status(404).send('Not found');

    const response = await fetch(videoData.stream_url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    if (!response.ok) return res.status(response.status).send('Embed error');

    res.setHeader('Content-Type', 'text/html');
    res.send(await response.text());
  } catch (e) { res.status(500).send('Error'); }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', database: supabase ? 'connected' : 'not connected', securityConfigured: true });
});

// 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Not found' });
});

// Only start local server when NOT on Vercel
if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT);
}

export default app;
