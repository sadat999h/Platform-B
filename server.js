// server.js - Platform B Backend with Supabase

const CONFIG = {
  ADMIN_USER_ID: 'admin',
  ADMIN_PASSWORD: 'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',

  // ⚠️ CHANGE THIS to your actual Vercel deployment URL
  PLATFORM_B_URL: 'https://platform-b-ten.vercel.app',

  PLATFORM_C_URL: 'https://platform-c-gules.vercel.app',
  SUPABASE_URL: 'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4',

  // Secret used to sign short-lived stream tokens — change this to any random string you like
  TOKEN_SECRET: 'plat-b-tok-secret-changeme-f7g2h9k3'
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
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    // Unknown origin — still allow so the video loads, but log nothing sensitive
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, X-Stream-Token, Authorization, Accept, Origin, X-Requested-With, Range');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges, X-Content-Duration');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

app.use(express.json());

// ============================================
// SHORT-LIVED STREAM TOKEN HELPERS
// Tokens are HMAC-SHA256 signed, tied to a videoId, expire in 5 minutes
// ============================================
function generateStreamToken(videoId) {
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes
  const payload = `${videoId}:${expiry}`;
  const sig = crypto
    .createHmac('sha256', CONFIG.TOKEN_SECRET)
    .update(payload)
    .digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

function validateStreamToken(token, videoId) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    // Format: videoId:expiry:sig  — videoId may contain hex chars only (32 hex chars)
    const sigIndex = decoded.lastIndexOf(':');
    const expiryIndex = decoded.lastIndexOf(':', sigIndex - 1);

    const vid    = decoded.substring(0, expiryIndex);
    const expiry = decoded.substring(expiryIndex + 1, sigIndex);
    const sig    = decoded.substring(sigIndex + 1);

    if (vid !== videoId) return false;
    if (Date.now() > parseInt(expiry, 10)) return false; // expired

    const expected = crypto
      .createHmac('sha256', CONFIG.TOKEN_SECRET)
      .update(`${vid}:${expiry}`)
      .digest('hex');

    // Constant-time comparison
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
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
} catch (_) {
  // Silent — avoids leaking config in logs
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
      return {
        streamUrl: `https://www.youtube.com/embed/${videoId}`,
        videoId, useProxy: true, isEmbed: true, success: true
      };
    }
    return { success: false, message: 'Invalid YouTube URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertVimeoUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(Boolean)[0];
    if (videoId) {
      return {
        streamUrl: `https://player.vimeo.com/video/${videoId}`,
        videoId, useProxy: true, isEmbed: true, success: true
      };
    }
    return { success: false, message: 'Invalid Vimeo URL' };
  } catch (e) { return { success: false, message: e.message }; }
}

function convertDailymotionUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(p => p && p !== 'video')[0];
    if (videoId) {
      return {
        streamUrl: `https://www.dailymotion.com/embed/video/${videoId}`,
        videoId, useProxy: true, isEmbed: true, success: true
      };
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
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
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
    if (!converter)
      return res.status(400).json({ success: false, message: 'Unsupported platform' });

    const converted = converter(videoUrl);
    if (!converted.success)
      return res.status(400).json({ success: false, message: converted.message });

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

    if (error)
      return res.status(500).json({ success: false, message: error.message });

    res.json({
      success: true,
      videoUrl: `${CONFIG.PLATFORM_B_URL}/video/${videoId}`,
      videoId,
      platform: platform.toLowerCase()
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Get video metadata — NEVER expose original URL
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const secKey = req.headers['x-security-string'];

    if (!secKey || secKey.trim() !== CONFIG.MASTER_SECURITY_STRING.trim()) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    if (!supabase)
      return res.status(500).json({ success: false, message: 'Database not initialized' });

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();

    if (error || !videoData)
      return res.status(404).json({ success: false, message: 'Video not found' });

    // Update access count (fire-and-forget)
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

    // Generate a short-lived signed token for this video stream
    const streamToken = generateStreamToken(videoId);
    return res.json({
      success: true,
      proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}`,
      streamToken,          // short-lived, sent separately (not baked into URL)
      platform: videoData.platform,
      type: 'video'
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Stream proxy — validates short-lived token, blocks download managers
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;

    // Accept token from custom header (preferred) OR query string (Safari fallback)
    const token = req.headers['x-stream-token'] || req.query.token;

    if (!token || !validateStreamToken(token, videoId)) {
      return res.status(403).send('Forbidden');
    }

    // Block known download manager user-agents
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const blocked = ['idm/', 'internet download manager', 'fdm', 'free download manager',
      'wget', 'curl/', 'aria2', 'uget', 'getright', 'flashget', 'dap/',
      'download accelerator', 'go-http-client', 'python-requests', 'libwww'];
    if (blocked.some(b => ua.includes(b))) {
      return res.status(403).send('Forbidden');
    }

    // Referer check — only allow requests from Platform C
    const referer = req.headers['referer'] || req.headers['origin'] || '';
    const platformCBase = CONFIG.PLATFORM_C_URL;
    const localOrigins = ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5174', 'http://127.0.0.1'];
    const isAllowedReferer = referer === '' || referer.startsWith(platformCBase) || localOrigins.some(o => referer.startsWith(o));
    if (!isAllowedReferer) {
      return res.status(403).send('Forbidden');
    }

    if (!supabase) return res.status(500).send('Database error');

    const { data: videoData, error } = await supabase
      .from('videos').select('*').eq('id', videoId).single();

    if (error || !videoData) return res.status(404).send('Not found');

    const sourceUrl = videoData.stream_url;
    const range = req.headers.range;

    const fetchHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Connection': 'keep-alive'
    };
    if (range) fetchHeaders['Range'] = range;
    if (videoData.is_google_drive) fetchHeaders['Referer'] = 'https://drive.google.com/';

    const response = await fetch(sourceUrl, { headers: fetchHeaders, redirect: 'follow' });

    if (!response.ok) return res.status(response.status).send('Source error');

    const contentType = response.headers.get('content-type') || 'video/mp4';
    const contentLength = response.headers.get('content-length');
    const contentRange  = response.headers.get('content-range');

    res.setHeader('Content-Type', contentType);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Content-Disposition', 'inline');
    res.removeHeader('X-Powered-By');

    if (contentLength) res.setHeader('Content-Length', contentLength);
    if (contentRange)  res.setHeader('Content-Range', contentRange);

    res.status(range && response.status === 206 ? 206 : 200);
    res.flushHeaders();

    if (res.socket) {
      res.socket.setNoDelay(true);
      res.socket.setTimeout(0);
    }

    response.body.pipe(res);

  } catch (e) {
    if (!res.headersSent) res.status(500).send('Stream error');
  }
});

// Embed proxy — permanent key is acceptable here (embeds aren't raw downloadable files)
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

    const response = await fetch(videoData.stream_url, {
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });

    if (!response.ok) return res.status(response.status).send('Embed error');

    const html = await response.text();
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (e) {
    res.status(500).send('Error');
  }
});

// Health check — no sensitive data exposed
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    database: supabase ? 'connected' : 'not connected',
    securityConfigured: true,
    cors: 'enabled'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Not found' });
});

// Only start local server when NOT running on Vercel
if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT);
}

export default app;
