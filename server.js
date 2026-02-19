// server.js - Platform B Backend with Supabase
// HARDCODED CONFIGURATION - Change these values

const CONFIG = {
  ADMIN_USER_ID: 'admin',
  ADMIN_PASSWORD: 'admin123',
  MASTER_SECURITY_STRING: '84418779257393762955868022673598',
  
  // ⚠️ CRITICAL: UPDATE THIS WITH YOUR ACTUAL PLATFORM B URL
  // Find your URL in Vercel dashboard under "Domains"
  // Examples:
  //   - 'https://platform-b-two.vercel.app'
  //   - 'https://platform-b-abc123.vercel.app'
  //   - 'https://your-custom-domain.com'
  PLATFORM_B_URL: 'https://platform-ar14ytgq5-sadat999hs-projects.vercel.app',
  
  PLATFORM_C_URL: 'https://platform-c-gules.vercel.app/',
  SUPABASE_URL: 'https://wkmxkdfkfpcmljegqasy.supabase.co',
  SUPABASE_SERVICE_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndrbXhrZGZrZnBjbWxqZWdxYXN5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDMwNjI3NywiZXhwIjoyMDg1ODgyMjc3fQ.5CPVQiudL6OoXqlBf2Sk25XOa1PaQ1VwgUzpovUrZB4'
};

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// ============================================
// CRITICAL CORS CONFIGURATION - MUST BE FIRST
// ============================================
app.use((req, res, next) => {
  // Allow multiple origins
  const allowedOrigins = [
    CONFIG.PLATFORM_C_URL,
    'https://platform-c.vercel.app',
    'https://platform-c-vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:3000'
  ];
  
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin) || !origin) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, Authorization, Accept, Origin, X-Requested-With, Range');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Content-Length, Content-Range, Accept-Ranges, X-Content-Duration');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Vary', 'Origin');
  
  // Handle preflight OPTIONS request
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  
  next();
});

app.use(express.json());

// Initialize Supabase - use environment variables if available, otherwise use CONFIG
let supabase;
try {
  const supabaseUrl = process.env.SUPABASE_URL || CONFIG.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_KEY || CONFIG.SUPABASE_SERVICE_KEY;
  
  if (!supabaseUrl || !supabaseKey) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
  }
  
  supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });
  
  console.log('✓ Supabase initialized successfully');
} catch (error) {
  console.error('❌ Supabase initialization error:', error.message);
  console.error('Make sure SUPABASE_URL and SUPABASE_SERVICE_KEY are configured');
}

// Platform converters
function convertDropboxUrl(url) {
  try {
    let directUrl = url;
    if (url.includes('raw=1')) {
      directUrl = url;
    } else if (url.includes('dl=0')) {
      directUrl = url.replace('dl=0', 'raw=1');
    } else if (url.includes('dl=1')) {
      directUrl = url.replace('dl=1', 'raw=1');
    } else {
      const sep = url.includes('?') ? '&' : '?';
      directUrl = url + sep + 'raw=1';
    }
    return { streamUrl: directUrl, useProxy: true, success: true };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

function convertGoogleDriveUrl(url) {
  try {
    let fileId = '';
    const matchFile = url.match(/\/file\/d\/([^/?]+)/);
    const matchOpen = url.match(/[?&]id=([^&]+)/);
    
    if (matchFile) fileId = matchFile[1];
    else if (matchOpen) fileId = matchOpen[1];
    
    if (fileId) {
      return { 
        streamUrl: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
        fileId: fileId,
        useProxy: true,
        isGoogleDrive: true,
        success: true 
      };
    }
    return { success: false, message: 'Invalid Google Drive URL' };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

function convertYouTubeUrl(url) {
  try {
    let videoId = '';
    const urlObj = new URL(url);
    
    if (urlObj.hostname.includes('youtu.be')) {
      videoId = urlObj.pathname.slice(1);
    } else if (urlObj.searchParams.has('v')) {
      videoId = urlObj.searchParams.get('v');
    }
    
    if (videoId) {
      return { 
        streamUrl: `https://www.youtube.com/embed/${videoId}`,
        videoId: videoId,
        useProxy: true,
        isEmbed: true,
        success: true 
      };
    }
    return { success: false, message: 'Invalid YouTube URL' };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

function convertVimeoUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(p => p)[0];
    if (videoId) {
      return { 
        streamUrl: `https://player.vimeo.com/video/${videoId}`,
        videoId: videoId,
        useProxy: true,
        isEmbed: true,
        success: true 
      };
    }
    return { success: false, message: 'Invalid Vimeo URL' };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

function convertDailymotionUrl(url) {
  try {
    const urlObj = new URL(url);
    const videoId = urlObj.pathname.split('/').filter(p => p && p !== 'video')[0];
    if (videoId) {
      return { 
        streamUrl: `https://www.dailymotion.com/embed/video/${videoId}`,
        videoId: videoId,
        useProxy: true,
        isEmbed: true,
        success: true 
      };
    }
    return { success: false, message: 'Invalid Dailymotion URL' };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { userId, password } = req.body;
    
    if (!userId || !password) {
      return res.status(400).json({ success: false, message: 'User ID and password required' });
    }
    
    if (userId === CONFIG.ADMIN_USER_ID && password === CONFIG.ADMIN_PASSWORD) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Submit video
app.post('/api/submit-video', async (req, res) => {
  try {
    const { userId, password, videoUrl, platform } = req.body;
    
    if (userId !== CONFIG.ADMIN_USER_ID || password !== CONFIG.ADMIN_PASSWORD) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!videoUrl || !platform) {
      return res.status(400).json({ success: false, message: 'Video URL and platform required' });
    }
    
    if (!supabase) {
      return res.status(500).json({ success: false, message: 'Database not initialized' });
    }
    
    let converted;
    switch(platform.toLowerCase()) {
      case 'dropbox': converted = convertDropboxUrl(videoUrl); break;
      case 'gdrive': converted = convertGoogleDriveUrl(videoUrl); break;
      case 'youtube': converted = convertYouTubeUrl(videoUrl); break;
      case 'vimeo': converted = convertVimeoUrl(videoUrl); break;
      case 'dailymotion': converted = convertDailymotionUrl(videoUrl); break;
      default: return res.status(400).json({ success: false, message: 'Unsupported platform' });
    }
    
    if (!converted.success) {
      return res.status(400).json({ success: false, message: converted.message });
    }
    
    const videoId = crypto.randomBytes(16).toString('hex');
    
    // Insert into Supabase
    const { error } = await supabase
      .from('videos')
      .insert({
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
    
    if (error) {
      console.error('Supabase insert error:', error);
      return res.status(500).json({ success: false, message: error.message });
    }
    
    const platformBUrl = `${CONFIG.PLATFORM_B_URL}/video/${videoId}`;
    
    res.json({
      success: true,
      videoUrl: platformBUrl,
      videoId,
      platform: platform.toLowerCase()
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get video metadata - NEVER expose original URL
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const secKey = req.headers['x-security-string'];
    
    console.log('=== VIDEO METADATA REQUEST ===');
    console.log('Video ID:', videoId);
    console.log('Origin:', req.headers.origin);
    console.log('Security header present:', !!secKey);
    console.log('Security header value:', secKey ? `${secKey.substring(0, 10)}...` : 'MISSING');
    console.log('Expected security:', CONFIG.MASTER_SECURITY_STRING.substring(0, 10) + '...');
    
    // More lenient security check with detailed logging
    if (!secKey) {
      console.error('❌ Security header missing');
      return res.status(403).json({ 
        success: false, 
        message: 'Security header required',
        hint: 'Add X-Security-String header'
      });
    }
    
    if (secKey.trim() !== CONFIG.MASTER_SECURITY_STRING.trim()) {
      console.error('❌ Security mismatch');
      console.error('Received:', secKey);
      console.error('Expected:', CONFIG.MASTER_SECURITY_STRING);
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string',
        hint: 'Check security string matches Platform B configuration'
      });
    }
    
    console.log('✓ Security validated');
    
    if (!supabase) {
      return res.status(500).json({ success: false, message: 'Database not initialized' });
    }
    
    // Fetch video from Supabase
    const { data: videoData, error } = await supabase
      .from('videos')
      .select('*')
      .eq('id', videoId)
      .single();
    
    if (error || !videoData) {
      console.error('Video not found:', error);
      return res.status(404).json({ success: false, message: 'Video not found' });
    }
    
    console.log('✓ Video found - Platform:', videoData.platform);
    
    // Update access count
    await supabase
      .from('videos')
      .update({
        access_count: videoData.access_count + 1,
        last_accessed_at: new Date().toISOString()
      })
      .eq('id', videoId);
    
    // Return only proxy URL, NEVER original
    if (videoData.is_embed) {
      console.log('✓ Returning embed URL');
      res.json({
        success: true,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}`,
        platform: videoData.platform,
        type: 'embed'
      });
    } else {
      console.log('✓ Returning stream URL');
      res.json({
        success: true,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/stream/${videoId}`,
        platform: videoData.platform,
        type: 'video'
      });
    }
  } catch (error) {
    console.error('Fetch video error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Stream proxy - ULTRA FAST with CORS
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    
    console.log('=== STREAM REQUEST ===');
    console.log('Video ID:', videoId);
    console.log('Origin:', req.headers.origin);
    console.log('Security key present:', !!key);
    
    if (!key) {
      console.error('❌ Security key missing');
      return res.status(403).send('Security key required');
    }
    
    if (key.trim() !== CONFIG.MASTER_SECURITY_STRING.trim()) {
      console.error('❌ Security key mismatch');
      return res.status(403).send('Invalid security key');
    }
    
    console.log('✓ Security validated');
    
    if (!supabase) {
      return res.status(500).send('Database error');
    }
    
    // Fetch video from Supabase
    const { data: videoData, error } = await supabase
      .from('videos')
      .select('*')
      .eq('id', videoId)
      .single();
    
    if (error || !videoData) {
      console.error('Video not found:', error);
      return res.status(404).send('Not found');
    }
    
    const sourceUrl = videoData.stream_url;
    const range = req.headers.range;
    
    console.log('Platform:', videoData.platform);
    console.log('Fetching from source...');
    
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Connection': 'keep-alive'
    };
    
    if (range) headers['Range'] = range;
    if (videoData.is_google_drive) {
      headers['Referer'] = 'https://drive.google.com/';
    }
    
    const response = await fetch(sourceUrl, { headers, redirect: 'follow' });
    
    console.log('Fetch status:', response.status);
    
    if (!response.ok) {
      return res.status(response.status).send('Source error');
    }
    
    // Set content type
    let contentType = response.headers.get('content-type') || 'video/mp4';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Accept-Ranges', 'bytes');
    
    const contentLength = response.headers.get('content-length');
    const contentRange = response.headers.get('content-range');
    
    if (contentLength) res.setHeader('Content-Length', contentLength);
    if (contentRange) res.setHeader('Content-Range', contentRange);
    
    res.setHeader('Cache-Control', 'public, max-age=31536000');
    
    if (range && response.status === 206) {
      res.status(206);
    } else {
      res.status(200);
    }
    
    console.log('✓ Streaming to client');
    
    res.flushHeaders();
    
    if (res.socket) {
      res.socket.setNoDelay(true);
      res.socket.setTimeout(0);
    }
    
    response.body.pipe(res);
    
  } catch (error) {
    console.error('Stream error:', error);
    if (!res.headersSent) {
      res.status(500).send('Stream error');
    }
  }
});

// Embed proxy
app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    
    console.log('=== EMBED REQUEST ===');
    console.log('Video ID:', videoId);
    console.log('Security key present:', !!key);
    
    if (!key) {
      console.error('❌ Security key missing');
      return res.status(403).send('Security key required');
    }
    
    if (key.trim() !== CONFIG.MASTER_SECURITY_STRING.trim()) {
      console.error('❌ Security key mismatch');
      return res.status(403).send('Invalid security key');
    }
    
    console.log('✓ Security validated');
    
    if (!supabase) {
      return res.status(500).send('Database error');
    }
    
    // Fetch video from Supabase
    const { data: videoData, error } = await supabase
      .from('videos')
      .select('*')
      .eq('id', videoId)
      .single();
    
    if (error || !videoData) {
      console.error('Video not found:', error);
      return res.status(404).send('Not found');
    }
    
    const embedUrl = videoData.stream_url;
    
    console.log('Fetching embed from:', embedUrl);
    
    const response = await fetch(embedUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    
    if (!response.ok) {
      console.error('Embed fetch failed:', response.status);
      return res.status(response.status).send('Embed error');
    }
    
    const html = await response.text();
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
    
    console.log('✓ Embed sent');
    
  } catch (error) {
    console.error('Embed error:', error);
    res.status(500).send('Error');
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    database: supabase ? 'connected' : 'not connected',
    securityConfigured: !!CONFIG.MASTER_SECURITY_STRING,
    cors: 'enabled',
    platformBUrl: CONFIG.PLATFORM_B_URL,
    securityString: CONFIG.MASTER_SECURITY_STRING.substring(0, 10) + '...'
  });
});

// Debug endpoint - shows configuration (⚠️ REMOVE IN PRODUCTION!)
app.get('/api/debug', (req, res) => {
  res.json({
    securityString: CONFIG.MASTER_SECURITY_STRING,
    platformBUrl: CONFIG.PLATFORM_B_URL,
    platformCUrl: CONFIG.PLATFORM_C_URL,
    supabaseConfigured: !!CONFIG.SUPABASE_URL && !!CONFIG.SUPABASE_SERVICE_KEY,
    message: '⚠️ REMOVE THIS ENDPOINT IN PRODUCTION!'
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

// Only start local server when NOT on Vercel
if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`========================================`);
    console.log(`Platform B running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`CORS enabled for: ${CONFIG.PLATFORM_C_URL}`);
    console.log(`Platform B URL: ${CONFIG.PLATFORM_B_URL}`);
    console.log(`Security: ${CONFIG.MASTER_SECURITY_STRING.substring(0, 10)}...`);
    console.log(`========================================`);
    console.log(`⚠️  IMPORTANT: Update PLATFORM_B_URL in CONFIG`);
    console.log(`⚠️  Current: ${CONFIG.PLATFORM_B_URL}`);
    console.log(`========================================`);
  });
}

export default app;
