// server.js - Platform B Backend
// HARDCODED CONFIGURATION - Change these values

const CONFIG = {
  ADMIN_USER_ID: 'Sporsho',
  ADMIN_PASSWORD: 'Sporsho123',
  MASTER_SECURITY_STRING: 'ULTRA_SECRET_KEY_12345_CHANGE_THIS',
  PLATFORM_B_URL: 'https://your-platform-b.vercel.app'
};

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';
import fetch from 'node-fetch';

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'X-Security-String', 'Range', 'Accept', 'Accept-Encoding'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges'],
  credentials: false,
  maxAge: 86400
}));

app.use(express.json());

// Additional CORS headers middleware
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, Range, Accept, Accept-Encoding');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// Initialize Firebase from environment variable
let db;
try {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT environment variable not set');
  }
  
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  }
  db = admin.firestore();
  console.log('✓ Firebase initialized successfully');
} catch (error) {
  console.error('❌ Firebase initialization error:', error.message);
  console.error('Make sure FIREBASE_SERVICE_ACCOUNT env variable contains valid JSON');
}

// CORS preflight handlers - Must be before other routes
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, Range, Accept, Accept-Encoding');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).end();
});

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
    
    if (!db) {
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
    
    await db.collection('videos').doc(videoId).set({
      originalUrl: videoUrl,
      streamUrl: converted.streamUrl,
      platform: platform.toLowerCase(),
      useProxy: converted.useProxy || false,
      isEmbed: converted.isEmbed || false,
      isGoogleDrive: converted.isGoogleDrive || false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: userId,
      accessCount: 0
    });
    
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
    // Set CORS headers first
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String');
    
    const { videoId } = req.params;
    const secKey = req.headers['x-security-string'];
    
    console.log('Video metadata request for:', videoId);
    console.log('Security header present:', !!secKey);
    
    if (secKey !== CONFIG.MASTER_SECURITY_STRING) {
      return res.status(403).json({ success: false, message: 'Invalid security string' });
    }
    
    console.log('✓ Security validated');
    
    if (!db) {
      return res.status(500).json({ success: false, message: 'Database not initialized' });
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ success: false, message: 'Video not found' });
    }
    
    const videoData = videoDoc.data();
    console.log('Video found - Platform:', videoData.platform);
    
    await db.collection('videos').doc(videoId).update({
      accessCount: admin.firestore.FieldValue.increment(1),
      lastAccessedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Return only proxy URL, NEVER original
    if (videoData.isEmbed) {
      res.json({
        success: true,
        proxyUrl: `${CONFIG.PLATFORM_B_URL}/api/embed/${videoId}`,
        platform: videoData.platform,
        type: 'embed'
      });
    } else {
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

// Stream proxy - ULTRA FAST
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    // Set CORS headers immediately
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Accept-Encoding, X-Security-String');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
    
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    
    console.log('=== STREAM REQUEST ===');
    console.log('Video ID:', videoId);
    
    if (key !== CONFIG.MASTER_SECURITY_STRING) {
      return res.status(403).send('Forbidden');
    }
    
    console.log('✓ Security validated');
    
    if (!db) {
      return res.status(500).send('Database error');
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).send('Not found');
    }
    
    const videoData = videoDoc.data();
    const sourceUrl = videoData.streamUrl;
    const range = req.headers.range;
    
    console.log('Platform:', videoData.platform);
    console.log('Fetching from source...');
    
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Connection': 'keep-alive'
    };
    
    if (range) headers['Range'] = range;
    if (videoData.isGoogleDrive) {
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
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    
    const { videoId } = req.params;
    const key = req.query.key || req.headers['x-security-string'];
    
    if (key !== CONFIG.MASTER_SECURITY_STRING) {
      return res.status(403).send('Forbidden');
    }
    
    if (!db) {
      return res.status(500).send('Database error');
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).send('Not found');
    }
    
    const videoData = videoDoc.data();
    const embedUrl = videoData.streamUrl;
    
    const response = await fetch(embedUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    
    if (!response.ok) {
      return res.status(response.status).send('Embed error');
    }
    
    const html = await response.text();
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
    
  } catch (error) {
    res.status(500).send('Error');
  }
});

// CORS preflight handlers - Must be before other routes
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Security-String, Range, Accept, Accept-Encoding');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).end();
});

// Health check
app.get('/api/health', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({ 
    status: 'ok',
    firebase: db ? 'connected' : 'not connected',
    securityConfigured: !!CONFIG.MASTER_SECURITY_STRING
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Platform B running on port ${PORT}`);
});

export default app;
