//server.js Platform B - FULLY SECURE (No URL Exposure)

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';
import fetch from 'node-fetch';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin
let db;
try {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.error('FIREBASE_SERVICE_ACCOUNT not set');
  } else {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
    }
    
    db = admin.firestore();
    console.log('Firebase initialized successfully');
  }
} catch (error) {
  console.error('Firebase initialization error:', error.message);
}

const MASTER_SECURITY_STRING = process.env.MASTER_SECURITY_STRING;

// Platform-specific URL converters
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
      const separator = url.includes('?') ? '&' : '?';
      directUrl = url + separator + 'raw=1';
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
    
    if (matchFile) {
      fileId = matchFile[1];
    } else if (matchOpen) {
      fileId = matchOpen[1];
    }
    
    if (fileId) {
      // Use multiple streaming URLs for better compatibility
      return { 
        streamUrl: `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`,
        alternateUrl: `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`,
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
    } else {
      const match = urlObj.pathname.match(/\/embed\/([^/?]+)/);
      if (match) videoId = match[1];
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

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { userId, password } = req.body;
    
    if (!userId || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID and password are required' 
      });
    }
    
    if (userId === process.env.ADMIN_USER_ID && password === process.env.ADMIN_PASSWORD) {
      res.json({
        success: true,
        message: 'Login successful'
      });
    } else {
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Submit video URL endpoint
app.post('/api/submit-video', async (req, res) => {
  try {
    const { userId, password, videoUrl, platform } = req.body;
    
    if (userId !== process.env.ADMIN_USER_ID || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    if (!videoUrl || !platform) {
      return res.status(400).json({ 
        success: false, 
        message: 'Video URL and platform are required' 
      });
    }
    
    if (!db) {
      return res.status(500).json({ 
        success: false, 
        message: 'Database not initialized. Check server configuration.' 
      });
    }
    
    let converted;
    switch(platform.toLowerCase()) {
      case 'dropbox':
        converted = convertDropboxUrl(videoUrl);
        break;
      case 'gdrive':
      case 'google-drive':
        converted = convertGoogleDriveUrl(videoUrl);
        break;
      case 'youtube':
        converted = convertYouTubeUrl(videoUrl);
        break;
      case 'vimeo':
        converted = convertVimeoUrl(videoUrl);
        break;
      case 'dailymotion':
        converted = convertDailymotionUrl(videoUrl);
        break;
      default:
        return res.status(400).json({ 
          success: false, 
          message: 'Unsupported platform' 
        });
    }
    
    if (!converted.success) {
      return res.status(400).json({ 
        success: false, 
        message: converted.message 
      });
    }
    
    const videoId = crypto.randomBytes(16).toString('hex');
    
    await db.collection('videos').doc(videoId).set({
      originalUrl: videoUrl,
      streamUrl: converted.streamUrl,
      alternateUrl: converted.alternateUrl || null,
      platform: platform.toLowerCase(),
      useProxy: converted.useProxy || false,
      isEmbed: converted.isEmbed || false,
      isGoogleDrive: converted.isGoogleDrive || false,
      platformVideoId: converted.videoId || converted.fileId || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: userId,
      accessCount: 0
    });
    
    const platformBUrl = `${process.env.PLATFORM_B_URL}/video/${videoId}`;
    
    res.json({
      success: true,
      videoUrl: platformBUrl,
      videoId,
      platform: platform.toLowerCase()
    });
  } catch (error) {
    console.error('Submit video error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// CRITICAL: Fetch video metadata - NEVER expose original URL
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.headers['x-security-string'];
    
    if (!securityString || securityString !== MASTER_SECURITY_STRING) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string' 
      });
    }
    
    if (!db) {
      return res.status(500).json({ 
        success: false, 
        message: 'Database not initialized' 
      });
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Video not found' 
      });
    }
    
    const videoData = videoDoc.data();
    
    await db.collection('videos').doc(videoId).update({
      accessCount: admin.firestore.FieldValue.increment(1),
      lastAccessedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // CRITICAL: NEVER send original URL to client
    // All content goes through our proxy
    if (videoData.isEmbed) {
      // For embeds (YouTube, Vimeo, Dailymotion), proxy the iframe
      res.json({
        success: true,
        proxyUrl: `${process.env.PLATFORM_B_URL}/api/embed/${videoId}`,
        platform: videoData.platform,
        type: 'embed',
        videoId: videoId
      });
    } else {
      // For direct videos (Dropbox, GDrive), proxy the stream
      res.json({
        success: true,
        proxyUrl: `${process.env.PLATFORM_B_URL}/api/stream/${videoId}`,
        platform: videoData.platform,
        type: 'video',
        videoId: videoId
      });
    }
  } catch (error) {
    console.error('Fetch video error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Embed proxy for iframe-based platforms (YouTube, Vimeo, Dailymotion)
app.get('/api/embed/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.query.key || req.headers['x-security-string'];
    
    if (!securityString || securityString !== MASTER_SECURITY_STRING) {
      return res.status(403).send('Forbidden');
    }
    
    if (!db) {
      return res.status(500).send('Database not initialized');
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).send('Not Found');
    }
    
    const videoData = videoDoc.data();
    const embedUrl = videoData.streamUrl;
    
    // Fetch the embed page and serve it
    const response = await fetch(embedUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    if (!response.ok) {
      return res.status(response.status).send('Embed Error');
    }
    
    let html = await response.text();
    
    // Set proper headers
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    res.send(html);
    
  } catch (error) {
    console.error('Embed proxy error:', error);
    res.status(500).send('Server Error');
  }
});

// Video streaming proxy - ULTRA-FAST with advanced buffering elimination
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.query.key || req.headers['x-security-string'];
    
    console.log('Stream request for video:', videoId);
    console.log('Security string present:', !!securityString);
    
    if (!securityString || securityString !== MASTER_SECURITY_STRING) {
      console.error('Invalid security string');
      return res.status(403).send('Forbidden');
    }
    
    if (!db) {
      console.error('Database not initialized');
      return res.status(500).send('Database not initialized');
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      console.error('Video not found:', videoId);
      return res.status(404).send('Not Found');
    }
    
    const videoData = videoDoc.data();
    let sourceUrl = videoData.streamUrl;
    const isGoogleDrive = videoData.isGoogleDrive || false;
    
    console.log('Source URL:', sourceUrl);
    console.log('Is Google Drive:', isGoogleDrive);
    
    // Handle range requests for instant seeking
    const range = req.headers.range;
    
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': '*/*',
      'Accept-Encoding': 'identity',
      'Connection': 'keep-alive'
    };
    
    if (range) {
      headers['Range'] = range;
      console.log('Range request:', range);
    }
    
    // Google Drive specific optimization
    if (isGoogleDrive) {
      headers['Referer'] = 'https://drive.google.com/';
      headers['Origin'] = 'https://drive.google.com';
    }
    
    try {
      let response = await fetch(sourceUrl, { 
        headers,
        redirect: 'manual',
        compress: false
      });
      
      console.log('Initial response status:', response.status);
      
      // Handle Google Drive redirects
      if (isGoogleDrive && (response.status === 301 || response.status === 302 || response.status === 303 || response.status === 307 || response.status === 308)) {
        const redirectUrl = response.headers.get('location');
        if (redirectUrl) {
          console.log('Following Google Drive redirect to:', redirectUrl);
          response = await fetch(redirectUrl, {
            headers,
            redirect: 'follow',
            compress: false
          });
          console.log('Redirect response status:', response.status);
        }
      }
      
      // Check if response contains Google Drive virus scan warning page
      if (isGoogleDrive && response.ok) {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
          console.log('Got HTML response from GDrive, extracting confirm code');
          const html = await response.text();
          const confirmMatch = html.match(/confirm=([^&"']+)/);
          
          if (confirmMatch) {
            const confirmCode = confirmMatch[1];
            const newUrl = sourceUrl.includes('?') 
              ? `${sourceUrl}&confirm=${confirmCode}`
              : `${sourceUrl}?confirm=${confirmCode}`;
            
            console.log('Bypassing confirmation with:', newUrl);
            response = await fetch(newUrl, {
              headers,
              redirect: 'follow',
              compress: false
            });
            console.log('Confirmation bypass status:', response.status);
          }
        }
      }
      
      if (!response.ok) {
        console.error('Source error:', response.status, response.statusText);
        return res.status(response.status).send('Source Error');
      }
      
      console.log('Streaming video successfully');
      
      // CRITICAL: Set CORS and streaming headers
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Accept-Encoding');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
      
      // Copy ALL headers from source
      const contentType = response.headers.get('content-type');
      const contentLength = response.headers.get('content-length');
      const contentRange = response.headers.get('content-range');
      const lastModified = response.headers.get('last-modified');
      const etag = response.headers.get('etag');
      
      if (contentType) res.setHeader('Content-Type', contentType);
      
      // Force Accept-Ranges for better seeking
      res.setHeader('Accept-Ranges', 'bytes');
      
      if (contentLength) res.setHeader('Content-Length', contentLength);
      if (contentRange) res.setHeader('Content-Range', contentRange);
      if (lastModified) res.setHeader('Last-Modified', lastModified);
      if (etag) res.setHeader('ETag', etag);
      
      // Optimize for streaming
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      
      // Set appropriate status
      if (range && response.status === 206) {
        res.status(206);
      } else if (range && contentLength) {
        res.status(200);
      } else {
        res.status(response.status);
      }
      
      // CRITICAL: Send headers immediately
      res.flushHeaders();
      
      // TCP optimization
      if (res.socket) {
        res.socket.setNoDelay(true);
        res.socket.setTimeout(0);
      }
      
      // ADVANCED: Stream with zero buffering using direct pipe
      response.body.on('error', (err) => {
        console.error('Stream pipe error:', err);
        if (!res.headersSent) {
          res.status(500).send('Stream Error');
        }
      });
      
      // Direct streaming with backpressure handling
      response.body.pipe(res, { end: true });
      
    } catch (fetchError) {
      console.error('Fetch error:', fetchError);
      if (!res.headersSent) {
        res.status(500).send('Stream Error');
      }
    }
    
  } catch (error) {
    console.error('Stream error:', error);
    if (!res.headersSent) {
      res.status(500).send('Server Error');
    }
  }
});

// Handle CORS preflight
app.options('/api/stream/:videoId', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).send();
});

app.options('/api/embed/:videoId', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).send();
});

// Get video stats
app.get('/api/stats/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const { userId, password } = req.query;
    
    if (userId !== process.env.ADMIN_USER_ID || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    if (!db) {
      return res.status(500).json({ 
        success: false, 
        message: 'Database not initialized' 
      });
    }
    
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Video not found' 
      });
    }
    
    const videoData = videoDoc.data();
    
    res.json({
      success: true,
      stats: {
        videoId,
        platform: videoData.platform,
        accessCount: videoData.accessCount || 0,
        createdAt: videoData.createdAt,
        lastAccessedAt: videoData.lastAccessedAt || null
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    firebase: db ? 'connected' : 'not connected'
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Platform B running on port ${PORT}`);
});

export default app;
