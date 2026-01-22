import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';
import fetch from 'node-fetch';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// Single security string from environment
const MASTER_SECURITY_STRING = process.env.MASTER_SECURITY_STRING;

// Helper function to convert Dropbox URLs to direct streaming URLs
function convertDropboxUrl(url) {
  try {
    const urlObj = new URL(url);
    
    // Check if it's a Dropbox URL
    if (urlObj.hostname.includes('dropbox.com')) {
      let directUrl = url;
      
      // If it already has raw=1, use as-is
      if (url.includes('raw=1')) {
        directUrl = url;
      }
      // If it has dl=0, replace with raw=1
      else if (url.includes('dl=0')) {
        directUrl = url.replace('dl=0', 'raw=1');
      }
      // If it has dl=1, replace with raw=1
      else if (url.includes('dl=1')) {
        directUrl = url.replace('dl=1', 'raw=1');
      }
      // If no dl parameter, add raw=1
      else {
        const separator = url.includes('?') ? '&' : '?';
        directUrl = url + separator + 'raw=1';
      }
      
      return {
        originalUrl: url,
        streamUrl: directUrl,
        type: 'dropbox',
        success: true
      };
    }
    
    return { success: false, message: 'Invalid Dropbox URL' };
  } catch (error) {
    return { success: false, message: 'Error parsing URL: ' + error.message };
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
    const { userId, password, videoUrl } = req.body;
    
    // Verify credentials
    if (userId !== process.env.ADMIN_USER_ID || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    if (!videoUrl) {
      return res.status(400).json({ 
        success: false, 
        message: 'Video URL is required' 
      });
    }
    
    // Convert Dropbox URL
    const converted = convertDropboxUrl(videoUrl);
    
    if (!converted.success) {
      return res.status(400).json({ 
        success: false, 
        message: converted.message 
      });
    }
    
    // Generate unique video ID
    const videoId = crypto.randomBytes(16).toString('hex');
    
    // Store video mapping in Firestore
    await db.collection('videos').doc(videoId).set({
      originalUrl: videoUrl,
      streamUrl: converted.streamUrl,
      videoType: converted.type,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: userId,
      accessCount: 0
    });
    
    // Generate Platform B URL
    const platformBUrl = `${process.env.PLATFORM_B_URL}/video/${videoId}`;
    
    res.json({
      success: true,
      videoUrl: platformBUrl,
      videoId
    });
  } catch (error) {
    console.error('Submit video error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Fetch video metadata endpoint - requires master security string
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.headers['x-security-string'];
    
    if (!securityString) {
      return res.status(401).json({ 
        success: false, 
        message: 'Security string required' 
      });
    }
    
    // Verify security string
    if (securityString !== MASTER_SECURITY_STRING) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string' 
      });
    }
    
    // Get video data from Firestore
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Video not found' 
      });
    }
    
    const videoData = videoDoc.data();
    
    // Update access count
    await db.collection('videos').doc(videoId).update({
      accessCount: admin.firestore.FieldValue.increment(1),
      lastAccessedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Return proxy URL instead of direct URL to avoid CORS
    const proxyUrl = `${process.env.PLATFORM_B_URL}/api/stream/${videoId}`;
    
    res.json({
      success: true,
      proxyUrl: proxyUrl,
      videoType: videoData.videoType,
      videoId: videoId
    });
  } catch (error) {
    console.error('Fetch video error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Video streaming proxy endpoint - bypasses CORS
app.get('/api/stream/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.headers['x-security-string'];
    
    if (!securityString) {
      return res.status(401).json({ 
        success: false, 
        message: 'Security string required' 
      });
    }
    
    // Verify security string
    if (securityString !== MASTER_SECURITY_STRING) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string' 
      });
    }
    
    // Get video data from Firestore
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Video not found' 
      });
    }
    
    const videoData = videoDoc.data();
    const dropboxUrl = videoData.streamUrl;
    
    // Handle range requests for video seeking
    const range = req.headers.range;
    
    // Fetch video from Dropbox with range support
    const headers = {
      'User-Agent': 'Mozilla/5.0'
    };
    
    if (range) {
      headers['Range'] = range;
    }
    
    const response = await fetch(dropboxUrl, { headers });
    
    // Set appropriate headers
    res.setHeader('Content-Type', response.headers.get('content-type') || 'video/mp4');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    
    if (range) {
      const contentRange = response.headers.get('content-range');
      const contentLength = response.headers.get('content-length');
      
      if (contentRange) res.setHeader('Content-Range', contentRange);
      if (contentLength) res.setHeader('Content-Length', contentLength);
      
      res.status(206); // Partial content
    } else {
      const contentLength = response.headers.get('content-length');
      if (contentLength) res.setHeader('Content-Length', contentLength);
    }
    
    // Stream the video
    response.body.pipe(res);
    
  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Stream error: ' + error.message 
    });
  }
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
    timestamp: new Date().toISOString()
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
