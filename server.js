import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';

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

// Helper function to extract Google Drive file ID and convert to direct stream URL
function convertGoogleDriveUrl(url) {
  try {
    const urlObj = new URL(url);
    
    if (urlObj.hostname.includes('drive.google.com')) {
      let fileId = '';
      
      // Extract file ID from various Google Drive URL formats
      const matchFile = url.match(/\/file\/d\/([^/?]+)/);
      const matchOpen = url.match(/[?&]id=([^&]+)/);
      
      if (matchFile) {
        fileId = matchFile[1];
      } else if (matchOpen) {
        fileId = matchOpen[1];
      }
      
      if (fileId) {
        return {
          fileId: fileId,
          // Direct video stream URL - fastest loading
          streamUrl: `https://drive.google.com/uc?export=download&id=${fileId}`,
          // Alternative embed URL
          embedUrl: `https://drive.google.com/file/d/${fileId}/preview`,
          type: 'gdrive',
          success: true
        };
      }
    }
    
    return { success: false, message: 'Invalid Google Drive URL' };
  } catch (error) {
    return { success: false, message: 'Error parsing URL: ' + error.message };
  }
}

// Login endpoint - simplified
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
    
    // Convert Google Drive URL
    const converted = convertGoogleDriveUrl(videoUrl);
    
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
      fileId: converted.fileId,
      streamUrl: converted.streamUrl,
      embedUrl: converted.embedUrl,
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

// Fetch video endpoint - requires master security string
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
    
    // Return video stream URL for fast loading
    res.json({
      success: true,
      streamUrl: videoData.streamUrl,
      embedUrl: videoData.embedUrl,
      fileId: videoData.fileId,
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
