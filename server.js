import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import admin from 'firebase-admin';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin (Firestore only)
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// In-memory session store
const sessions = new Map();

// Clean up old sessions every hour
setInterval(() => {
  const oneHourAgo = Date.now() - 3600000;
  for (const [sessionId, session] of sessions.entries()) {
    if (session.createdAt < oneHourAgo) {
      sessions.delete(sessionId);
    }
  }
}, 3600000);

// Helper function to convert URLs to embeddable format
function convertToEmbeddableUrl(url) {
  try {
    const urlObj = new URL(url);
    
    // YouTube URLs
    if (urlObj.hostname.includes('youtube.com') || urlObj.hostname.includes('youtu.be')) {
      let videoId = '';
      
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
          url: `https://www.youtube.com/embed/${videoId}`,
          type: 'youtube',
          videoId: videoId
        };
      }
    }
    
    // Google Drive URLs
    if (urlObj.hostname.includes('drive.google.com')) {
      let fileId = '';
      
      const matchFile = url.match(/\/file\/d\/([^/?]+)/);
      const matchOpen = url.match(/[?&]id=([^&]+)/);
      
      if (matchFile) {
        fileId = matchFile[1];
      } else if (matchOpen) {
        fileId = matchOpen[1];
      }
      
      if (fileId) {
        return {
          url: `https://drive.google.com/file/d/${fileId}/preview`,
          type: 'gdrive',
          fileId: fileId
        };
      }
    }
    
    // Vimeo URLs
    if (urlObj.hostname.includes('vimeo.com')) {
      const videoId = urlObj.pathname.split('/').pop();
      if (videoId) {
        return {
          url: `https://player.vimeo.com/video/${videoId}`,
          type: 'vimeo',
          videoId: videoId
        };
      }
    }
    
    // Dailymotion URLs
    if (urlObj.hostname.includes('dailymotion.com')) {
      const videoId = urlObj.pathname.split('/').pop();
      if (videoId) {
        return {
          url: `https://www.dailymotion.com/embed/video/${videoId}`,
          type: 'dailymotion',
          videoId: videoId
        };
      }
    }
    
    // Default: return as-is if already embeddable or unknown
    return {
      url: url,
      type: 'other',
      videoId: null
    };
  } catch (error) {
    return {
      url: url,
      type: 'other',
      videoId: null
    };
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
      const securityString = crypto.randomBytes(32).toString('hex');
      const sessionId = crypto.randomBytes(16).toString('hex');
      
      sessions.set(sessionId, {
        userId,
        securityString,
        createdAt: Date.now()
      });
      
      await db.collection('security_strings').doc(securityString).set({
        createdBy: userId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        active: true
      });
      
      res.json({
        success: true,
        sessionId,
        securityString
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
    const { sessionId, videoUrl } = req.body;
    
    if (!sessionId || !videoUrl) {
      return res.status(400).json({ 
        success: false, 
        message: 'Session ID and video URL are required' 
      });
    }
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired session' 
      });
    }
    
    // Convert URL to embeddable format
    const convertedUrl = convertToEmbeddableUrl(videoUrl);
    
    const videoId = crypto.randomBytes(16).toString('hex');
    
    // Store video mapping in Firestore
    await db.collection('videos').doc(videoId).set({
      originalUrl: videoUrl,
      embeddableUrl: convertedUrl.url,
      videoType: convertedUrl.type,
      platformVideoId: convertedUrl.videoId,
      securityString: session.securityString,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: session.userId,
      accessCount: 0
    });
    
    const platformBUrl = `${process.env.PLATFORM_B_URL}/video/${videoId}`;
    
    res.json({
      success: true,
      videoUrl: platformBUrl,
      videoId,
      videoType: convertedUrl.type
    });
  } catch (error) {
    console.error('Submit video error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

// Fetch video endpoint (requires security string)
app.get('/api/video/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const securityString = req.headers['x-security-string'];
    
    if (!securityString) {
      return res.status(401).json({ 
        success: false, 
        message: 'Security string required in X-Security-String header' 
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
    
    if (videoData.securityString !== securityString) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string' 
      });
    }
    
    const securityDoc = await db.collection('security_strings').doc(securityString).get();
    if (!securityDoc.exists || !securityDoc.data().active) {
      return res.status(403).json({ 
        success: false, 
        message: 'Security string is inactive or expired' 
      });
    }
    
    // Update access count
    await db.collection('videos').doc(videoId).update({
      accessCount: admin.firestore.FieldValue.increment(1),
      lastAccessedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({
      success: true,
      embeddableUrl: videoData.embeddableUrl,
      videoType: videoData.videoType,
      platformVideoId: videoData.platformVideoId,
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
