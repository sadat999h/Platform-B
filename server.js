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

// In-memory session store (use Redis in production)
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
      // Generate unique security string for this session
      const securityString = crypto.randomBytes(32).toString('hex');
      const sessionId = crypto.randomBytes(16).toString('hex');
      
      // Store session in memory
      sessions.set(sessionId, {
        userId,
        securityString,
        createdAt: Date.now()
      });
      
      // Also store the security string in Firestore for validation
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
    
    // Validate session
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired session' 
      });
    }
    
    // Generate unique video ID
    const videoId = crypto.randomBytes(16).toString('hex');
    
    // Store video mapping in Firestore
    await db.collection('videos').doc(videoId).set({
      originalUrl: videoUrl,
      securityString: session.securityString,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: session.userId,
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
    
    // Validate video exists
    const videoDoc = await db.collection('videos').doc(videoId).get();
    
    if (!videoDoc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'Video not found' 
      });
    }
    
    const videoData = videoDoc.data();
    
    // Validate security string
    if (videoData.securityString !== securityString) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid security string' 
      });
    }
    
    // Verify security string is still active
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
      originalUrl: videoData.originalUrl,
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

// Get video stats (optional - for admin)
app.get('/api/stats/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const sessionId = req.headers['x-session-id'];
    
    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid session' 
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
    console.error('Stats error:', error);
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
