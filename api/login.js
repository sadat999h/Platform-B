import crypto from 'crypto';

// In-memory session storage (for simplicity, use Redis in production)
const sessions = new Map();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { username, password } = req.body;

  // Get credentials from environment
  const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Validate credentials
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate security string (this is the master key for the session)
  const securityString = crypto.randomBytes(32).toString('hex');
  const sessionToken = crypto.randomBytes(32).toString('hex');

  // Store session
  sessions.set(sessionToken, {
    securityString,
    username,
    createdAt: new Date().toISOString(),
  });

  // Clean up old sessions (older than 24 hours)
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  for (const [token, session] of sessions.entries()) {
    if (new Date(session.createdAt).getTime() < oneDayAgo) {
      sessions.delete(token);
    }
  }

  return res.status(200).json({
    success: true,
    sessionToken,
    securityString,
    message: 'Login successful. Use this security string for Platform C.',
  });
}
