import { kv } from '@vercel/kv';
import crypto from 'crypto';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Token');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Get session token from header
  const sessionToken = req.headers['x-session-token'] || req.headers['authorization']?.replace('Bearer ', '');

  if (!sessionToken) {
    return res.status(401).json({ error: 'Session token required. Please login first.' });
  }

  // Validate session (in production, check from Redis/KV)
  const securityString = req.headers['x-security-string'];
  if (!securityString) {
    return res.status(401).json({ error: 'Security string required' });
  }

  const { platformAUrl } = req.body;

  if (!platformAUrl) {
    return res.status(400).json({ error: 'platformAUrl is required' });
  }

  // Validate URL format
  try {
    new URL(platformAUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Generate unique wrapped video ID
  const wrappedVideoId = crypto.randomBytes(16).toString('hex');

  // Store in Vercel KV
  const videoData = {
    platformAUrl,
    securityString, // Store the security string that can access this video
    createdAt: new Date().toISOString(),
  };

  await kv.set(`video:${wrappedVideoId}`, JSON.stringify(videoData));

  // Generate Platform B URL
  const platformBUrl = `${process.env.PLATFORM_B_URL || `https://${req.headers.host}`}/watch/${wrappedVideoId}`;

  return res.status(200).json({
    success: true,
    wrappedVideoId,
    platformBUrl,
    message: 'Video wrapped successfully. Share this URL with Platform C.',
  });
}
