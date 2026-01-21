import { kv } from '@vercel/kv';

export const config = {
  api: {
    responseLimit: false,
  },
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'X-Security-String, Range, Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { videoId } = req.query;

  // Extract security string from headers or query params
  const securityString = 
    req.headers['x-security-string'] || 
    req.query.key;

  if (!securityString) {
    return res.status(403).json({ error: 'Security string required' });
  }

  // Retrieve video data from KV
  const videoDataJson = await kv.get(`video:${videoId}`);
  
  if (!videoDataJson) {
    return res.status(404).json({ error: 'Video not found' });
  }

  const videoData = JSON.parse(videoDataJson);

  // Validate security string
  if (videoData.securityString !== securityString) {
    return res.status(403).json({ error: 'Invalid security string' });
  }

  // Proxy the video stream from Platform A
  try {
    const headers = {
      'User-Agent': 'Mozilla/5.0 (compatible; SecureVideoProxy/1.0)',
    };

    // Forward range header for video seeking
    if (req.headers.range) {
      headers['Range'] = req.headers.range;
    }

    const response = await fetch(videoData.platformAUrl, {
      method: req.method,
      headers,
    });

    if (!response.ok) {
      console.error('Platform A fetch failed:', response.status, response.statusText);
      return res.status(response.status).json({ 
        error: 'Failed to fetch video from Platform A' 
      });
    }

    // Forward response headers
    const contentType = response.headers.get('content-type');
    const contentLength = response.headers.get('content-length');
    const acceptRanges = response.headers.get('accept-ranges');
    const contentRange = response.headers.get('content-range');

    if (contentType) res.setHeader('Content-Type', contentType);
    if (contentLength) res.setHeader('Content-Length', contentLength);
    if (acceptRanges) res.setHeader('Accept-Ranges', acceptRanges);
    if (contentRange) res.setHeader('Content-Range', contentRange);

    // Cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=31536000');

    res.status(response.status);

    if (req.method === 'HEAD') {
      return res.end();
    }

    // Stream the video
    const reader = response.body.getReader();
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
    
    res.end();
  } catch (error) {
    console.error('Proxy error:', error);
    return res.status(500).json({ error: 'Failed to stream video' });
  }
}
