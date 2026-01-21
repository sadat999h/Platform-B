import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-Session-Token');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Validate session
  const sessionToken = req.headers['x-session-token'];
  if (!sessionToken) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const keys = [];
    let cursor = 0;

    do {
      const result = await kv.scan(cursor, { match: 'video:*', count: 100 });
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== 0);

    const videos = [];
    
    for (const key of keys) {
      const videoDataJson = await kv.get(key);
      if (videoDataJson) {
        const videoData = JSON.parse(videoDataJson);
        const videoId = key.replace('video:', '');
        videos.push({
          videoId,
          platformAUrl: videoData.platformAUrl,
          createdAt: videoData.createdAt,
          platformBUrl: `${process.env.PLATFORM_B_URL || req.headers.host}/watch/${videoId}`,
        });
      }
    }

    return res.status(200).json({ success: true, videos, count: videos.length });
  } catch (error) {
    console.error('List videos error:', error);
    return res.status(500).json({ error: 'Failed to list videos' });
  }
}
