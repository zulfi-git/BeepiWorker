import { SignJWT } from 'jose';

// Simple in-memory cache and rate limit store
const CACHE_TTL = 86400000; // 24 hours in ms
const RATE_LIMIT = 10; // requests per minute
const cache = new Map();
const rateLimiter = new Map();

export default {
  async fetch(request, env, ctx) {
    const headers = corsHeaders(request);
    if (!headers) {
      return new Response('Forbidden', { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    try {
      validateRequest(request);

    try {
      // Rate limiting
      const ip = request.headers.get('cf-connecting-ip') || 'unknown';
      if (isRateLimited(ip)) {
        return new Response(JSON.stringify({ 
          error: 'Rate limit exceeded. Please try again later.' 
        }), {
          status: 429,
          headers: corsHeaders()
        });
      }

      const { registrationNumber } = await request.json();

      // Input validation
      if (!isValidRegistrationNumber(registrationNumber)) {
        return new Response(JSON.stringify({ 
          error: 'Invalid registration number format' 
        }), {
          status: 400,
          headers: corsHeaders()
        });
      }

      // Check cache
      const cachedData = getCache(registrationNumber);
      if (cachedData) {
        return new Response(JSON.stringify(cachedData), {
          headers: corsHeaders()
        });
      }

      const jwt = await generateJWT(env);
      const accessToken = await getAccessToken(jwt, env);
      const vehicleData = await getVehicleData(accessToken, registrationNumber, env);

      // Cache the response
      setCache(registrationNumber, vehicleData);

      return new Response(JSON.stringify(vehicleData), {
        headers: corsHeaders()
      });
    } catch (error) {
      const status = error.name === 'ValidationError' ? 400 : 500;
      return new Response(JSON.stringify({ 
        error: error.message,
        code: error.name
      }), {
        status,
        headers: corsHeaders()
      });
    }
  }
};

function corsHeaders(request) {
  const origin = request.headers.get('Origin');
  if (origin !== 'https://beepi.no') {
    return null;
  }
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "https://beepi.no",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function validateRequest(request) {
  const origin = request.headers.get('Origin');
  const referer = request.headers.get('Referer');
  
  if (!origin || origin !== 'https://beepi.no') {
    throw new Error('Invalid origin');
  }
  
  if (!referer || !referer.startsWith('https://beepi.no/')) {
    throw new Error('Invalid referer');
  }
}

function handleCORS() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "https://beepi.no",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    }
  });
}

function isValidRegistrationNumber(reg) {
  return /^[A-Z]{2}[0-9]{4,5}$/.test(reg.replace(/\s/g, ''));
}

function isRateLimited(ip) {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const key = `${ip}:${minute}`;

  const count = rateLimiter.get(key) || 0;
  if (count >= RATE_LIMIT) return true;

  rateLimiter.set(key, count + 1);
  return false;
}

function getCache(key) {
  const item = cache.get(key);
  if (item && Date.now() - item.timestamp < CACHE_TTL) {
    return item.data;
  }
  cache.delete(key);
  return null;
}

const MAX_CACHE_SIZE = 1000; // Maximum number of entries

function setCache(key, data) {
  // Clean old entries if cache is too large
  if (cache.size >= MAX_CACHE_SIZE) {
    const now = Date.now();
    // Delete oldest entries and expired entries
    for (const [k, v] of cache.entries()) {
      if (now - v.timestamp > CACHE_TTL) {
        cache.delete(k);
      }
    }
    // If still too large, delete oldest entries
    if (cache.size >= MAX_CACHE_SIZE) {
      const oldest = [...cache.entries()]
        .sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
      cache.delete(oldest[0]);
    }
  }
  
  cache.set(key, {
    timestamp: Date.now(),
    data
  });
}

async function generateJWT(env) {
  const now = Math.floor(Date.now() / 1000);

  // Parse the private key from PEM format
  if (!env.PRIVATE_KEY) {
    throw new Error('PRIVATE_KEY environment variable is missing');
  }

  let privateKey;
  try {
    // Extract the base64 part between BEGIN and END markers
    const pemContents = env.PRIVATE_KEY
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, '');

    const binaryStr = atob(pemContents);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      bytes,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );
  } catch (error) {
    throw new Error(`Invalid private key format: ${error.message}`);
  }
  
  // Build JWT payload
  const jwt = await new SignJWT({
    scope: env.SCOPE || "svv:kjoretoy/kjoretoyopplysninger",
    iss: env.CLIENT_ID,
    aud: env.AUD || "https://test.maskinporten.no/",
    exp: now + 119, // slightly less than 120 seconds to allow for clock skew
    iat: now,
    jti: "jwt-" + crypto.randomUUID(),
    resource: env.RESOURCE || "https://www.utv.vegvesen.no"
  })
  .setProtectedHeader({ 
    alg: "RS256",
    kid: "246667915295584784094897563941390788079644225910"  // Hardcoded KID
  })
  .sign(privateKey);

  return jwt;
}

async function getAccessToken(jwt, env) {
  const tokenUrl = env.TOKEN_URL || "https://test.maskinporten.no/token";
  
  // Using URLSearchParams to properly format the body
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', jwt);
  
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  });

  const responseBody = await response.text();
  
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${responseBody}`);
  }

  try {
    const data = JSON.parse(responseBody);
    return data.access_token;
  } catch (error) {
    throw new Error(`Failed to parse token response: ${responseBody}`);
  }
}

async function getVehicleData(token, registrationNumber, env) {
  const lookupUrl = env.LOOKUP_URL || 
    "https://akfell-datautlevering-sisdinky.utv.atlas.vegvesen.no/kjoretoyoppslag/bulk/kjennemerke";
  
  const response = await fetch(lookupUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify([
      { kjennemerke: registrationNumber }
    ])
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Vehicle lookup failed: ${error}`);
  }

  return response.json();
}