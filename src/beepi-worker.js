
// Import libraries for JWT generation
import { SignJWT } from 'jose';

export default {
  async fetch(request, env, ctx) {
    // Handle CORS
    if (request.method === "OPTIONS") {
      return handleCORS();
    }

    try {
      // Get registration number from request
      const { registrationNumber } = await request.json();

      // Generate JWT
      const jwt = await generateJWT(env);

      // Exchange JWT for access token
      const accessToken = await getAccessToken(jwt, env);

      // Call Vegvesen API
      const vehicleData = await getVehicleData(accessToken, registrationNumber, env);

      // Return data to WordPress
      return new Response(JSON.stringify(vehicleData), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "https://beepi.no"
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({ 
        error: error.message,
        details: error.stack 
      }), {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "https://beepi.no"
        }
      });
    }
  }
};

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
