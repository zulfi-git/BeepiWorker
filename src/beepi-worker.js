// Import libraries for JWT generation
import { SignJWT } from 'jose';

// Store your business certificate and private key as Worker Secrets
// Access them with: env.BUSINESS_CERT and env.PRIVATE_KEY

export default {
  async fetch(request, env, ctx) {
    // Set up CORS to allow requests from your WordPress site
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
      return new Response(JSON.stringify({ error: error.message }), {
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
  
  // Create the private key from the environment variable
  const privateKey = env.PRIVATE_KEY;
  
  // Create the JWT
  const jwt = await new SignJWT({
    aud: "https://maskinporten.no/",
    scope: "svv:kjoretoy/kjoretoyopplysninger",
    resource: "https://www.vegvesen.no",
    iss: env.CLIENT_ID,
    exp: now + 60, // 1 minute from now
    iat: now,
    jti: "jwt-" + crypto.randomUUID()
  })
  .setProtectedHeader({ 
    alg: "RS256",
    x5c: [env.BUSINESS_CERT]
  })
  .sign(privateKey);
  
  return jwt;
}

async function getAccessToken(jwt, env) {
  const response = await fetch("https://maskinporten.no/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${error}`);
  }
  
  const data = await response.json();
  return data.access_token;
}

async function getVehicleData(token, registrationNumber, env) {
  const response = await fetch("https://akfell-datautlevering.atlas.vegvesen.no/kjoretoyoppslag/bulk/kjennemerke", {
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