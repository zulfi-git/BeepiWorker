
// Simple test script
import fetch from 'node-fetch';

async function testWorker() {
  try {
    const response = await fetch('http://0.0.0.0:8787', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        registrationNumber: "AB12345"
      })
    });
    
    const data = await response.json();
    console.log('Response:', data);
  } catch (error) {
    console.error('Error:', error);
  }
}

testWorker();
