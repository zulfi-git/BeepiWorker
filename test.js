
// Simple test script
import fetch from 'node-fetch';

async function testWorker() {
  try {
    const response = await fetch('https://beepi.zhaiden.workers.dev', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://beepi.no'
      },
      body: JSON.stringify({
        registrationNumber: "CU11262"
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Error response:', errorText);
      return;
    }

    const data = await response.json();
    console.log('Response:', data);
  } catch (error) {
    console.error('Error:', error);
  }
}

testWorker();
