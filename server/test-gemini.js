require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function testGemini() {
  console.log('--- Testing Gemini API Connection ---');
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey.trim() === '' || apiKey === 'your_gemini_api_key_here') {
    console.error('❌ Error: GEMINI_API_KEY is not set in server/.env');
    console.log('\nTo set it:');
    console.log('1. Open server/.env');
    console.log('2. Add your key: GEMINI_API_KEY=AIzaSy...');
    console.log('3. Re-run: node test-gemini.js');
    process.exit(1);
  }

  const modelName = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  console.log(`Using model: ${modelName}`);
  console.log(`API Key detected: ${apiKey.slice(0, 6)}...${apiKey.slice(-4)}`);

  try {
    const ai = new GoogleGenAI({ apiKey });
    console.log('Sending test prompt to Gemini...');
    
    const startTime = Date.now();
    const response = await ai.models.generateContent({
      model: modelName,
      contents: 'Respond with the exact phrase: "Gemini API connection confirmed."',
    });

    const elapsed = Date.now() - startTime;
    console.log(`\n✅ Success! Received response in ${elapsed}ms:`);
    console.log('--------------------------------------------------');
    console.log(response.text);
    console.log('--------------------------------------------------');
  } catch (error) {
    console.error('\n❌ Gemini API Call Failed:');
    if (error.status) console.error(`Status code: ${error.status}`);
    if (error.message) console.error(`Error message: ${error.message}`);
    console.error(error);
  }
}

testGemini();
