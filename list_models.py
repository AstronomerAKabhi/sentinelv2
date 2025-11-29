import google.generativeai as genai
import json
import os

try:
    with open('/home/abhi/sentinel_v2/config.json') as f:
        config = json.load(f)
    
    genai.configure(api_key=config['gemini_api_key'])
    
    print("Available Models:")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print(f"Error: {e}")
