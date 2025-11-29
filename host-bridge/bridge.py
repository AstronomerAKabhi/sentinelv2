#!/usr/bin/env python3
import sys
import json
import struct
import subprocess
import os
import requests

LIMA_INSTANCE = "local"
REMOTE_BINARY_PATH = os.path.expanduser("~/sentinel_v2/linux-backend/target/release/sentinel_cli")

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('=I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message):
    encoded_content = json.dumps(message).encode('utf-8')
    encoded_length = struct.pack('=I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def run_remote_scan(payload):
    cmd = [REMOTE_BINARY_PATH]
    
    env = os.environ.copy()
    env["VT_API_KEY"] = "5544106b4abff975881f81a0ef8c9d547f8fc213b57c73561c9af1679583f3eb"
    env["HF_TOKEN"] = "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"
    
def handle_message(message):
    target = message.get("target", "")
    action = message.get("action", "scan")
    
    is_url = target.startswith("http://") or target.startswith("https://")
    
    if is_url:
        result = scan_url(target)
    else:
        result = scan_file(target)
    
    send_message(result)

def scan_url(url):
    import requests
    
    HF_TOKEN = "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"
    
    safe_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'netflix.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org'
    ]
    
    domain = url.split('/')[2] if len(url.split('/')) > 2 else url
    is_whitelisted = any(safe in domain.lower() for safe in safe_domains)
    
    if is_whitelisted:
        return {
            "status": "ANALYZED",
            "details": f"Domain {domain} is on the trusted whitelist",
            "isolation_method": "whitelist_check",
            "threat_score": {
                "level": "LOW",
                "score": 5,
                "confidence": 0.95,
                "indicators": ["Verified legitimate domain", "On whitelist"]
            },
            "timestamp": int(__import__('time').time())
        }
    
    api_url = "https://router.huggingface.co/v1/chat/completions"
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    
    payload = {
        "model": "google/gemma-2-2b-it",
        "messages": [{"role": "user", "content": f"Analyze this URL for phishing: {url}. Reply with MALICIOUS or SAFE."}],
        "max_tokens": 100
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            llm_response = data['choices'][0]['message']['content']
            
            is_malicious = "MALICIOUS" in llm_response.upper()
            
            score = 0
            indicators = []
            confidence = 0.6
            
            if is_malicious:
                score += 50
                indicators.append("LLM flagged as potentially suspicious")
                confidence = 0.75
            else:
                indicators.append("LLM analysis: appears safe")
            
            suspicious_patterns = ['verify', 'suspend', 'urgent', 'confirm', 'secure-account']
            if any(pattern in url.lower() for pattern in suspicious_patterns):
                score += 30
                indicators.append("URL contains high-risk keywords")
            
            if url.startswith('http://'):
                score += 15
                indicators.append("No HTTPS encryption")
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
            if any(tld in url.lower() for tld in suspicious_tlds):
                score += 25
                indicators.append("Suspicious top-level domain")
            
            if score < 30:
                level = "LOW"
            elif score < 70:
                level = "MEDIUM"
            else:
                level = "HIGH"
            
            return {
                "status": "ANALYZED",
                "details": f"LLM Analysis: {llm_response[:200]}",
                "isolation_method": "llm_analysis",
                "threat_score": {
                    "level": level,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators
                },
                "timestamp": int(data['created'])
            }
        else:
            return {
                "status": "error",
                "details": f"LLM API error: {response.status_code}"
            }
    except Exception as e:
        return {
            "status": "error",
            "details": f"URL scan error: {str(e)}"
        }

def scan_file(file_path):
    import subprocess
    
    binary_path = os.path.expanduser("~/sentinel_v2/linux-backend/target/release/sentinel_cli")
    cmd = [binary_path, "--path", file_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout
            json_start = output.rfind('{')
            
            if json_start != -1:
                brace_count = 0
                for i in range(json_start, len(output)):
                    if output[i] == '{':
                        brace_count += 1
                    elif output[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = output[json_start:i+1]
                            return json.loads(json_str)
            
            return {
                "status": "error",
                "details": "No valid JSON in output"
            }
        else:
            return {
                "status": "error",
                "details": result.stderr or "File scan failed",
                "code": result.returncode
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "details": "File scan timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "details": f"Scan error: {str(e)}"
        }

def main():
    while True:
        message = read_message()
        if not message:
            break
        handle_message(message)

if __name__ == "__main__":
    main()
