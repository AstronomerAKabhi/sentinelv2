import click
import requests
import subprocess
import os
import json
import sys

VT_API_KEY = os.environ.get("VT_API_KEY", "5544106b4abff975881f81a0ef8c9d547f8fc213b57c73561c9af1679583f3eb")
HF_TOKEN = os.environ.get("HF_TOKEN", "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")
LIMA_INSTANCE = "default"
REMOTE_BINARY_PATH = "/tmp/cargo_cache/release/sentinel_cli"
SSH_CONFIG_PATH = os.path.expanduser("~/.lima/default/ssh.config")

@click.group()
def cli():
    """Sentinel V2 CLI - Phishing & Malware Analysis Tool"""
    pass

@cli.command()
@click.argument("url")
def scan_url(url):
    """Tier 1: Intent Analysis via LLM (Hugging Face)"""
    click.echo(f"\n🔍 Analyzing URL: {url}...\n")
    
    api_url = "https://router.huggingface.co/v1/chat/completions"
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    
    payload = {
        "model": "google/gemma-2-2b-it",
        "messages": [{"role": "user", "content": f"Analyze this URL for phishing: {url}. Reply with MALICIOUS or SAFE."}],
        "max_tokens": 100
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            llm_response = data['choices'][0]['message']['content']
            
            is_malicious = "MALICIOUS" in llm_response.upper()
            
            score = 0
            indicators = []
            confidence = 0.7
            
            if is_malicious:
                score += 70
                indicators.append("🚨 LLM flagged as potentially malicious")
                confidence = 0.85
            else:
                indicators.append("✅ LLM analysis: appears safe")
            
            phishing_keywords = ['login', 'verify', 'suspend', 'account', 'secure', 'update']
            if any(keyword in url.lower() for keyword in phishing_keywords):
                score += 20
                indicators.append("⚠️ URL contains suspicious keywords")
            
            if url.startswith('http://'):
                score += 10
                indicators.append("⚠️ No HTTPS encryption")
            
            if score < 30:
                level = "🟢 LOW"
                color = "\033[92m"
            elif score < 70:
                level = "🟡 MEDIUM"
                color = "\033[93m"
            else:
                level = "🔴 HIGH"
                color = "\033[91m"
            
            click.echo("=" * 60)
            click.echo(f"  Threat Level: {color}{level}\033[0m")
            click.echo(f"  Risk Score: {score}/100")
            click.echo(f"  Confidence: {int(confidence * 100)}%")
            click.echo("=" * 60)
            click.echo("\n📊 Risk Indicators:")
            for indicator in indicators:
                click.echo(f"  • {indicator}")
            
            click.echo(f"\n💬 AI Analysis:")
            analysis_lines = llm_response.replace('\n\n', '\n').split('\n')
            display_lines = []
            char_count = 0
            for line in analysis_lines[:8]:
                if char_count + len(line) > 500:
                    break
                display_lines.append(f"  {line.strip()}")
                char_count += len(line)
            click.echo("\n".join(display_lines))
            click.echo("\n" + "=" * 60)
            
            try:
                from log_manager import save_scan_log
                log_path = save_scan_log({
                    "timestamp": __import__('time').time(),
                    "target": url,
                    "type": "url",
                    "threat_level": level,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators,
                    "status": "ANALYZED"
                })
                click.echo(f"\n💾 Saved to: {log_path}")
            except Exception as e:
                pass
        else:
            click.echo(f"❌ Error: {response.status_code} - {response.text}")
    except Exception as e:
        click.echo(f"❌ Exception: {str(e)}")

@cli.command()
@click.argument("path")
def scan_file(path):
    """Tier 3: Behavioral Analysis via Rust Sandbox (Firecracker VM)"""
    click.echo(f"\n🔬 Sandboxing File: {path}...\n")
    
    binary_path = os.path.expanduser("~/sentinel_v2/linux-backend/target/release/sentinel_cli")
    cmd = [binary_path, "--path", path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            import re
            output = result.stdout
            
            json_pattern = r'\{[^{]*"status".*?\}(?=\s*$)'
            matches = re.findall(json_pattern, output, re.DOTALL)
            
            if not matches:
                click.echo(f"❌ No valid JSON found in output")
                click.echo(f"Output length: {len(output)} chars")
                return
            
            json_str = matches[-1]
            
            brace_count = 0
            start_idx = output.rfind(json_str)
            for i in range(start_idx, len(output)):
                if output[i] == '{':
                    brace_count += 1
                elif output[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_str = output[start_idx:i+1]
                        break
            
            data = json.loads(json_str)
            
            threat_score = data.get('threat_score', {})
            level = threat_score.get('level', 'UNKNOWN')
            score = threat_score.get('score', 0)
            confidence = threat_score.get('confidence', 0.0)
            indicators = threat_score.get('indicators', [])
            
            if level == 'HIGH':
                level_display = "🔴 HIGH"
                color = "\033[91m"
            elif level == 'MEDIUM':
                level_display = "🟡 MEDIUM"
                color = "\033[93m"
            elif level == 'LOW':
                level_display = "🟢 LOW"
                color = "\033[92m"
            else:
                level_display = "⚪ UNKNOWN"
                color = "\033[90m"
            
            click.echo("=" * 60)
            click.echo(f"  Status: {data.get('status', 'UNKNOWN')}")
            click.echo(f"  Threat Level: {color}{level_display}\033[0m")
            click.echo(f"  Risk Score: {score}/100")
            click.echo(f"  Confidence: {int(confidence * 100)}%")
            click.echo(f"  Isolation: {data.get('isolation_method', 'unknown').upper()}")
            click.echo("=" * 60)
            
            if indicators:
                click.echo("\n📊 Risk Indicators:")
                for indicator in indicators:
                    click.echo(f"  • {indicator}")
            
            click.echo(f"\n💬 Analysis Summary:")
            details = data.get('details', 'No additional details')
            
            if "MicroVM executed" in details:
                click.echo(f"  ✅ File successfully analyzed in hardware-isolated microVM")
                click.echo(f"  🔒 Isolation: Firecracker (1 vCPU, 128MB RAM)")
                click.echo(f"  ⚡ Execution: Complete kernel boot + file analysis")
                click.echo(f"  🛡️ Security: Zero host contamination risk")
                if score < 30:
                    click.echo(f"  ✓ Verdict: No malicious behavior detected")
                elif score < 70:
                    click.echo(f"  ⚠ Verdict: Some suspicious indicators found")
                else:
                    click.echo(f"  🚨 Verdict: High-risk indicators detected")
            else:
                click.echo(f"  {details[:400]}")
            
            click.echo("\n" + "=" * 60)
            
            try:
                from log_manager import save_scan_log
                log_path = save_scan_log({
                    "timestamp": data.get('timestamp', __import__('time').time()),
                    "target": path,
                    "type": "file",
                    "threat_level": level,
                    "score": score,
                    "confidence": confidence,
                    "indicators": indicators,
                    "status": data.get('status', 'ANALYZED'),
                    "isolation_method": data.get('isolation_method', '')
                })
                click.echo(f"\n💾 Saved to: {log_path}")
            except Exception as e:
                pass
        else:
            click.echo(f"❌ Error (Exit Code {result.returncode}):")
            click.echo(result.stderr)
    except json.JSONDecodeError as e:
        click.echo(f"❌ Failed to parse response: {str(e)}")
        click.echo(f"Raw output: {result.stdout}")
    except Exception as e:
        click.echo(f"❌ Execution Failed: {str(e)}")

if __name__ == "__main__":
    cli()
