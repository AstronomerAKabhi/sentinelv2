import os
from playwright.sync_api import sync_playwright
import pytesseract
from PIL import Image

def capture_screenshot(url, output_path="/tmp/screenshot.png"):
    """Capture screenshot of a URL using Playwright"""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=60000, wait_until="domcontentloaded")
            page.screenshot(path=output_path)
            browser.close()
        return output_path
    except Exception as e:
        print(f"Screenshot failed: {e}")
        return None

def extract_text(image_path):
    """Extract text from image using Tesseract OCR"""
    try:
        return pytesseract.image_to_string(Image.open(image_path))
    except Exception as e:
        print(f"OCR failed: {e}")
        return ""
