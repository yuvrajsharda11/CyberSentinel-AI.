"""Local OCR and QR analysis for screenshots and other images.

This module extracts visible text and QR payloads. It does not execute image
content, open links, or send data to an external service. Findings are
heuristics for analyst review, not a trained visual phishing classifier.
"""
from __future__ import annotations

import io
import re

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError

from services.url_detector import analyze_url

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
PHISHING_CUES = (
    "verify your account", "confirm your password", "sign in to continue",
    "account suspended", "unusual activity", "urgent action required",
    "payment failed", "update your credentials", "your account will be closed",
)


def _extract_urls(text: str) -> list[str]:
    urls = []
    for match in URL_PATTERN.findall(text or ""):
        cleaned = match.rstrip(".,;:!?)]}")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls[:25]


def _decode_qr(image: Image.Image) -> list[str]:
    rgb = np.asarray(image.convert("RGB"))
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    try:
        ok, decoded, _points, _ = detector.detectAndDecodeMulti(bgr)
        if ok:
            return list(dict.fromkeys(item.strip() for item in decoded if item and item.strip()))[:25]
    except (cv2.error, AttributeError, ValueError):
        pass
    try:
        value, _points, _ = detector.detectAndDecode(bgr)
        return [value.strip()] if value and value.strip() else []
    except cv2.error:
        return []


def analyze_image(name: str, data: bytes) -> dict:
    """Analyze an image locally using OCR, QR decoding, and URL checks."""
    if not data:
        return {"error": "The uploaded image is empty."}
    if len(data) > MAX_IMAGE_BYTES:
        return {"error": "Image is larger than the 10 MB analysis limit."}

    try:
        with Image.open(io.BytesIO(data)) as source:
            if source.width * source.height > MAX_IMAGE_PIXELS:
                return {"error": "Image dimensions exceed the 20-megapixel safety limit."}
            source.verify()
        with Image.open(io.BytesIO(data)) as source:
            image = ImageOps.exif_transpose(source).convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        return {"error": "Could not safely read this image. Try a PNG or JPEG screenshot."}

    qr_payloads = _decode_qr(image)
    ocr_error = None
    try:
        text = pytesseract.image_to_string(image, timeout=20).strip()
    except (pytesseract.TesseractNotFoundError, pytesseract.TesseractError, RuntimeError) as exc:
        text = ""
        ocr_error = "OCR is unavailable. Install the Tesseract OCR engine to extract text."

    ocr_urls = _extract_urls(text)
    all_urls = list(dict.fromkeys(ocr_urls + [item for item in qr_payloads
                                             if item.lower().startswith(("http://", "https://"))]))[:25]
    url_results = [{"url": url, **analyze_url(url)} for url in all_urls]
    indicators = []
    text_lower = text.lower()
    cue_hits = [cue for cue in PHISHING_CUES if cue in text_lower]
    if cue_hits:
        indicators.append("Urgent or account-verification wording detected: " + ", ".join(cue_hits[:5]))
    if qr_payloads:
        indicators.append(f"Decoded {len(qr_payloads)} QR code(s); review the payload before opening it.")
    if any(not item.lower().startswith(("http://", "https://")) for item in qr_payloads):
        indicators.append("At least one QR code contains non-URL text or a different link scheme.")
    if any(item.get("risk_score", 0) >= 40 for item in url_results):
        indicators.append("An extracted URL received a medium-or-higher risk score from the URL analyzer.")

    score = max([item.get("risk_score", 0) for item in url_results] + ([20] if cue_hits else [0]))
    return {
        "filename": name,
        "size_bytes": len(data),
        "image_dimensions": f"{image.width} × {image.height}",
        "risk_score": int(score),
        "analysis_method": "Local OCR, QR decoding, and URL heuristics",
        "ocr_text": text[:12_000],
        "ocr_truncated": len(text) > 12_000,
        "ocr_error": ocr_error,
        "qr_payloads": qr_payloads,
        "extracted_urls": ocr_urls,
        "url_results": url_results,
        "indicators": indicators,
        "limitations": [
            "This is not a trained visual phishing classifier and may miss image-based tricks.",
            "OCR can misread text; inspect the original image and verify links independently.",
            "QR payloads are displayed only; they are never opened automatically.",
        ],
    }
