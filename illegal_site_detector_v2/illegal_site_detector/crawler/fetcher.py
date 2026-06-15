"""
웹 크롤러 모듈
- robots.txt 준수
- 요청 속도 제한 (Rate Limiting)
- 텍스트 + 이미지 해시 수집
"""

import time
import hashlib
import re
import urllib.robotparser
from urllib.parse import urlparse, urljoin
from typing import Optional

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
}

REQUEST_TIMEOUT = 10      # 초
RATE_LIMIT_DELAY = 1.5    # 요청 간 최소 대기 시간(초) — 서버 보호
MAX_IMAGE_FETCH = 8       # 이미지 해시 수집 최대 개수
MAX_TEXT_LEN = 8000       # 텍스트 최대 길이


# ─────────────────────────────────────────
# robots.txt 준수 확인
# ─────────────────────────────────────────

def is_crawlable(url: str) -> bool:
    """robots.txt를 확인하여 크롤링 허용 여부 반환"""
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        return rp.can_fetch(HEADERS["User-Agent"], url)
    except Exception:
        return True  # robots.txt 없으면 허용으로 간주


# ─────────────────────────────────────────
# 페이지 크롤링
# ─────────────────────────────────────────

def fetch_page(url: str) -> dict:
    """
    URL 페이지를 크롤링하여 텍스트, 제목, 메타, 이미지 URL 목록 반환
    robots.txt 위반 시 크롤링 중단.
    """
    result = {
        "url": url,
        "title": "",
        "meta_description": "",
        "text": "",
        "image_urls": [],
        "status_code": None,
        "error": None,
        "crawlable": True,
    }

    # robots.txt 체크
    if not is_crawlable(url):
        result["crawlable"] = False
        result["error"] = "robots.txt에 의해 크롤링 불허"
        return result

    time.sleep(RATE_LIMIT_DELAY)  # Rate Limiting

    try:
        resp = requests.get(url, headers=HEADERS,
                            timeout=REQUEST_TIMEOUT, allow_redirects=True)
        result["status_code"] = resp.status_code

        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        # 인코딩 감지
        resp.encoding = resp.apparent_encoding or "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")

        # 제목
        result["title"] = soup.title.string.strip() if soup.title else ""

        # 메타 description
        meta = soup.find("meta", attrs={"name": "description"})
        if meta:
            result["meta_description"] = meta.get("content", "")

        # 본문 텍스트 (스크립트/스타일 제거)
        for tag in soup(["script", "style", "noscript", "iframe"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        result["text"] = text[:MAX_TEXT_LEN]

        # 이미지 URL 수집 (해시용)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        imgs = []
        for img in soup.find_all("img", src=True):
            src = img["src"]
            if src.startswith("http"):
                imgs.append(src)
            elif src.startswith("//"):
                imgs.append("https:" + src)
            elif src.startswith("/"):
                imgs.append(base + src)
        result["image_urls"] = imgs[:MAX_IMAGE_FETCH]

    except requests.exceptions.Timeout:
        result["error"] = "요청 시간 초과"
    except requests.exceptions.ConnectionError:
        result["error"] = "연결 실패"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────
# 이미지 해시 수집 (콘텐츠 저장 없이 해시만)
# ─────────────────────────────────────────

def fetch_image_hashes(image_urls: list) -> list:
    """
    이미지를 직접 저장하지 않고 MD5 해시값만 수집.
    불법 이미지 소지 문제를 피하기 위한 안전 설계.
    """
    hashes = []
    for img_url in image_urls:
        try:
            time.sleep(0.3)
            resp = requests.get(img_url, headers=HEADERS,
                                timeout=5, stream=True)
            if resp.status_code == 200:
                content = resp.content
                md5 = hashlib.md5(content).hexdigest()
                size = len(content)
                hashes.append({
                    "url": img_url,
                    "md5": md5,
                    "size_kb": round(size / 1024, 1),
                })
        except Exception:
            continue
    return hashes


# ─────────────────────────────────────────
# URL 정규화
# ─────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc or url
    except Exception:
        return url
