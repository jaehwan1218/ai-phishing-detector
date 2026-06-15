"""
공식 사이버위협 인텔리전스 피드 연동 모듈 (OpenPhish 기반)

연동 피드:
  - OpenPhish — 실시간 피싱 URL 공개 피드 (무료, API 키 불필요)
    https://openphish.com

신고 기관:
  - KISA 118    : https://www.krcert.or.kr
  - 방통심의위  : https://www.kocsc.or.kr
  - 경찰청      : https://ecrm.police.go.kr
"""

import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path

import requests

# ─── 경로 ───────────────────────────────────────────
BASE_DIR        = Path(__file__).parent.parent
CACHE_DIR       = BASE_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)
BLOCKLIST_CACHE = CACHE_DIR / "blocklist.json"
CACHE_TTL_HOURS = 24

HEADERS = {"User-Agent": "Mozilla/5.0 (security-research-tool/1.0)"}
OPENPHISH_FEED = "https://openphish.com/feed.txt"


# ══════════════════════════════════════════════════════
# 피드 수신
# ══════════════════════════════════════════════════════

def fetch_openphish() -> tuple[list[dict], str]:
    """
    OpenPhish 무료 공개 피드 수신.
    실시간 피싱 URL 목록 (API 키 불필요).
    """
    try:
        resp = requests.get(OPENPHISH_FEED, headers=HEADERS, timeout=20)
        if resp.status_code != 200:
            return [], f"OpenPhish HTTP {resp.status_code}"

        urls = [u.strip() for u in resp.text.splitlines()
                if u.strip().startswith("http")]
        entries = [
            {
                "url":        u,
                "threat":     "phishing",
                "tags":       ["phishing"],
                "date_added": datetime.now().strftime("%Y-%m-%d"),
                "source":     "OpenPhish",
            }
            for u in urls
        ]
        return entries, f"OpenPhish: {len(entries)}건 수신"
    except Exception as e:
        return [], f"OpenPhish 오류: {e}"


# ══════════════════════════════════════════════════════
# 캐시 관리
# ══════════════════════════════════════════════════════

def _cache_fresh() -> bool:
    if not BLOCKLIST_CACHE.exists():
        return False
    mtime = datetime.fromtimestamp(BLOCKLIST_CACHE.stat().st_mtime)
    return datetime.now() - mtime < timedelta(hours=CACHE_TTL_HOURS)


def load_cached_blocklist() -> list[dict]:
    if not BLOCKLIST_CACHE.exists():
        return []
    with open(BLOCKLIST_CACHE, encoding="utf-8") as f:
        return json.load(f).get("entries", [])


def _save_cache(entries: list[dict]):
    with open(BLOCKLIST_CACHE, "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": datetime.now().isoformat(),
            "count":      len(entries),
            "entries":    entries,
        }, f, ensure_ascii=False, indent=2)


def refresh_blocklist(force: bool = False) -> tuple[list[dict], str]:
    """
    차단 목록 갱신 (캐시 유효 시 생략, force=True면 강제 갱신).
    반환: (entries, status_message)
    """
    if not force and _cache_fresh():
        entries = load_cached_blocklist()
        return entries, f"캐시 유효 ({len(entries):,}건) — {CACHE_TTL_HOURS}h 이내 자동 갱신"

    entries, msg = fetch_openphish()

    # 중복 제거
    seen, unique = set(), []
    for e in entries:
        u = e.get("url", "")
        if u and u not in seen:
            seen.add(u)
            unique.append(e)

    if unique:
        _save_cache(unique)

    status = f"{msg}  →  총 {len(unique):,}건 저장"
    return unique, status


# ══════════════════════════════════════════════════════
# 차단 목록 대조
# ══════════════════════════════════════════════════════

def _domain(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "https://" + url
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def check_against_blocklist(url: str) -> dict:
    """
    URL을 캐시된 차단 목록과 대조.
    반환: {matched, matched_entry, match_type, source}
    """
    entries   = load_cached_blocklist()
    url_norm  = url.strip().lower()
    input_dom = _domain(url)

    for entry in entries:
        bl = entry.get("url", "").strip().lower()

        if url_norm == bl:                          # 완전 일치
            return {"matched": True, "matched_entry": entry,
                    "match_type": "exact", "source": entry.get("source", "")}

        if input_dom and input_dom == _domain(bl):  # 도메인 일치
            return {"matched": True, "matched_entry": entry,
                    "match_type": "domain", "source": entry.get("source", "")}

    return {"matched": False, "matched_entry": None,
            "match_type": "none", "source": ""}


# ══════════════════════════════════════════════════════
# 통계
# ══════════════════════════════════════════════════════

def get_blocklist_stats() -> dict:
    if not BLOCKLIST_CACHE.exists():
        return {"total": 0, "updated_at": None, "by_source": {}}
    with open(BLOCKLIST_CACHE, encoding="utf-8") as f:
        data = json.load(f)
    entries   = data.get("entries", [])
    by_source = {}
    for e in entries:
        s = e.get("source", "unknown")
        by_source[s] = by_source.get(s, 0) + 1
    return {
        "total":      data.get("count", len(entries)),
        "updated_at": data.get("updated_at", ""),
        "by_source":  by_source,
    }
