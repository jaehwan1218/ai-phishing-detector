"""
공식 실시간 위협 인텔리전스 피드 연동 모듈 (무료 공개 피드 전용)

연동 피드 (전부 무료, API 키·인증 불필요):
  1. OpenPhish          — 실시간 피싱 URL 피드 (https://openphish.com)
  2. Phishing.Database  — 활성 피싱 도메인/링크 (github.com/mitchellkrogza/Phishing.Database)
  3. URLhaus (text)     — 악성 URL 공개 텍스트 피드 (https://urlhaus.abuse.ch)

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

# ─── 피드 정의 ──────────────────────────────────────
FEEDS = {
    "OpenPhish": {
        "url":  "https://openphish.com/feed.txt",
        "kind": "url",          # 전체 URL 목록
        "threat": "phishing",
        # 대형 피드의 부분 수신을 위한 상한 (성능 보호)
        "limit": None,
    },
    "Phishing.Database": {
        "url":  "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "kind": "url",
        "threat": "phishing",
        "limit": 100000,        # 약 79만건 중 상위 10만건만 (메모리/속도 균형)
    },
    "URLhaus": {
        "url":  "https://urlhaus.abuse.ch/downloads/text/",
        "kind": "url",
        "threat": "malware",
        "limit": 100000,
    },
}


# ══════════════════════════════════════════════════════
# 피드 수신
# ══════════════════════════════════════════════════════

def _fetch_feed(name: str, spec: dict) -> tuple[list[dict], str]:
    """단일 피드를 수신하여 표준 항목 리스트로 변환"""
    try:
        resp = requests.get(spec["url"], headers=HEADERS, timeout=20)
        if resp.status_code != 200:
            return [], f"{name}: HTTP {resp.status_code}"

        lines = [
            l.strip() for l in resp.text.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

        # 상한 적용
        limit = spec.get("limit")
        if limit:
            lines = lines[:limit]

        today = datetime.now().strftime("%Y-%m-%d")
        entries = []
        for line in lines:
            # url 종류만 수집 (http로 시작)
            if spec["kind"] == "url" and not line.startswith("http"):
                continue
            entries.append({
                "url":        line,
                "threat":     spec["threat"],
                "tags":       [spec["threat"]],
                "date_added": today,
                "source":     name,
            })
        return entries, f"{name}: {len(entries):,}건"
    except requests.exceptions.Timeout:
        return [], f"{name}: 시간 초과"
    except Exception as e:
        return [], f"{name}: 오류({e})"


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


def _save_cache(entries: list[dict], domain_index: dict):
    with open(BLOCKLIST_CACHE, "w", encoding="utf-8") as f:
        json.dump({
            "updated_at":    datetime.now().isoformat(),
            "count":         len(entries),
            "entries":       entries,
        }, f, ensure_ascii=False)


def refresh_blocklist(force: bool = False, progress_cb=None) -> tuple[list[dict], str]:
    """
    모든 무료 피드를 수신하여 차단 목록을 갱신합니다.
    progress_cb: 진행 상황 콜백 함수 (선택, str 인자 받음)
    반환: (entries, status_message)
    """
    if not force and _cache_fresh():
        entries = load_cached_blocklist()
        return entries, f"캐시 유효 ({len(entries):,}건) — {CACHE_TTL_HOURS}h 이내 자동 갱신"

    all_entries = []
    msgs = []

    for name, spec in FEEDS.items():
        if progress_cb:
            progress_cb(f"{name} 수신 중...")
        entries, msg = _fetch_feed(name, spec)
        all_entries.extend(entries)
        msgs.append(msg)

    # 중복 제거 (URL 기준)
    if progress_cb:
        progress_cb("중복 제거 중...")
    seen, unique = set(), []
    for e in all_entries:
        u = e.get("url", "")
        if u and u not in seen:
            seen.add(u)
            unique.append(e)

    if unique:
        _save_cache(unique, {})

    status = "  |  ".join(msgs) + f"  →  중복제거 후 총 {len(unique):,}건"
    return unique, status


# ══════════════════════════════════════════════════════
# 차단 목록 대조 (도메인 인덱스로 고속 조회)
# ══════════════════════════════════════════════════════

def _domain(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "https://" + url
        netloc = urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


# 모듈 레벨 캐시 (반복 조회 시 매번 파일 안 읽도록)
_BLOCKLIST_MEM   = None
_URL_SET         = None
_DOMAIN_INDEX    = None


def _ensure_index():
    """차단 목록을 메모리에 적재하고 URL dict + 도메인 인덱스 구축"""
    global _BLOCKLIST_MEM, _URL_SET, _DOMAIN_INDEX
    if _URL_SET is not None:
        return
    entries = load_cached_blocklist()
    _BLOCKLIST_MEM = entries
    _URL_SET = {}        # url(소문자) -> entry  (O(1) 완전일치 조회)
    _DOMAIN_INDEX = {}   # domain -> entry       (O(1) 도메인일치 조회)
    for e in entries:
        u = e.get("url", "").strip().lower()
        if not u:
            continue
        _URL_SET[u] = e
        d = _domain(u)
        if d and d not in _DOMAIN_INDEX:
            _DOMAIN_INDEX[d] = e


def invalidate_index():
    """캐시 갱신 후 메모리 인덱스 무효화 (다음 조회 시 재구축)"""
    global _BLOCKLIST_MEM, _URL_SET, _DOMAIN_INDEX
    _BLOCKLIST_MEM = _URL_SET = _DOMAIN_INDEX = None


def check_against_blocklist(url: str) -> dict:
    """
    URL을 차단 목록과 대조 (O(1) 고속 조회).
    반환: {matched, matched_entry, match_type, source}
    """
    _ensure_index()
    if not _URL_SET:
        return {"matched": False, "matched_entry": None,
                "match_type": "none", "source": ""}

    url_norm  = url.strip().lower()
    input_dom = _domain(url)

    # 1. 완전 일치 (dict 조회 O(1))
    e = _URL_SET.get(url_norm)
    if e:
        return {"matched": True, "matched_entry": e,
                "match_type": "exact", "source": e.get("source", "")}

    # 2. 도메인 일치 (dict 조회 O(1))
    if input_dom and input_dom in _DOMAIN_INDEX:
        e = _DOMAIN_INDEX[input_dom]
        return {"matched": True, "matched_entry": e,
                "match_type": "domain", "source": e.get("source", "")}

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
