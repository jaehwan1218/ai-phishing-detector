"""
화이트리스트(안심 사이트) 관리 모듈
- 사용자가 등록한 안전 URL을 whitelist.txt 에 누적 저장한다.
- 프로그램 시작 시 파일을 읽어 도메인 단위로 매칭하며, 등록된 사이트는
  크롤링·AI 분류·위협 피드 대조를 모두 생략하고 즉시 'Pass' 처리한다.
- 모든 파일 I/O는 예외 처리되어 실패해도 프로그램이 멈추지 않는다.
"""

import threading
from urllib.parse import urlparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
WHITELIST_PATH = BASE_DIR / "whitelist.txt"

_LOCK = threading.Lock()


def _domain(url: str) -> str:
    """URL에서 도메인만 추출 (www. 제거, 소문자)."""
    try:
        u = (url or "").strip()
        if not u.startswith("http"):
            u = "https://" + u
        netloc = urlparse(u).netloc.lower().strip()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return (url or "").lower().strip()


def load_whitelist() -> list:
    """whitelist.txt 의 원본 URL 목록을 읽어온다 (없으면 빈 리스트)."""
    urls = []
    if not WHITELIST_PATH.exists():
        return urls
    try:
        with open(WHITELIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except Exception:
        pass
    return urls


def whitelist_domains() -> set:
    """등록된 URL들을 도메인 집합으로 반환 (빠른 매칭용)."""
    return {_domain(u) for u in load_whitelist() if _domain(u)}


def is_whitelisted(url: str, domains: set = None) -> bool:
    """URL이 화이트리스트에 있는지 도메인 단위로 확인."""
    dom = _domain(url)
    if not dom:
        return False
    if domains is None:
        domains = whitelist_domains()
    return dom in domains


def add_to_whitelist(url: str):
    """
    URL을 화이트리스트에 추가.
    반환: (성공여부: bool, 안내메시지: str)
    """
    url = (url or "").strip()
    if not url:
        return False, "등록할 URL이 없습니다"
    dom = _domain(url)
    if not dom or "." not in dom:
        return False, "올바른 URL이 아닙니다"
    if dom in whitelist_domains():
        return False, f"이미 등록된 안심 사이트입니다 ({dom})"
    try:
        with _LOCK:
            with open(WHITELIST_PATH, "a", encoding="utf-8") as f:
                f.write(url + "\n")
        return True, f"안심 사이트로 등록되었습니다 ({dom})"
    except Exception as e:
        return False, f"저장 실패: {e}"
