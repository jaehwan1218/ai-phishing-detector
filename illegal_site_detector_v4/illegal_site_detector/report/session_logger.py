"""
보안 세션 로그 모듈
- 탐지가 수행될 때마다 security_logs.txt 에 타임스탬프·URL·결과·사유를 실시간 누적 저장.
- 분석은 워커 스레드에서 동시에 일어날 수 있으므로 Lock 으로 파일 쓰기를 직렬화한다.
- 로그 기록 자체가 실패해도(권한·디스크 등) 본 프로그램이 절대 멈추지 않도록 모두 예외 처리한다.

로그 형식 예:
[2026-06-16 14:45:28] URL: http://tvwiki-shelter.co | 결과: 불법·유해 사이트 (이유: 크롤링 타이틀 '티비위키' 매칭 → 불법 OTT·웹툰 차단)
"""

import threading
from datetime import datetime
from pathlib import Path

# 프로젝트 루트 (report/ 의 상위)
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = BASE_DIR / "security_logs.txt"

_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────
# 결과 → 사람이 읽는 판정/사유 문자열
# ─────────────────────────────────────────────────────
def _verdict_text(result: dict) -> str:
    if result.get("category") == "safe" and result.get("risk_level") == "LOW":
        return "정상"
    if result.get("risk_level") == "HIGH":
        return "불법·유해 사이트"
    return "의심"


def _build_reason(result: dict) -> str:
    """탐지 결과 dict 에서 차단/판정 사유를 직관적인 한 줄로 요약한다."""
    # 1순위: 위협 인텔리전스 피드 차단목록 적중
    if result.get("kisa_matched"):
        src = result.get("kisa_match_source", "위협피드") or "위협피드"
        mt = result.get("kisa_match_type", "")
        return f"위협 인텔리전스 차단목록 적중 ({src} {mt})".strip()

    title = (result.get("title") or "").strip()
    cat_name = result.get("category_name", "") or "기타"

    # 매칭된 키워드 상위 몇 개 수집
    kw_bits = []
    for _cat, kws in (result.get("matched_keywords") or {}).items():
        for kw, cnt in kws[:2]:
            kw_bits.append(f"'{kw}'(×{cnt})")
        if len(kw_bits) >= 3:
            break

    # 정상
    if result.get("category") == "safe":
        if title:
            return f"크롤링 타이틀 '{title[:30]}' — 위험 키워드 미검출 (정상)"
        return "위험 신호 미검출 (정상)"

    # 위험/의심
    parts = []
    if title:
        parts.append(f"타이틀 '{title[:30]}'")
    if kw_bits:
        parts.append("키워드 " + ", ".join(kw_bits))
    core = " / ".join(parts) if parts else f"{cat_name} 패턴"
    return f"{core} 매칭 → {cat_name} 차단"


# ─────────────────────────────────────────────────────
# 공개 함수
# ─────────────────────────────────────────────────────
def _write_line(line: str) -> bool:
    """파일에 한 줄 누적 기록. 실패해도 예외를 밖으로 던지지 않는다."""
    try:
        with _LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return True
    except Exception:
        # 로깅 실패가 탐지 기능을 망가뜨리면 안 되므로 조용히 무시
        return False


def log_detection(url: str, result: dict) -> str:
    """탐지 1건을 기록하고, 기록한 로그 문자열을 반환한다."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdict = _verdict_text(result)
    reason = _build_reason(result)
    conf = result.get("confidence", 0)
    line = (f"[{ts}] URL: {url} | 결과: {verdict} "
            f"(신뢰도 {conf}% · 이유: {reason})")
    _write_line(line)
    return line


def log_error(url: str, message: str) -> str:
    """분석 실패(네트워크 단절·잘못된 URL 등)를 기록한다."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    shown = url if url else "(입력 없음)"
    line = f"[{ts}] URL: {shown} | 결과: 분석 실패 (이유: {message})"
    _write_line(line)
    return line


def log_event(message: str) -> str:
    """세션 단위 일반 이벤트(피드 갱신 등)를 기록한다."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] EVENT: {message}"
    _write_line(line)
    return line
