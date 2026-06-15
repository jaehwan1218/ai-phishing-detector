"""
특징 추출 모듈 - URL 구조 분석 및 이메일 TF-IDF 벡터화
"""

import re
import unicodedata
import numpy as np
from urllib.parse import urlparse


# ═════════════════════════════════════════════════════════════
# [신규] 우회(Obfuscation) 정제 / 텍스트 표준화 전처리
#   - 악성 도메인·스팸이 필터를 우회하려고 쓰는 변종 텍스트를
#     모델이 학습/탐지하기 전에 표준형(canonical form)으로 정규화한다.
#   - 학습(trainer.prepare_features)과 예측(predict_email) 양쪽에서
#     동일하게 호출되어야 효과가 있다.
# ═════════════════════════════════════════════════════════════

# 1) 보이지 않는 문자(제로폭 공백, BOM, 결합문자 등) — 단어를 쪼개는 데 악용됨
_INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\u17b4\u17b5\u115f\u1160\u3164\uffa0]"
)

# 2) 단어 '사이'에 억지로 끼워 넣는 우회용 구분자(filler) 문자 집합
#    예) 성*인 → 성인,  광_고 → 광고,  f*r*e*e → free,  v.e-r.i.f-y → verify
#    한글/영문/숫자(\w) '사이'에 낀 경우에만 제거하므로 정상 문장은 보존된다.
_FILLER_CHARS = r"*@_~^|+=.\-·•∙⋅・･．。'\"`!?#$%&/\\:;,()\[\]{}<>＊＿－"
_FILLER_BETWEEN_RE = re.compile(rf"(?<=\w)[{_FILLER_CHARS}\s]*?[{_FILLER_CHARS}]+(?=\w)")
# 공백을 사이에 둔 병합은 '끼워넣기 전용' 문자에만 적용한다.
# (마침표·쉼표·물음표 등 정상 문장부호는 제외 → 'A. B' 같은 정상문 보존)
_FILLER_TIGHT = r"*@_~^|+=·•∙⋅・･＊＿"
_FILLER_SPACED_RE = re.compile(rf"(?<=\w)\s*[{_FILLER_TIGHT}]+\s*(?=\w)")

# 3) 한글 호환 자모(분리된 자음/모음) → 음절 재결합용 테이블
#    예) 'ㅅㅓㅇㅇㅣㄴ' → '성인'
_CHO = list("ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ")
_JUNG = list("ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ")
_JONG = list(" ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ")  # index 0 = 받침 없음
_CHO_IDX = {c: i for i, c in enumerate(_CHO)}
_JUNG_IDX = {c: i for i, c in enumerate(_JUNG)}
_JONG_IDX = {c: i for i, c in enumerate(_JONG) if c != " "}


def _compose_jamo(text: str) -> str:
    """분리된 한글 호환 자모(ㅅ ㅓ ㅇ …)를 음절(성)로 best-effort 재결합."""
    out = []
    i, n = [], len(text)
    idx = 0
    while idx < n:
        ch = text[idx]
        # 초성 후보 + 중성 후보가 연속하면 음절로 합친다
        if ch in _CHO_IDX and idx + 1 < n and text[idx + 1] in _JUNG_IDX:
            L = _CHO_IDX[ch]
            V = _JUNG_IDX[text[idx + 1]]
            T = 0
            consumed = 2
            # 종성 후보가 있고, 그 다음이 또 다른 중성이 아니면 종성으로 흡수
            if (idx + 2 < n and text[idx + 2] in _JONG_IDX and
                    not (idx + 3 < n and text[idx + 3] in _JUNG_IDX)):
                T = _JONG_IDX[text[idx + 2]]
                consumed = 3
            out.append(chr(0xAC00 + (L * 21 + V) * 28 + T))
            idx += consumed
        else:
            out.append(ch)
            idx += 1
    return "".join(out)


def normalize_text(text: str) -> str:
    """
    우회용 변종 텍스트를 표준형으로 정제한다. (이메일/스팸 본문용)

    처리 순서:
      1. 유니코드 NFKC 정규화 (전각→반각, 호환문자 통일)
      2. 제로폭/보이지 않는 문자 제거
      3. 분리된 한글 자모 음절 재결합 (ㅅㅓㅇㅇㅣㄴ → 성인)
      4. 단어 사이에 낀 우회용 특수문자 제거 (성*인 → 성인, 광_고 → 광고)
      5. 공백 정리 + 소문자화

    주의: 느낌표 수·대문자 비율·URL 수 등 '원문' 신호가 필요한 메타 특징은
          원문(text)에서 따로 계산하고, 키워드/TF-IDF 매칭에만 이 정제본을 쓴다.
    """
    if not text:
        return ""
    # 1. 보이지 않는 문자 제거 (자모를 쪼개는 데 악용되는 채움문자 포함)
    text = _INVISIBLE_RE.sub("", text)
    # 2. 분리된 한글 호환 자모 재결합 (NFKC보다 먼저 — NFKC가 자모를 부분
    #    결합/변형시키기 전에 원본 호환 자모 상태에서 처리해야 정확하다)
    text = _compose_jamo(text)
    # 3. 유니코드 NFKC 정규화 (전각→반각, 호환문자 통일, 남은 자모 정리)
    text = unicodedata.normalize("NFKC", text)
    # 4. 단어 사이 우회용 특수문자 제거 (성*인 → 성인, 두 번 적용해 연쇄 처리)
    text = _FILLER_SPACED_RE.sub("", text)
    text = _FILLER_BETWEEN_RE.sub("", text)
    # 5. 공백 정리
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def obfuscation_score(text: str) -> int:
    """원문이 정제 과정에서 얼마나 변형됐는지(우회 강도) = 길이 차이.
    값이 클수록 필러 문자/제로폭/자모분리가 많이 사용된 의심스러운 텍스트."""
    if not text:
        return 0
    cleaned = normalize_text(text).replace(" ", "")
    raw = re.sub(r"\s+", "", text.lower())
    return max(0, len(raw) - len(cleaned))


# ─── URL 도메인 랜덤화(계속 바뀌는 도메인) 탐지용 ───
_RANDOM_LABEL_RE = re.compile(r"[a-z0-9]*\d[a-z0-9]*", re.IGNORECASE)


def domain_randomness_score(url: str) -> float:
    """
    도메인 라벨에 무작위 영숫자/숫자가 섞여 '계속 도메인을 바꾸는' 패턴을 점수화.
    예) verify-account-9f3k21.xyz, secure-login-x7q2.info
    반환: 0.0(정상) ~ 1.0(매우 의심) 사이의 연속값.
    """
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = parsed.hostname or ""
    except Exception:
        return 0.0
    if not host:
        return 0.0

    labels = host.split(".")
    suspicious = 0.0
    checked = 0
    for label in labels:
        # 끝의 하이픈 토큰까지 포함해 세부 토큰으로 분해
        for tok in re.split(r"[-_]", label):
            if not tok:
                continue
            checked += 1
            digits = sum(c.isdigit() for c in tok)
            digit_ratio = digits / len(tok)
            # 길고 숫자가 섞인 토큰 = 랜덤 생성 도메인 의심
            if len(tok) >= 5 and digits >= 2 and digit_ratio >= 0.25:
                suspicious += 1.0
            elif digit_ratio >= 0.5 and len(tok) >= 3:
                suspicious += 0.6
    if checked == 0:
        return 0.0
    return round(min(1.0, suspicious / checked + (0.3 if suspicious > 0 else 0)), 4)


def normalize_url(url: str) -> str:
    """
    URL을 표준화한다: 소문자화 + 도메인 라벨 뒤에 붙은 무작위 숫자/영숫자
    꼬리를 표준 토큰('<rnd>')으로 치환해, 도메인을 매번 바꾸는 우회를 무력화.
    (구조적 특징은 원본 URL에서 추출하고, 키워드 비교에는 이 표준형을 쓴다.)
    """
    if not url:
        return ""
    u = url.strip().lower()
    # 도메인 라벨 끝의 -랜덤숫자/영숫자 꼬리를 치환: secure-login-9f3k2 → secure-login-<rnd>
    u = re.sub(r"[-_][a-z0-9]*\d[a-z0-9]*(?=[./?]|$)", "-<rnd>", u)
    return u


# ─────────────────────────────────────────
# URL 구조적 특징 추출
# ─────────────────────────────────────────

def extract_url_features(url: str) -> np.ndarray:
    """
    URL에서 구조적 특징 13개를 수치화하여 반환합니다.
    기획서 항목: 길이, 특수문자(@, -, _), IP 포함 여부, 서브도메인 수 등
    """
    features = []

    # 1. URL 전체 길이
    features.append(len(url))

    # 2. @ 기호 포함 여부 (피싱 URL에 자주 사용)
    features.append(1 if "@" in url else 0)

    # 3. 하이픈(-) 개수
    features.append(url.count("-"))

    # 4. 언더스코어(_) 개수
    features.append(url.count("_"))

    # 5. 점(.) 개수
    features.append(url.count("."))

    # 6. 숫자 개수
    features.append(sum(c.isdigit() for c in url))

    # 7. IP 주소 형태 포함 여부
    ip_pattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    features.append(1 if ip_pattern.search(url) else 0)

    # 8. HTTPS 여부 (0=http, 1=https)
    features.append(1 if url.startswith("https") else 0)

    # 9. 서브도메인 개수
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        subdomains = max(0, len(parts) - 2)
    except Exception:
        subdomains = 0
    features.append(subdomains)

    # 10. URL 경로 길이
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        features.append(len(parsed.path))
    except Exception:
        features.append(0)

    # 11. 쿼리 파라미터 개수
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        features.append(len(parsed.query.split("&")) if parsed.query else 0)
    except Exception:
        features.append(0)

    # 12. 피싱 의심 키워드 포함 여부
    phishing_keywords = [
        "login", "verify", "update", "secure", "account",
        "bank", "paypal", "signin", "confirm", "password",
        "free", "win", "prize", "click", "urgent"
    ]
    # 표준화된 URL에서 매칭 → sec* ure, log-in 같은 우회 키워드도 포착
    url_norm = normalize_url(url)
    url_lower = url.lower()
    keyword_count = sum(
        1 for kw in phishing_keywords if kw in url_lower or kw in url_norm
    )
    features.append(keyword_count)

    # 13. 특수문자 총 개수 (!, ?, =, &, % 등)
    special_chars = sum(1 for c in url if c in "!?=&%#$~")
    features.append(special_chars)

    # 14. [신규] 도메인 랜덤화 점수 (계속 바뀌는 무작위 숫자 꼬리 도메인 탐지)
    features.append(domain_randomness_score(url))

    return np.array(features, dtype=float)


URL_FEATURE_NAMES = [
    "URL 길이", "@ 포함", "하이픈(-) 수", "언더스코어(_) 수",
    "점(.) 수", "숫자 수", "IP 주소 형태", "HTTPS 여부",
    "서브도메인 수", "경로 길이", "쿼리 파라미터 수",
    "피싱 키워드 수", "특수문자 수", "도메인 랜덤화 점수"
]


# ─────────────────────────────────────────
# 이메일 피싱 키워드 분석 (보조 특징)
# ─────────────────────────────────────────

PHISHING_EMAIL_KEYWORDS = [
    "urgent", "verify", "account", "suspend", "click",
    "password", "update", "confirm", "login", "bank",
    "prize", "winner", "free", "limited", "immediately",
    "action required", "security alert", "unusual activity",
    "dear customer", "credit card", "ssn", "social security",
]


def extract_email_meta_features(text: str) -> np.ndarray:
    """이메일 텍스트에서 피싱 키워드 기반 보조 특징 추출.

    키워드 매칭은 우회 정제본(normalize_text)에서 수행해
    '성*인', '광_고', 'v e r i f y' 같은 변종도 포착한다.
    느낌표 수·대문자 비율·URL 수는 '원문' 신호이므로 원문에서 계산한다.
    """
    cleaned = normalize_text(text)            # 우회 정제본 (키워드 매칭용)
    text_lower = text.lower()                 # 원문 소문자
    features = []

    # 피싱 키워드 총 등장 횟수 (정제본 + 원문 중 더 많이 잡힌 쪽)
    total_hits = sum(
        max(cleaned.count(kw), text_lower.count(kw))
        for kw in PHISHING_EMAIL_KEYWORDS
    )
    features.append(total_hits)

    # URL 포함 여부 (원문 기준)
    url_count = len(re.findall(r"https?://\S+", text))
    features.append(url_count)

    # 느낌표 개수 (원문 기준)
    features.append(text.count("!"))

    # 대문자 비율 (원문 기준)
    alpha = [c for c in text if c.isalpha()]
    upper_ratio = sum(1 for c in alpha if c.isupper()) / max(len(alpha), 1)
    features.append(round(upper_ratio, 4))

    # 전체 텍스트 길이 (원문 기준)
    features.append(len(text))

    # [신규] 우회 강도 점수: 정제로 제거된 필러/제로폭/자모분리 문자 수
    features.append(obfuscation_score(text))

    return np.array(features, dtype=float)
