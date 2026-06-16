"""
불법 사이트 분류 분석기
URL 구조 + 텍스트 키워드 + 이미지 해시 수 → 카테고리 + 신뢰도 점수
"""

import re
from urllib.parse import urlparse
from model.keywords import (
    CATEGORIES, URL_PATTERNS, TEXT_KEYWORDS,
    SUSPICIOUS_TLDS, CATEGORY_COLORS, CATEGORY_ICONS,
)


# ─────────────────────────────────────────
# URL 구조 분석
# ─────────────────────────────────────────

def analyze_url_structure(url: str) -> dict:
    """URL 자체에서 카테고리별 패턴 점수 계산"""
    url_lower = url.lower()
    scores = {cat: 0 for cat in CATEGORIES}

    for cat, patterns in URL_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in url_lower:
                scores[cat] += 2   # URL 적중은 가중치 2

    # 의심 TLD 보너스
    try:
        tld = "." + urlparse(url).netloc.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            for cat in scores:
                scores[cat] += 1
    except Exception:
        pass

    return scores


# ─────────────────────────────────────────
# 텍스트 키워드 분석
# ─────────────────────────────────────────

def analyze_text(text: str, title: str = "", meta: str = "") -> dict:
    """페이지 텍스트에서 카테고리별 키워드 점수 계산"""
    combined = (title + " " + meta + " " + text).lower()
    scores = {cat: 0 for cat in CATEGORIES}
    matched = {cat: [] for cat in CATEGORIES}

    for cat, keywords in TEXT_KEYWORDS.items():
        for kw in keywords:
            count = combined.count(kw.lower())
            if count > 0:
                scores[cat] += count
                matched[cat].append((kw, count))

    # 제목/메타에서 발견 시 가중치 추가
    title_meta = (title + " " + meta).lower()
    for cat, keywords in TEXT_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in title_meta:
                scores[cat] += 3   # 제목·메타 적중 가중치

    return scores, matched


# ─────────────────────────────────────────
# 이미지 신호 분석
# ─────────────────────────────────────────

def analyze_images(image_hashes: list) -> dict:
    """
    이미지 개수와 크기 분포로 성인/도박 사이트 간접 탐지.
    이미지 자체는 저장하지 않고 해시·수량만 사용.
    """
    signals = {cat: 0 for cat in CATEGORIES}

    total = len(image_hashes)
    # 이미지가 매우 많으면 (썸네일 나열형) 불법 OTT·성인 사이트 의심
    if total >= 6:
        signals["illegal_ott"] += 1
        signals["adult"] += 1

    # 대용량 이미지(배너형) 다수 → 도박 사이트 의심
    large = [h for h in image_hashes if h.get("size_kb", 0) > 50]
    if len(large) >= 3:
        signals["gambling"] += 2

    return signals


# ─────────────────────────────────────────
# 종합 분석 → 최종 판정
# ─────────────────────────────────────────

def classify_site(crawl_result: dict, image_hashes: list = None) -> dict:
    """
    URL + 텍스트 + 이미지 신호를 종합하여 최종 카테고리 판정.
    반환: {category, category_name, confidence, scores, matched_keywords, risk_level}
    """
    url = crawl_result.get("url", "")
    text = crawl_result.get("text", "")
    title = crawl_result.get("title", "")
    meta = crawl_result.get("meta_description", "")
    image_hashes = image_hashes or []

    # 1. URL 구조 점수
    url_scores = analyze_url_structure(url)

    # 2. 텍스트 점수
    text_scores, matched_kw = analyze_text(text, title, meta)

    # 3. 이미지 신호
    img_scores = analyze_images(image_hashes)

    # 4. 합산 (URL×2 + 텍스트×1 + 이미지×1)
    total_scores = {}
    for cat in CATEGORIES:
        total_scores[cat] = (
            url_scores[cat] * 2 +
            text_scores[cat] * 1 +
            img_scores[cat] * 1
        )

    max_cat = max(total_scores, key=total_scores.get)
    max_score = total_scores[max_cat]

    # 5. 신뢰도 계산 (0~100%)
    #    점수가 0이면 안전, 최대 점수에 비례하여 신뢰도 상승
    if max_score == 0:
        confidence = 0.0
        category = "safe"
    else:
        # 점수 5 이상이면 확정, 2~4는 의심, 1은 낮음
        raw_conf = min(max_score / 20.0, 1.0)  # 20점 만점 기준
        confidence = round(raw_conf * 100, 1)
        category = max_cat if max_score >= 2 else "safe"

    # 6. 위험 등급
    if confidence >= 70:
        risk_level = "HIGH"
        risk_label = "🚨 고위험"
    elif confidence >= 35:
        risk_level = "MEDIUM"
        risk_label = "⚠️ 의심"
    else:
        risk_level = "LOW"
        risk_label = "✅ 안전"

    # 7. KISA 공식 차단 목록 대조 (캐시 기반, 실패해도 분석 계속)
    kisa_match = {"matched": False, "matched_entry": None,
                  "match_type": "none", "source": ""}
    try:
        from model.kisa_feed import check_against_blocklist
        kisa_match = check_against_blocklist(url)
        # KISA 공식 목록 적중 → 위험도 최대 고정
        if kisa_match["matched"]:
            confidence  = 100.0
            risk_level  = "HIGH"
            risk_label  = "🚨 고위험"
            if category == "safe":
                category = "illegal_ott"   # 기본 카테고리 fallback
    except Exception:
        pass

    return {
        "url": url,
        "category": category,
        "category_name": CATEGORIES.get(category, "안전"),
        "category_icon": CATEGORY_ICONS.get(category, "✅"),
        "category_color": CATEGORY_COLORS.get(category, "#3fb950"),
        "confidence": confidence,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "scores": total_scores,
        "matched_keywords": matched_kw,
        "title": title,
        "meta": meta,
        "image_count": len(image_hashes),
        "url_scores": url_scores,
        "text_scores": text_scores,
        "kisa_matched":       kisa_match["matched"],
        "kisa_match_type":    kisa_match["match_type"],
        "kisa_match_source":  kisa_match["source"],
        "kisa_matched_entry": kisa_match["matched_entry"],
    }
