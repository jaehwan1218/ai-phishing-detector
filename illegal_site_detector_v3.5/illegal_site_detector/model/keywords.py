"""
카테고리별 탐지 키워드 및 URL 패턴 규칙
"""

# ─────────────────────────────────────────
# 카테고리 정의
# ─────────────────────────────────────────
CATEGORIES = {
    "gambling": "불법 도박",
    "illegal_ott": "불법 OTT·웹툰",
    "illegal_sports": "불법 스포츠 중계",
    "adult": "성인 유해 콘텐츠",
}

# ─────────────────────────────────────────
# URL 패턴 (도메인·경로에서 탐지)
# ─────────────────────────────────────────
URL_PATTERNS = {
    "gambling": [
        "bet", "casino", "poker", "baccarat", "slot", "gamble",
        "toto", "토토", "카지노", "바카라", "슬롯", "배팅", "베팅",
        "먹튀", "승부조작", "스포츠베팅", "불법베팅",
    ],
    "illegal_ott": [
        "누누티비", "nunu", "dramacool", "kshow", "torrent",
        "free-drama", "free-webtoon", "manhwa-free", "toonkor",
        "마나토끼", "밤토끼", "웹툰무료", "dramas-free", "watch-free",
    ],
    "illegal_sports": [
        "무료중계", "실시간중계", "nba-free", "epl-free",
        "sports-live-free", "kbo-free", "live-stream-free",
        "해외축구무료", "스포츠무료", "중계무료",
    ],
    "adult": [
        "porn", "xxx", "adult", "nude", "hentai", "av-",
        "성인", "야동", "19금", "불법촬영", "몰카",
        "음란", "obscene",
    ],
}

# ─────────────────────────────────────────
# 페이지 텍스트 키워드
# ─────────────────────────────────────────
TEXT_KEYWORDS = {
    "gambling": [
        "배팅", "베팅", "카지노", "바카라", "슬롯머신", "포커",
        "토토사이트", "먹튀검증", "충전", "환전", "입금계좌",
        "홀짝", "파워볼", "미니게임", "레이싱걸",
        "bet now", "deposit", "withdraw", "jackpot",
    ],
    "illegal_ott": [
        "무료 다운로드", "무료 스트리밍", "자막 다운", "토렌트",
        "드라마 다시보기", "영화 무료", "웹툰 무료", "만화 무료",
        "최신화 무료", "회원가입 없이", "HD 무료",
        "free download", "watch free", "torrent", "sub download",
    ],
    "illegal_sports": [
        "무료 중계", "실시간 중계", "EPL 무료", "NBA 무료",
        "KBO 무료", "해외축구 무료", "스포츠 생중계 무료",
        "라이브 스트리밍 무료", "중계 사이트",
        "free live", "stream free", "watch live free",
    ],
    "adult": [
        "성인 인증", "19금", "야동", "음란물", "성인물",
        "불법 촬영", "몰카", "야설", "성인 사이트",
        "enter if you are 18", "adult content", "xxx",
        "pornographic", "explicit content",
    ],
}

# ─────────────────────────────────────────
# 위험 TLD (불법 사이트 자주 사용)
# ─────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".pw", ".cc", ".ws", ".top", ".icu",
    ".vip", ".club", ".online", ".site", ".fun",
}

# ─────────────────────────────────────────
# 카테고리별 색상
# ─────────────────────────────────────────
CATEGORY_COLORS = {
    "gambling":       "#f85149",   # 빨강
    "illegal_ott":    "#d29922",   # 주황
    "illegal_sports": "#bc8cff",   # 보라
    "adult":          "#ff6eb4",   # 핑크
    "safe":           "#3fb950",   # 초록
}

CATEGORY_ICONS = {
    "gambling":       "🎰",
    "illegal_ott":    "🎬",
    "illegal_sports": "⚽",
    "adult":          "🔞",
    "safe":           "✅",
}
