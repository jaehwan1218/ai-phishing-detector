"""
불법·유해 사이트 탐지 시스템 — CustomTkinter 다크 대시보드 (v2.5 UI)
탭 구성: 단일 URL 분석 | 일괄 분석 | 탐지 결과 목록 | KISA 위협정보 | 신고 안내

탐지 로직은 기존 model / crawler / report 모듈을 그대로 사용한다.
이 파일은 UI(테마·레이아웃·여백)만 세련되게 재구성한 버전이다.
"""

import sys
import ctypes
import threading
import queue
from datetime import datetime
from tkinter import ttk, filedialog, messagebox, font as tkfont

import customtkinter as ctk

from urllib.parse import urlparse

from crawler.fetcher import fetch_page, fetch_image_hashes, normalize_url
from model.analyzer import classify_site
from report.generator import generate_csv_report, generate_text_report
from report.session_logger import log_detection, log_error, log_event, LOG_PATH
from model.whitelist import (load_whitelist, add_to_whitelist,
                             is_whitelisted, whitelist_domains, WHITELIST_PATH)


# ════════════════════════════════════════════════════════════════════
#  DPI 인식 (모듈 단독 실행 대비) — 창 생성 전에 한 번 더 보장
# ════════════════════════════════════════════════════════════════════
def _ensure_dpi_awareness():
    if not sys.platform.startswith("win"):
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


_ensure_dpi_awareness()

# CustomTkinter 전역 외형 — 다크 모드 + 블루 베이스
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")
# 위젯 자체 스케일링은 끄고 OS DPI 만 따르게 하여 글자 번짐 방지
try:
    ctk.deactivate_automatic_dpi_awareness()
except Exception:
    pass


# ════════════════════════════════════════════════════════════════════
#  팔레트 — 딥 네이비 기반 보안 콘솔 톤
# ════════════════════════════════════════════════════════════════════
BG_DARK   = "#0b0f17"   # 최하단 배경 (딥 네이비-블랙)
BG_BASE   = "#0e1420"   # 탭 본문 배경
BG_CARD   = "#151c2b"   # 카드
BG_CARD2  = "#1b2436"   # 카드 강조/헤더
BG_INPUT  = "#1a2230"   # 입력창
BORDER    = "#27324a"   # 경계선

ACCENT    = "#3b9eff"   # 네온 블루 (주 강조)
ACCENT_HI = "#1f7fe0"   # 네온 블루 hover
GLOW      = "#5bd1ff"   # 라이트 시안 (포커스/링크)
PASS_DIM  = "#0e2738"   # 안심 사이트(Pass) 배너 배경 틴트 (틸-네이비)

GRN       = "#2fe089"   # 정상 (초록)
GRN_DIM   = "#123524"   # 정상 배너 배경 틴트
RED       = "#ff4d5e"   # 위험 (레드)
RED_DIM   = "#3a121a"   # 위험 배너 배경 틴트
ORG       = "#ffa235"   # 의심 (오렌지)
ORG_DIM   = "#3a2a12"   # 의심 배너 배경 틴트
PURPLE    = "#a98bff"
PINK      = "#ff79c6"

TXT_PRI   = "#e8eef6"   # 기본 텍스트 (밝은 화이트)
TXT_SEC   = "#94a3b8"   # 보조 텍스트 (연한 그레이)
TXT_MUTED = "#5b6675"   # 흐린 텍스트

CAT_COLORS = {
    "gambling":       RED,
    "illegal_ott":    ORG,
    "illegal_sports": PURPLE,
    "adult":          PINK,
    "safe":           GRN,
}

# 여백 상수 — 답답하지 않게 넉넉히
PAD_X = 24
PAD_Y = 14


# ════════════════════════════════════════════════════════════════════
#  폰트 — 가독성 좋은 한글 폰트 자동 선택 + 크기 최적화
# ════════════════════════════════════════════════════════════════════
def _pick_font_family(root) -> str:
    """설치된 폰트 중 가독성 좋은 한글 폰트를 우선순위대로 선택."""
    prefer = ["Pretendard", "Pretendard Variable", "맑은 고딕",
              "Malgun Gothic", "나눔고딕", "NanumGothic",
              "Apple SD Gothic Neo", "Noto Sans KR", "Noto Sans CJK KR"]
    try:
        available = set(tkfont.families(root))
    except Exception:
        available = set()
    for fam in prefer:
        if fam in available:
            return fam
    return "맑은 고딕"   # Windows 기본값으로 폴백


def _pick_mono_family(root) -> str:
    prefer = ["Cascadia Mono", "Cascadia Code", "Consolas",
              "D2Coding", "JetBrains Mono", "Courier New"]
    try:
        available = set(tkfont.families(root))
    except Exception:
        available = set()
    for fam in prefer:
        if fam in available:
            return fam
    return "Consolas"


class IllegalSiteDetector:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.results = []
        self.q = queue.Queue()
        self._current_result = None
        self.whitelist = whitelist_domains()   # 시작 시 안심 사이트 목록 로드

        # ── 폰트 세트 구성 ────────────────────────────────
        fam = _pick_font_family(root)
        mono = _pick_mono_family(root)
        self.f_body  = ctk.CTkFont(family=fam, size=14)
        self.f_bold  = ctk.CTkFont(family=fam, size=14, weight="bold")
        self.f_small = ctk.CTkFont(family=fam, size=12)
        self.f_tiny  = ctk.CTkFont(family=fam, size=11)
        self.f_title = ctk.CTkFont(family=fam, size=18, weight="bold")
        self.f_h2    = ctk.CTkFont(family=fam, size=15, weight="bold")
        self.f_verdict = ctk.CTkFont(family=fam, size=38, weight="bold")
        self.f_icon  = ctk.CTkFont(family=fam, size=40)
        self.f_mono  = ctk.CTkFont(family=mono, size=12)

        root.title("불법·유해 사이트 탐지 시스템")
        root.geometry("1080x760")
        root.minsize(940, 660)
        root.configure(fg_color=BG_DARK)
        self._center(root, 1080, 760)

        self._style_ttk()
        self._build_header()
        self._build_tabs()
        self._poll_queue()

    # ─── 유틸 ────────────────────────────────────────────
    def _center(self, win, w, h):
        win.update_idletasks()
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")

    def _style_ttk(self):
        """Treeview(결과 표)는 ttk 위젯이라 별도로 다크 테마를 입힌다."""
        fam = _pick_font_family(self.root)
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("Dark.Treeview",
                    background=BG_CARD, foreground=TXT_PRI,
                    fieldbackground=BG_CARD, rowheight=30,
                    borderwidth=0, font=(fam, 11))
        s.configure("Dark.Treeview.Heading",
                    background=BG_CARD2, foreground=TXT_SEC,
                    relief="flat", font=(fam, 11, "bold"))
        s.map("Dark.Treeview.Heading", background=[("active", BG_CARD2)])
        s.map("Dark.Treeview",
              background=[("selected", "#22304a")],
              foreground=[("selected", TXT_PRI)])
        s.configure("Dark.Vertical.TScrollbar",
                    background=BG_CARD2, troughcolor=BG_BASE,
                    bordercolor=BG_BASE, arrowcolor=TXT_SEC, relief="flat")

    # ─── 헤더 ────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self.root, fg_color=BG_CARD, corner_radius=0, height=66)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", padx=PAD_X, pady=10)
        ctk.CTkLabel(left, text="🛡", font=self.f_icon, text_color=ACCENT
                     ).pack(side="left", padx=(0, 10))
        title_box = ctk.CTkFrame(left, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="불법·유해 사이트 탐지 시스템",
                     font=self.f_title, text_color=TXT_PRI).pack(anchor="w")
        ctk.CTkLabel(title_box, text="인공지능 개론 기말 프로젝트  ·  v1.0.0",
                     font=self.f_tiny, text_color=TXT_MUTED).pack(anchor="w")

        self.stat_var = ctk.StringVar(value="● 분석 대기 중")
        ctk.CTkLabel(hdr, textvariable=self.stat_var, font=self.f_small,
                     text_color=TXT_SEC).pack(side="right", padx=PAD_X)

    # ─── 탭 컨테이너 ─────────────────────────────────────
    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(
            self.root, fg_color=BG_BASE, corner_radius=12,
            segmented_button_fg_color=BG_CARD,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HI,
            segmented_button_unselected_color=BG_CARD,
            segmented_button_unselected_hover_color=BG_CARD2,
            text_color=TXT_PRI, border_width=0)
        self.tabs.pack(fill="both", expand=True, padx=PAD_X, pady=(12, PAD_X))
        try:
            self.tabs._segmented_button.configure(font=self.f_bold)
        except Exception:
            pass

        t_single = self.tabs.add("🔍  단일 분석")
        t_batch  = self.tabs.add("📋  일괄 분석")
        t_result = self.tabs.add("📊  결과 목록")
        t_kisa   = self.tabs.add("🛰  위협정보")
        t_report = self.tabs.add("📢  신고 안내")
        t_about  = self.tabs.add("ℹ  정보")

        self._build_single_tab(t_single)
        self._build_batch_tab(t_batch)
        self._build_results_tab(t_result)
        self._build_kisa_tab(t_kisa)
        self._build_report_tab(t_report)
        self._build_about_tab(t_about)

    # ════════════════════════════════════════════════════
    #  탭 1: 단일 URL 분석
    # ════════════════════════════════════════════════════
    def _build_single_tab(self, parent):
        parent.configure(fg_color="transparent")

        # ── 입력 카드 ──────────────────────────────────
        in_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER)
        in_card.pack(fill="x", padx=PAD_X, pady=(PAD_Y, 8))

        ctk.CTkLabel(in_card, text="분석할 URL", font=self.f_bold,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(16, 6))

        row = ctk.CTkFrame(in_card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(0, 4))
        self.url_var = ctk.StringVar()
        entry = ctk.CTkEntry(row, textvariable=self.url_var, font=self.f_mono,
                             height=44, corner_radius=10, fg_color=BG_INPUT,
                             border_color=BORDER, border_width=1,
                             text_color=TXT_PRI,
                             placeholder_text="https://example.com")
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self._run_single())
        self.analyze_btn = ctk.CTkButton(
            row, text="분석", font=self.f_bold, width=110, height=44,
            corner_radius=10, fg_color=ACCENT, hover_color=ACCENT_HI,
            text_color="#06121f", command=self._run_single)
        self.analyze_btn.pack(side="left", padx=(10, 0))

        # 예시 칩
        ex = ctk.CTkFrame(in_card, fg_color="transparent")
        ex.pack(fill="x", padx=18, pady=(6, 6))
        ctk.CTkLabel(ex, text="예시", font=self.f_tiny, text_color=TXT_MUTED
                     ).pack(side="left", padx=(0, 8))
        EXAMPLES = [
            ("정상 사이트", "https://www.naver.com"),
            ("도박 패턴", "http://casino-baccarat-bet.xyz/login"),
            ("불법 OTT 패턴", "http://nunutv-free-drama.tk/watch"),
            ("성인 패턴", "http://adult-19-free.ml/enter"),
        ]
        for lbl, url in EXAMPLES:
            ctk.CTkButton(ex, text=lbl, font=self.f_tiny, height=28,
                          corner_radius=14, fg_color=BG_INPUT,
                          hover_color=BG_CARD2, text_color=TXT_SEC,
                          command=lambda u=url: self.url_var.set(u)
                          ).pack(side="left", padx=3)

        # 화이트리스트(안심 사이트) 등록 행
        wl = ctk.CTkFrame(in_card, fg_color="transparent")
        wl.pack(fill="x", padx=18, pady=(0, 14))
        ctk.CTkButton(wl, text="✓ 현재 URL 안심 등록", font=self.f_tiny, height=28,
                      corner_radius=14, fg_color=BG_INPUT, hover_color=BG_CARD2,
                      text_color=GLOW, command=self._register_whitelist
                      ).pack(side="left")
        self.wl_count_var = ctk.StringVar(value="")
        ctk.CTkLabel(wl, textvariable=self.wl_count_var, font=self.f_tiny,
                     text_color=TXT_MUTED).pack(side="left", padx=10)
        self._update_wl_count()

        self.single_status = ctk.StringVar(value="")
        self.single_status_lbl = ctk.CTkLabel(
            parent, textvariable=self.single_status, font=self.f_small,
            text_color=TXT_SEC)
        self.single_status_lbl.pack(anchor="w", padx=PAD_X + 4, pady=(2, 4))

        # ── 판정 배너 (시그니처: 정상=초록 / 위험=대형 레드) ──
        self.verdict_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14,
                                         border_width=1, border_color=BORDER)
        self.verdict_card.pack(fill="x", padx=PAD_X, pady=8)

        vinner = ctk.CTkFrame(self.verdict_card, fg_color="transparent")
        vinner.pack(fill="x", padx=24, pady=20)

        self.verdict_icon = ctk.CTkLabel(vinner, text="—", font=self.f_icon,
                                         text_color=TXT_MUTED, width=64)
        self.verdict_icon.pack(side="left", padx=(0, 18))

        vtext = ctk.CTkFrame(vinner, fg_color="transparent")
        vtext.pack(side="left", fill="x", expand=True)
        self.verdict_main = ctk.CTkLabel(vtext, text="분석 대기", font=self.f_verdict,
                                         text_color=TXT_MUTED, anchor="w")
        self.verdict_main.pack(anchor="w")
        self.verdict_sub = ctk.CTkLabel(vtext, text="URL을 입력하고 분석을 시작하세요",
                                        font=self.f_small, text_color=TXT_SEC, anchor="w")
        self.verdict_sub.pack(anchor="w", pady=(2, 0))

        # 신뢰도 게이지 (우측)
        gauge = ctk.CTkFrame(vinner, fg_color="transparent")
        gauge.pack(side="right", padx=(18, 0))
        ctk.CTkLabel(gauge, text="신뢰도", font=self.f_tiny,
                     text_color=TXT_SEC).pack(anchor="e")
        self.conf_value = ctk.CTkLabel(gauge, text="—", font=self.f_title,
                                       text_color=TXT_PRI)
        self.conf_value.pack(anchor="e")
        self.conf_bar = ctk.CTkProgressBar(gauge, width=180, height=10,
                                           corner_radius=6, fg_color=BG_INPUT,
                                           progress_color=ACCENT)
        self.conf_bar.set(0)
        self.conf_bar.pack(anchor="e", pady=(4, 0))

        # ── 상세 분석 ──────────────────────────────────
        det_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=14,
                                border_width=1, border_color=BORDER)
        det_card.pack(fill="both", expand=True, padx=PAD_X, pady=(8, PAD_Y))

        head = ctk.CTkFrame(det_card, fg_color="transparent")
        head.pack(fill="x", padx=18, pady=(14, 4))
        ctk.CTkLabel(head, text="상세 분석", font=self.f_h2,
                     text_color=TXT_PRI).pack(side="left")
        ctk.CTkButton(head, text="결과 목록에 저장", font=self.f_small, height=32,
                      corner_radius=8, fg_color=BG_INPUT, hover_color=BG_CARD2,
                      text_color=TXT_SEC, command=self._save_current_to_list
                      ).pack(side="right")

        self.detail_text = ctk.CTkTextbox(det_card, font=self.f_mono,
                                          fg_color=BG_INPUT, text_color=TXT_PRI,
                                          corner_radius=10, wrap="word",
                                          border_width=0)
        self.detail_text.pack(fill="both", expand=True, padx=18, pady=(4, 18))
        self.detail_text.configure(state="disabled")

    def _set_single_status(self, text, error=False):
        """하단 안내문구 설정. error=True 면 빨간색으로 표시."""
        self.single_status.set(text)
        try:
            self.single_status_lbl.configure(
                text_color=(RED if error else TXT_SEC))
        except Exception:
            pass

    @staticmethod
    def _validate_url(raw: str):
        """
        입력 URL 검증.
        반환: (정규화된_url, 오류메시지)  — 정상이면 오류메시지는 None.
        """
        if not raw or not raw.strip():
            return None, "URL을 입력해 주세요"

        url = normalize_url(raw.strip())   # scheme 없으면 https:// 자동 추가
        try:
            parsed = urlparse(url)
        except Exception:
            return None, "올바른 URL 주소를 입력해 주세요"

        netloc = parsed.netloc.strip()
        # 도메인에 점(.)이 있어야 하고 공백/유효문자 검사
        if (not netloc) or ("." not in netloc) or (" " in netloc) \
                or netloc.startswith(".") or netloc.endswith("."):
            return None, "올바른 URL 주소를 입력해 주세요  (예: https://example.com)"
        return url, None

    def _set_analyzing(self, on: bool):
        """분석 중에는 버튼을 비활성화하여 연타로 인한 꼬임을 방지."""
        try:
            if on:
                self.analyze_btn.configure(state="disabled", text="분석 중…")
            else:
                self.analyze_btn.configure(state="normal", text="분석")
        except Exception:
            pass

    def _stop_loading_bar(self):
        try:
            self.conf_bar.stop()
            self.conf_bar.configure(mode="determinate")
        except Exception:
            pass

    def _update_wl_count(self):
        try:
            self.wl_count_var.set(f"🛡 등록된 안심 사이트 {len(self.whitelist)}개")
        except Exception:
            pass

    def _register_whitelist(self):
        """입력창의 URL을 화이트리스트에 등록."""
        url, err = self._validate_url(self.url_var.get())
        if err:
            self._set_single_status(f"⚠ 등록 실패: {err}", error=True)
            return
        ok, msg = add_to_whitelist(url)
        self.whitelist = whitelist_domains()    # 메모리 목록 갱신
        self._update_wl_count()
        self._set_single_status(("✓ " if ok else "⚠ ") + msg, error=(not ok))

    def _run_single(self):
        # ── 1. 입력 검증 (빈 값 / 잘못된 형식) ──────────────
        url, err = self._validate_url(self.url_var.get())
        if err:
            self._set_single_status(f"⚠ {err}", error=True)
            self._set_verdict_invalid(err)
            log_error(self.url_var.get().strip(), err)
            return

        # ── 2. 화이트리스트(안심 사이트) → 즉시 Pass, 검사 생략 ──
        if is_whitelisted(url, self.whitelist):
            self._show_whitelist_pass(url)
            return

        # ── 3. 분석 시작: 버튼 비활성화 + 로딩 애니메이션 ──
        self._set_analyzing(True)
        self._set_single_status("🤖 AI 분석 진행 중…  (웹 크롤링 · 위협 피드 대조)")
        self._set_verdict_pending()
        self._set_detail("AI 분석 진행 중입니다. 잠시만 기다려 주세요…")
        threading.Thread(target=self._single_worker, args=(url,), daemon=True).start()

    def _show_whitelist_pass(self, url):
        """화이트리스트 등록 사이트 — 정밀 검사 없이 즉시 통과."""
        self._stop_loading_bar()
        self._current_result = None
        self.verdict_card.configure(fg_color=PASS_DIM, border_color=ACCENT)
        self.verdict_icon.configure(text="🛡", text_color=GLOW)
        self.verdict_main.configure(text="안심 사이트 (Pass)", text_color=GLOW)
        self.verdict_sub.configure(
            text="화이트리스트 등록 사이트 — 정밀 검사를 생략했습니다",
            text_color=TXT_PRI)
        self.conf_value.configure(text="PASS", text_color=GLOW)
        self.conf_bar.configure(progress_color=ACCENT)
        self.conf_bar.set(1.0)
        self._set_detail(
            f"URL        {url}\n\n"
            "🛡  안심 사이트 (화이트리스트)\n"
            "사용자가 직접 등록한 신뢰 도메인이므로 크롤링·AI 분류·위협 피드 대조를 "
            "모두 생략하고 즉시 통과 처리했습니다.\n\n"
            "오탐(False Positive)으로 등록한 경우 whitelist.txt 에서 해당 줄을 삭제하면 "
            "다시 정상적으로 분석됩니다.")
        self._set_single_status("🛡 안심 사이트 (Pass) — 검사 생략", error=False)
        try:
            log_event(f"화이트리스트 Pass (검사 생략) — {url}")
        except Exception:
            pass

    @staticmethod
    def _friendly_crawl_reason(crawl_err, crawl):
        """크롤링 실패/제한 사유를 사람이 읽기 쉬운 안내로 변환 (부분 분석용)."""
        low = str(crawl_err or "")
        if (crawl and crawl.get("crawlable") is False) or ("robots" in low):
            return ("robots.txt 정책으로 본문 수집이 제한되어, "
                    "URL 구조와 위협 인텔리전스 피드만으로 판정했습니다")
        if ("연결" in low) or ("시간 초과" in low) or ("Connection" in low) \
                or ("Timeout" in low) or ("Max retries" in low) \
                or ("Name or service" in low) or ("NameResolution" in low):
            return ("사이트에 접속할 수 없어(존재하지 않거나 응답 없음) 본문을 읽지 못했습니다. "
                    "URL 구조와 위협 피드만으로 판정했습니다")
        if low.startswith("HTTP"):
            return (f"페이지 응답 오류({low})로 본문을 읽지 못해, "
                    "URL 구조와 위협 피드만으로 판정했습니다")
        return ("본문을 불러오지 못해 URL 구조와 위협 피드만으로 판정했습니다"
                + (f" ({low})" if low else ""))

    def _single_worker(self, url):
        try:
            crawl = fetch_page(url)
            crawl_err = crawl.get("error")
            has_content = bool(crawl.get("text") or crawl.get("title"))

            img_hashes = []
            if crawl.get("image_urls"):
                try:
                    img_hashes = fetch_image_hashes(crawl["image_urls"])
                except Exception:
                    img_hashes = []   # 이미지 수집 실패는 분석 진행에 영향 없음

            # 본문을 못 읽었더라도 분석을 멈추지 않는다.
            # URL 구조 + 위협 인텔리전스 피드 기준으로 '부분 분석'을 수행한다.
            result = classify_site(crawl, img_hashes)
            result["crawl_error"] = crawl_err
            result["status_code"] = crawl.get("status_code")
            result["partial"] = (not has_content)
            result["partial_reason"] = (
                self._friendly_crawl_reason(crawl_err, crawl)
                if not has_content else "")
            self.q.put(("single_done", result))
        except Exception as e:
            # 예기치 못한 모든 오류를 안전하게 흡수
            self.q.put(("single_error", (url, str(e))))

    def _set_verdict_pending(self):
        self.verdict_card.configure(fg_color=BG_CARD, border_color=BORDER)
        self.verdict_icon.configure(text="🤖", text_color=ACCENT)
        self.verdict_main.configure(text="AI 분석 진행 중…", text_color=TXT_PRI)
        self.verdict_sub.configure(text="페이지를 수집하고 위협 피드와 대조하고 있습니다")
        self.conf_value.configure(text="…", text_color=ACCENT)
        # 진행 상황을 알 수 없는 구간이므로 indeterminate 게이지 애니메이션
        self.conf_bar.configure(progress_color=ACCENT, mode="indeterminate")
        try:
            self.conf_bar.start()
        except Exception:
            pass

    def _set_verdict_invalid(self, msg):
        """잘못된 입력/네트워크 실패 시 판정 배너를 안내 상태로."""
        self._stop_loading_bar()
        self.verdict_card.configure(fg_color=ORG_DIM, border_color=ORG)
        self.verdict_icon.configure(text="⚠", text_color=ORG)
        self.verdict_main.configure(text="확인 필요", text_color=ORG)
        self.verdict_sub.configure(text=msg, text_color=TXT_PRI)
        self.conf_value.configure(text="—", text_color=TXT_SEC)
        self.conf_bar.configure(progress_color=ORG)
        self.conf_bar.set(0)

    def _show_single_result(self, r):
        self._stop_loading_bar()
        self._current_result = r
        is_safe = (r["category"] == "safe")
        risk = r.get("risk_level", "LOW")
        partial = r.get("partial", False)
        partial_reason = r.get("partial_reason", "")

        # 배너 색상 — 정상=초록 / 고위험=레드 / 의심=오렌지
        if is_safe and risk == "LOW":
            if partial:
                # 본문을 못 읽어 위험 신호가 안 잡힌 경우 → '정상' 단정 대신 '부분 분석'
                tint, ring, color = BG_CARD2, ACCENT, ACCENT
                main_txt = "부분 분석"
                sub_txt = "본문 미수집 — URL·위협 피드 기준 위험 신호 없음"
                icon = "🧩"
            else:
                tint, ring, color = GRN_DIM, GRN, GRN
                main_txt = "정상"
                sub_txt = "탐지된 위험 요소가 없습니다"
                icon = "✅"
        elif risk == "HIGH":
            tint, ring, color = RED_DIM, RED, RED
            main_txt = "불법·유해 사이트"
            sub_txt = f"{r['category_name']} 의심 — 즉시 신고 권장"
            icon = r.get("category_icon", "🚨")
        else:
            tint, ring, color = ORG_DIM, ORG, ORG
            main_txt = "의심"
            sub_txt = f"{r['category_name']} 신호 일부 탐지 — 추가 확인 필요"
            icon = r.get("category_icon", "⚠️")

        # 부분 분석이면 위험/의심 판정에도 '본문 미수집' 꼬리표를 붙인다
        if partial and not (is_safe and risk == "LOW"):
            sub_txt += "  ·  본문 미수집(URL·피드 기준)"

        self.verdict_card.configure(fg_color=tint, border_color=ring)
        self.verdict_icon.configure(text=icon, text_color=color)
        self.verdict_main.configure(text=main_txt, text_color=color)
        self.verdict_sub.configure(text=sub_txt, text_color=TXT_PRI)
        self.conf_value.configure(text=f"{r['confidence']}%", text_color=color)
        self.conf_bar.configure(progress_color=color)
        self.conf_bar.set(min(r["confidence"] / 100.0, 1.0))

        # 상세 텍스트
        L = []
        L.append(f"URL        {r['url']}")
        L.append(f"제목        {r.get('title') or '알 수 없음'}")
        L.append(f"HTTP 상태   {r.get('status_code', '—')}")
        if r.get("kisa_matched"):
            L.append(f"위협 피드   ⚠ 차단목록 적중 ({r.get('kisa_match_source','')}, "
                     f"{r.get('kisa_match_type','')})")
        if partial:
            L.append("")
            L.append("⚠ 부분 분석 (본문 미수집)")
            L.append(f"   {partial_reason}")
            if r.get("crawl_error"):
                L.append(f"   상세 사유: {r['crawl_error']}")
        elif r.get("crawl_error"):
            L.append(f"크롤링 오류 {r['crawl_error']}")
        L.append("")
        L.append("─── 카테고리별 점수 ──────────────────────")
        score_labels = {"gambling": "🎰 불법 도박", "illegal_ott": "🎬 불법 OTT·웹툰",
                        "illegal_sports": "⚽ 불법 스포츠 중계", "adult": "🔞 성인 유해"}
        for cat, label in score_labels.items():
            sc = r["scores"].get(cat, 0)
            bar = "█" * min(sc, 24)
            L.append(f"  {label:<18} {sc:3}점  {bar}")
        L.append("")
        L.append("─── 탐지된 키워드 ────────────────────────")
        any_kw = False
        for cat, kws in r.get("matched_keywords", {}).items():
            if kws:
                any_kw = True
                L.append(f"  [{score_labels.get(cat, cat)}]")
                for kw, cnt in kws[:6]:
                    L.append(f"     • {kw}  (×{cnt})")
        if not any_kw:
            L.append("  탐지된 키워드 없음")
        L.append("")
        L.append(f"수집 이미지   {r.get('image_count', 0)}개 (해시만 수집, 원본 미저장)")

        self._set_detail("\n".join(L))
        self._set_single_status(
            f"✅ 분석 완료  ·  {datetime.now().strftime('%H:%M:%S')}", error=False)

        # 보안 세션 로그 실시간 누적 저장 (실패해도 분석에 영향 없음)
        try:
            log_detection(r.get("url", ""), r)
        except Exception:
            pass

    def _set_detail(self, text):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def _save_current_to_list(self):
        if self._current_result:
            self.results.append(self._current_result)
            self._refresh_results_tree()
            self.stat_var.set(f"● 저장 완료 — 총 {len(self.results)}건")
            messagebox.showinfo("저장됨", "결과 목록에 추가되었습니다.")

    # ════════════════════════════════════════════════════
    #  탭 2: 일괄 분석
    # ════════════════════════════════════════════════════
    def _build_batch_tab(self, parent):
        parent.configure(fg_color="transparent")

        in_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER)
        in_card.pack(fill="x", padx=PAD_X, pady=(PAD_Y, 8))
        ctk.CTkLabel(in_card, text="URL 목록  (한 줄에 하나씩)", font=self.f_bold,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(16, 6))
        self.batch_text = ctk.CTkTextbox(in_card, font=self.f_mono, height=150,
                                         fg_color=BG_INPUT, text_color=TXT_PRI,
                                         corner_radius=10, wrap="none", border_width=0)
        self.batch_text.pack(fill="x", padx=18, pady=(0, 8))
        self.batch_text.insert("1.0",
            "https://www.naver.com\n"
            "http://casino-baccarat-bet.xyz/login\n"
            "http://nunutv-free-drama.tk/watch\n")

        ctrl = ctk.CTkFrame(in_card, fg_color="transparent")
        ctrl.pack(fill="x", padx=18, pady=(0, 16))
        ctk.CTkButton(ctrl, text="일괄 분석 시작", font=self.f_bold, height=42,
                      corner_radius=10, fg_color=ACCENT, hover_color=ACCENT_HI,
                      text_color="#06121f", command=self._run_batch).pack(side="left")
        self.batch_prog_var = ctk.StringVar(value="")
        ctk.CTkLabel(ctrl, textvariable=self.batch_prog_var, font=self.f_small,
                     text_color=TXT_SEC).pack(side="left", padx=14)

        self.batch_progress = ctk.CTkProgressBar(parent, height=10, corner_radius=6,
                                                 fg_color=BG_INPUT, progress_color=ACCENT)
        self.batch_progress.set(0)
        self.batch_progress.pack(fill="x", padx=PAD_X, pady=(2, 8))
        self._batch_total = 0

        log_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                                border_width=1, border_color=BORDER)
        log_card.pack(fill="both", expand=True, padx=PAD_X, pady=(0, PAD_Y))
        ctk.CTkLabel(log_card, text="분석 로그", font=self.f_h2,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(14, 4))
        self.batch_log = ctk.CTkTextbox(log_card, font=self.f_mono, fg_color=BG_INPUT,
                                        text_color=TXT_PRI, corner_radius=10,
                                        wrap="word", border_width=0)
        self.batch_log.pack(fill="both", expand=True, padx=18, pady=(4, 18))
        self.batch_log.configure(state="disabled")

    def _run_batch(self):
        raw = self.batch_text.get("1.0", "end").strip()
        urls = [normalize_url(u.strip()) for u in raw.splitlines() if u.strip()]
        if not urls:
            return
        self._batch_total = len(urls)
        self.batch_progress.set(0)
        self._batch_log_clear()
        threading.Thread(target=self._batch_worker, args=(urls,), daemon=True).start()

    def _batch_worker(self, urls):
        for i, url in enumerate(urls, 1):
            self.q.put(("batch_progress", (i, len(urls), url)))
            try:
                crawl = fetch_page(url)
                try:
                    img_hashes = fetch_image_hashes(crawl.get("image_urls", []))
                except Exception:
                    img_hashes = []
                result = classify_site(crawl, img_hashes)
                result["crawl_error"] = crawl.get("error")
                result["status_code"] = crawl.get("status_code")
                has_content = bool(crawl.get("text") or crawl.get("title"))
                result["partial"] = (not has_content)
                result["partial_reason"] = (
                    self._friendly_crawl_reason(crawl.get("error"), crawl)
                    if not has_content else "")
                self.results.append(result)
                self.q.put(("batch_item_done", result))
            except Exception as e:
                self.q.put(("batch_item_error", (url, str(e))))
        self.q.put(("batch_all_done", len(urls)))

    def _batch_log_clear(self):
        self.batch_log.configure(state="normal")
        self.batch_log.delete("1.0", "end")
        self.batch_log.configure(state="disabled")

    def _batch_log(self, text):
        self.batch_log.configure(state="normal")
        self.batch_log.insert("end", text + "\n")
        self.batch_log.see("end")
        self.batch_log.configure(state="disabled")

    # ════════════════════════════════════════════════════
    #  탭 3: 결과 목록
    # ════════════════════════════════════════════════════
    def _build_results_tab(self, parent):
        parent.configure(fg_color="transparent")

        ctrl = ctk.CTkFrame(parent, fg_color="transparent")
        ctrl.pack(fill="x", padx=PAD_X, pady=(PAD_Y, 8))
        ctk.CTkButton(ctrl, text="CSV 내보내기 (신고용)", font=self.f_small, height=36,
                      corner_radius=8, fg_color=GRN, hover_color="#26b870",
                      text_color="#06180f", command=self._export_csv).pack(side="left")
        ctk.CTkButton(ctrl, text="텍스트 리포트", font=self.f_small, height=36,
                      corner_radius=8, fg_color=BG_CARD2, hover_color=BG_CARD,
                      text_color=TXT_PRI, command=self._show_text_report
                      ).pack(side="left", padx=8)
        ctk.CTkButton(ctrl, text="목록 초기화", font=self.f_small, height=36,
                      corner_radius=8, fg_color=BG_CARD2, hover_color="#3a1620",
                      text_color=TXT_SEC, command=self._clear_results).pack(side="right")

        table_card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                                  border_width=1, border_color=BORDER)
        table_card.pack(fill="both", expand=True, padx=PAD_X, pady=(0, PAD_Y))

        cols = ("카테고리", "위험등급", "신뢰도", "URL", "제목")
        self.tree = ttk.Treeview(table_card, columns=cols, show="headings",
                                 selectmode="browse", style="Dark.Treeview")
        widths = [150, 110, 80, 380, 200]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        vsb = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview,
                            style="Dark.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 6), pady=10)
        self.tree.pack(fill="both", expand=True, padx=(10, 0), pady=10)

        # 위험등급별 행 색상
        self.tree.tag_configure("HIGH", foreground=RED)
        self.tree.tag_configure("MEDIUM", foreground=ORG)
        self.tree.tag_configure("LOW", foreground=GRN)

    def _refresh_results_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in self.results:
            self.tree.insert("", "end",
                tags=(r.get("risk_level", "LOW"),),
                values=(
                    f"{r.get('category_icon','')} {r.get('category_name','')}",
                    r.get("risk_label", ""),
                    f"{r.get('confidence', 0)}%",
                    r.get("url", ""),
                    (r.get("title", "") or "")[:40],
                ))

    def _export_csv(self):
        if not self.results:
            messagebox.showwarning("결과 없음", "저장된 분석 결과가 없습니다.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 파일", "*.csv")],
            initialfile=f"불법사이트_탐지보고서_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if path:
            generate_csv_report(self.results, path)
            messagebox.showinfo("저장 완료", f"CSV 저장 완료:\n{path}")

    def _show_text_report(self):
        if not self.results:
            messagebox.showwarning("결과 없음", "저장된 분석 결과가 없습니다.")
            return
        win = ctk.CTkToplevel(self.root)
        win.title("탐지 보고서")
        win.geometry("720x540")
        win.configure(fg_color=BG_DARK)
        box = ctk.CTkTextbox(win, font=self.f_mono, fg_color=BG_INPUT,
                             text_color=TXT_PRI, corner_radius=10, border_width=0)
        box.pack(fill="both", expand=True, padx=18, pady=18)
        box.insert("1.0", generate_text_report(self.results))
        box.configure(state="disabled")

    def _clear_results(self):
        if messagebox.askyesno("초기화", "결과 목록을 모두 지울까요?"):
            self.results.clear()
            self._refresh_results_tree()
            self.stat_var.set("● 목록 비움")

    # ════════════════════════════════════════════════════
    #  탭 4: KISA / 위협정보
    # ════════════════════════════════════════════════════
    def _build_kisa_tab(self, parent):
        parent.configure(fg_color="transparent")
        wrap = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=8, pady=4)

        info = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER)
        info.pack(fill="x", padx=PAD_X, pady=(PAD_Y, 8))
        ctk.CTkLabel(info, text="🛰  실시간 위협 인텔리전스 (무료 공개 피드)",
                     font=self.f_h2, text_color=TXT_PRI
                     ).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(info,
                     text="OpenPhish · Phishing.Database · URLhaus 3개 무료 공개 피드를 통합 수신해 "
                          "URL 분석 시 차단 목록과 자동 대조합니다. (API 키·인증 불필요)",
                     font=self.f_small, text_color=TXT_SEC, justify="left",
                     wraplength=900).pack(anchor="w", padx=16, pady=(0, 14))

        ctrl = ctk.CTkFrame(wrap, fg_color="transparent")
        ctrl.pack(fill="x", padx=PAD_X, pady=4)
        ctk.CTkButton(ctrl, text="전체 피드 갱신", font=self.f_bold, height=40,
                      corner_radius=10, fg_color=ACCENT, hover_color=ACCENT_HI,
                      text_color="#06121f", command=self._kisa_refresh).pack(side="left")
        self.kisa_stat_var = ctk.StringVar(value="차단 목록 미로드")
        ctk.CTkLabel(ctrl, textvariable=self.kisa_stat_var, font=self.f_small,
                     text_color=TXT_SEC).pack(side="left", padx=14)

        # 통계 카드 3종
        stat_row = ctk.CTkFrame(wrap, fg_color="transparent")
        stat_row.pack(fill="x", padx=PAD_X, pady=8)
        self.kisa_total_var  = ctk.StringVar(value="—")
        self.kisa_update_var = ctk.StringVar(value="—")
        self.kisa_src_var    = ctk.StringVar(value="—")
        for label_text, var, icon in [
            ("총 차단 URL", self.kisa_total_var, "📦"),
            ("마지막 갱신", self.kisa_update_var, "🕐"),
            ("데이터 출처", self.kisa_src_var, "🏛"),
        ]:
            sc = ctk.CTkFrame(stat_row, fg_color=BG_CARD, corner_radius=12,
                              border_width=1, border_color=BORDER)
            sc.pack(side="left", fill="both", expand=True, padx=(0, 10))
            ctk.CTkLabel(sc, text=f"{icon}  {label_text}", font=self.f_tiny,
                         text_color=TXT_SEC).pack(anchor="w", padx=14, pady=(12, 2))
            ctk.CTkLabel(sc, textvariable=var, font=self.f_bold, text_color=ACCENT,
                         wraplength=260, justify="left").pack(anchor="w", padx=14, pady=(0, 12))

        log_card = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=12,
                                border_width=1, border_color=BORDER)
        log_card.pack(fill="both", expand=True, padx=PAD_X, pady=8)
        ctk.CTkLabel(log_card, text="피드 수신 로그", font=self.f_h2,
                     text_color=TXT_PRI).pack(anchor="w", padx=16, pady=(14, 4))
        self.kisa_log = ctk.CTkTextbox(log_card, font=self.f_mono, height=180,
                                       fg_color=BG_INPUT, text_color=TXT_PRI,
                                       corner_radius=10, wrap="word", border_width=0)
        self.kisa_log.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        self.kisa_log.configure(state="disabled")

        guide = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=12,
                             border_width=1, border_color=BORDER)
        guide.pack(fill="x", padx=PAD_X, pady=(8, PAD_Y))
        ctk.CTkLabel(guide, text="📌 사용 안내", font=self.f_bold,
                     text_color=TXT_PRI).pack(anchor="w", padx=16, pady=(14, 6))
        steps = [
            "① '전체 피드 갱신' → 3개 무료 피드 통합 수신 (API 키·인증 불필요)",
            "      • OpenPhish: 실시간 피싱 URL",
            "      • Phishing.Database: 활성 피싱 링크 (GitHub 공개)",
            "      • URLhaus: 악성 URL 공개 피드 (abuse.ch)",
            "② 수신 목록은 cache/blocklist.json 에 저장 (24시간 캐시)",
            "③ URL 분석 시 완전일치·도메인일치 자동 대조 → 적중 시 위험도 100% 고정",
            "",
            "  ※ 국내 불법 사이트 신고는 '신고 안내' 탭의 기관을 이용하세요.",
        ]
        for step in steps:
            ctk.CTkLabel(guide, text=step, font=self.f_small, text_color=TXT_SEC,
                         justify="left").pack(anchor="w", padx=16, pady=1)
        ctk.CTkLabel(guide, text="", font=self.f_tiny).pack(pady=2)

        self._kisa_load_stats()

    def _kisa_log_write(self, text):
        self.kisa_log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.kisa_log.insert("end", f"[{ts}]  {text}\n")
        self.kisa_log.see("end")
        self.kisa_log.configure(state="disabled")

    def _kisa_load_stats(self):
        try:
            from model.kisa_feed import get_blocklist_stats
            stats = get_blocklist_stats()
            if stats["total"] > 0:
                self.kisa_total_var.set(f"{stats['total']:,} 건")
                upd = stats.get("updated_at", "")[:16].replace("T", " ")
                self.kisa_update_var.set(upd or "—")
                src = " / ".join(f"{k}({v}건)" for k, v in stats["by_source"].items())
                self.kisa_src_var.set(src or "—")
                self.kisa_stat_var.set(f"차단 목록 {stats['total']:,}건 로드됨")
            else:
                self.kisa_stat_var.set("차단 목록 없음 — '전체 피드 갱신'을 눌러주세요")
        except Exception as e:
            self.kisa_stat_var.set(f"통계 로드 실패: {e}")

    def _kisa_refresh(self):
        self.kisa_stat_var.set("🔄 무료 공개 피드 3종 수신 중...")
        self._kisa_log_write("피드 갱신 시작...")
        threading.Thread(target=self._kisa_refresh_worker, daemon=True).start()

    def _kisa_refresh_worker(self):
        try:
            from model.kisa_feed import refresh_blocklist, invalidate_index
            def _progress(msg):
                self.q.put(("kisa_progress", msg))
            entries, status = refresh_blocklist(force=True, progress_cb=_progress)
            invalidate_index()
            self.q.put(("kisa_done", (entries, status)))
        except Exception as e:
            self.q.put(("kisa_error", str(e)))

    # ════════════════════════════════════════════════════
    #  탭 5: 신고 안내
    # ════════════════════════════════════════════════════
    def _build_report_tab(self, parent):
        parent.configure(fg_color="transparent")
        wrap = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=8, pady=4)

        ctk.CTkLabel(wrap, text="📢 불법 사이트 신고 기관", font=self.f_title,
                     text_color=TXT_PRI).pack(anchor="w", padx=PAD_X, pady=(PAD_Y, 2))
        ctk.CTkLabel(wrap, text="탐지된 불법·유해 사이트는 아래 기관에 신고할 수 있습니다.",
                     font=self.f_small, text_color=TXT_SEC).pack(anchor="w", padx=PAD_X, pady=(0, 10))

        AGENCIES = [
            ("🏛  방송통신심의위원회",
             "인터넷 유해 정보 (불법 도박, 불법 스트리밍, 성인물 등) 신고",
             "https://www.kocsc.or.kr", "위법·유해 정보 신고 → '신고하기' 메뉴"),
            ("🛡  KISA 사이버침해대응센터",
             "사이버 범죄, 피싱, 악성코드, 개인정보 침해 신고  /  전화 118",
             "https://www.krcert.or.kr", "신고·상담 → 인터넷 침해사고 신고"),
            ("👮  경찰청 사이버범죄 신고시스템",
             "불법 도박, 불법 촬영물 유포, 사기 등 형사 사건 신고",
             "https://ecrm.police.go.kr", "사이버범죄 신고 → 범죄 유형 선택"),
            ("🎰  불법도박 신고센터 (사행산업통합감독위원회)",
             "불법 스포츠 도박, 온라인 카지노 등 전문 신고 채널",
             "https://www.kgef.or.kr", "불법도박 신고 메뉴"),
            ("📹  디지털성범죄피해자지원센터",
             "불법 촬영물, 성적 착취물 유포 피해 신고 및 삭제 지원",
             "https://d4u.stop.or.kr", "긴급 신고 및 삭제 지원 신청"),
        ]
        for name, desc, url, guide in AGENCIES:
            c = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=12,
                             border_width=1, border_color=BORDER)
            c.pack(fill="x", padx=PAD_X, pady=6)
            ctk.CTkLabel(c, text=name, font=self.f_bold, text_color=TXT_PRI
                         ).pack(anchor="w", padx=16, pady=(12, 2))
            ctk.CTkLabel(c, text=desc, font=self.f_small, text_color=TXT_SEC
                         ).pack(anchor="w", padx=16)
            ctk.CTkLabel(c, text=f"🔗 {url}", font=self.f_mono, text_color=GLOW
                         ).pack(anchor="w", padx=16)
            ctk.CTkLabel(c, text=f"📌 {guide}", font=self.f_small, text_color=TXT_MUTED
                         ).pack(anchor="w", padx=16, pady=(0, 12))

        law = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=12,
                           border_width=1, border_color=BORDER)
        law.pack(fill="x", padx=PAD_X, pady=(8, PAD_Y))
        ctk.CTkLabel(law, text="⚖  관련 법령", font=self.f_bold,
                     text_color=TXT_PRI).pack(anchor="w", padx=16, pady=(12, 6))
        laws = [
            "• 불법 도박 운영·이용: 국민체육진흥법, 형법 제247조 (도박장 개설)",
            "• 불법 스트리밍·웹툰 유포: 저작권법 제136조 (저작재산권 침해)",
            "• 불법 성인물 유포: 정보통신망법 제74조, 성폭력처벌법 제14조",
            "• 무단 크롤링/스크래핑: 정보통신망법 제48조 (무단 접근 금지)",
        ]
        for t in laws:
            ctk.CTkLabel(law, text=t, font=self.f_small, text_color=TXT_SEC
                         ).pack(anchor="w", padx=16, pady=2)
        ctk.CTkLabel(law, text="", font=self.f_tiny).pack(pady=2)

    # ════════════════════════════════════════════════════
    #  탭 6: 프로그램 정보 (About)
    # ════════════════════════════════════════════════════
    def _build_about_tab(self, parent):
        parent.configure(fg_color="transparent")
        wrap = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=8, pady=4)

        # ── 히어로 카드 ─────────────────────────────────
        hero = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=16,
                            border_width=1, border_color=ACCENT)
        hero.pack(fill="x", padx=PAD_X, pady=(PAD_Y, 10))
        inner = ctk.CTkFrame(hero, fg_color="transparent")
        inner.pack(fill="x", padx=24, pady=22)
        ctk.CTkLabel(inner, text="🛡", font=self.f_icon, text_color=ACCENT
                     ).pack(side="left", padx=(0, 20))
        box = ctk.CTkFrame(inner, fg_color="transparent")
        box.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(box, text="불법·유해 사이트 탐지 시스템", font=self.f_verdict,
                     text_color=TXT_PRI, anchor="w").pack(anchor="w")
        ctk.CTkLabel(box, text="Illegal & Harmful Site Detector",
                     font=self.f_small, text_color=TXT_SEC, anchor="w").pack(anchor="w")
        badge = ctk.CTkFrame(box, fg_color=ACCENT, corner_radius=14)
        badge.pack(anchor="w", pady=(10, 0))
        ctk.CTkLabel(badge, text="  인공지능 개론 기말 프로젝트  ·  v1.0.0  ",
                     font=self.f_bold, text_color="#06121f").pack(padx=2, pady=4)

        # ── 개발팀 카드 ─────────────────────────────────
        team = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=14,
                            border_width=1, border_color=BORDER)
        team.pack(fill="x", padx=PAD_X, pady=8)
        ctk.CTkLabel(team, text="👥  개발팀", font=self.f_h2,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(14, 8))
        members = [
            ("김재환", "팀장 · 탐지 엔진 / 시스템 설계"),
            ("팀원 A", "크롤러 · 위협 인텔리전스 피드 연동"),
            ("팀원 B", "UI/UX 디자인 · 화이트리스트 / 로그"),
            ("팀원 C", "테스트 · 신고 가이드 · 문서화"),
        ]
        for name, role in members:
            row = ctk.CTkFrame(team, fg_color=BG_INPUT, corner_radius=10)
            row.pack(fill="x", padx=18, pady=4)
            ctk.CTkLabel(row, text=f"  {name}", font=self.f_bold, text_color=GLOW,
                         width=120, anchor="w").pack(side="left", padx=(6, 10), pady=10)
            ctk.CTkLabel(row, text=role, font=self.f_small, text_color=TXT_SEC,
                         anchor="w").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(team, text="", font=self.f_tiny).pack(pady=2)

        # ── 기술 스택 카드 ───────────────────────────────
        tech = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=14,
                            border_width=1, border_color=BORDER)
        tech.pack(fill="x", padx=PAD_X, pady=8)
        ctk.CTkLabel(tech, text="🧩  기술 스택", font=self.f_h2,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(14, 8))
        chips = ctk.CTkFrame(tech, fg_color="transparent")
        chips.pack(fill="x", padx=14, pady=(0, 14))
        STACK = ["Python 3", "CustomTkinter", "BeautifulSoup4", "scikit-learn",
                 "requests", "OpenPhish", "URLhaus", "Phishing.Database"]
        # 칩을 줄바꿈되게 배치
        rowf = None
        for i, name in enumerate(STACK):
            if i % 4 == 0:
                rowf = ctk.CTkFrame(chips, fg_color="transparent")
                rowf.pack(fill="x", pady=3)
            ctk.CTkLabel(rowf, text=f"  {name}  ", font=self.f_small,
                         text_color=TXT_PRI, fg_color=BG_INPUT, corner_radius=12
                         ).pack(side="left", padx=4)

        # ── 주요 기능 카드 ───────────────────────────────
        feat = ctk.CTkFrame(wrap, fg_color=BG_CARD, corner_radius=14,
                            border_width=1, border_color=BORDER)
        feat.pack(fill="x", padx=PAD_X, pady=8)
        ctk.CTkLabel(feat, text="✨  주요 기능", font=self.f_h2,
                     text_color=TXT_PRI).pack(anchor="w", padx=18, pady=(14, 6))
        feats = [
            "URL 구조 · 텍스트 키워드 · 이미지 신호 종합 분류 (4개 위험 카테고리)",
            "무료 위협 인텔리전스 피드 3종 통합 대조 (OpenPhish · URLhaus · Phishing.DB)",
            "화이트리스트(안심 사이트) 등록으로 오탐 방지 — 즉시 Pass 처리",
            "탐지 결과 실시간 보안 로그 저장 (security_logs.txt)",
            "robots.txt 준수 · 요청 속도 제한 · 이미지 해시만 수집 (원본 미저장)",
            "신고용 CSV / 텍스트 리포트 생성 및 기관별 신고 가이드 제공",
        ]
        for ft in feats:
            ctk.CTkLabel(feat, text=f"•  {ft}", font=self.f_small, text_color=TXT_SEC,
                         justify="left", wraplength=880, anchor="w"
                         ).pack(anchor="w", padx=18, pady=2)
        ctk.CTkLabel(feat, text="", font=self.f_tiny).pack(pady=2)

        # ── 푸터 ─────────────────────────────────────────
        ctk.CTkLabel(wrap,
                     text="© 2026 인공지능 개론 기말 프로젝트 팀  ·  교육·연구 및 합법적 신고 목적 전용",
                     font=self.f_tiny, text_color=TXT_MUTED
                     ).pack(anchor="center", padx=PAD_X, pady=(6, PAD_Y))

    # ════════════════════════════════════════════════════
    #  큐 폴링 (워커 스레드 → UI)
    # ════════════════════════════════════════════════════
    def _poll_queue(self):
        try:
            while True:
                msg, data = self.q.get_nowait()

                if msg == "single_done":
                    self._set_analyzing(False)
                    self._show_single_result(data)

                elif msg == "single_fail":
                    # 네트워크 단절 / 접근 불가 등 — 친절한 안내 + 로그
                    self._set_analyzing(False)
                    url, friendly = data
                    self._set_single_status(f"⚠ {friendly}", error=True)
                    self._set_verdict_invalid(friendly)
                    log_error(url, friendly)

                elif msg == "single_error":
                    self._set_analyzing(False)
                    self._stop_loading_bar()
                    url, errmsg = data if isinstance(data, tuple) else ("", str(data))
                    self._set_single_status("⚠ 분석 중 오류가 발생했습니다", error=True)
                    self.verdict_card.configure(fg_color=RED_DIM, border_color=RED)
                    self.verdict_icon.configure(text="⚠", text_color=RED)
                    self.verdict_main.configure(text="분석 실패", text_color=RED)
                    self.verdict_sub.configure(text=str(errmsg), text_color=TXT_PRI)
                    log_error(url, errmsg)

                elif msg == "batch_progress":
                    i, total, url = data
                    self.batch_progress.set(i / max(total, 1))
                    self.batch_prog_var.set(f"{i}/{total}  —  {url[:50]}")

                elif msg == "batch_item_done":
                    r = data
                    self._batch_log(
                        f"[{r['risk_label']}] {r['category_icon']} "
                        f"{r['url'][:60]}  ({r['confidence']}%)")
                    self._refresh_results_tree()
                    try:
                        log_detection(r.get("url", ""), r)
                    except Exception:
                        pass

                elif msg == "batch_item_error":
                    url, err = data
                    self._batch_log(f"[오류] {url[:60]}  → {err}")
                    log_error(url, err)

                elif msg == "batch_all_done":
                    self.batch_prog_var.set(f"✅ 완료 — {data}개 분석")
                    self.stat_var.set(f"● 총 {len(self.results)}건 누적")

                elif msg == "kisa_progress":
                    self.kisa_stat_var.set(f"🔄 {data}")
                    self._kisa_log_write(data)

                elif msg == "kisa_done":
                    entries, status = data
                    self.kisa_stat_var.set(f"✅ 갱신 완료 ({len(entries):,}건)")
                    self._kisa_log_write(f"갱신 완료: {status}")
                    self._kisa_load_stats()
                    try:
                        log_event(f"위협 피드 갱신 완료 — {len(entries):,}건")
                    except Exception:
                        pass

                elif msg == "kisa_error":
                    self.kisa_stat_var.set(f"❌ 오류: {data}")
                    self._kisa_log_write(f"오류: {data}")

        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)
