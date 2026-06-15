"""
불법·유해 사이트 탐지 시스템 — Tkinter 대시보드
탭 구성: 단일 URL 분석 | 일괄 분석 | 탐지 결과 목록 | 신고 가이드
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import os
from datetime import datetime

from crawler.fetcher import fetch_page, fetch_image_hashes, normalize_url
from model.analyzer import classify_site
from report.generator import generate_csv_report, generate_text_report

# ─── 팔레트 ──────────────────────────────────────────
BG_DARK    = "#0d1117"
BG_CARD    = "#161b22"
BG_INPUT   = "#21262d"
BORDER     = "#30363d"
ACCENT     = "#58a6ff"
GRN        = "#3fb950"
RED        = "#f85149"
ORG        = "#d29922"
PURPLE     = "#bc8cff"
PINK       = "#ff6eb4"
TEXT_PRI   = "#e6edf3"
TEXT_SEC   = "#8b949e"
TEXT_MUTED = "#484f58"

FONT       = ("맑은 고딕", 11)
FONT_B     = ("맑은 고딕", 11, "bold")
FONT_T     = ("맑은 고딕", 14, "bold")
FONT_S     = ("맑은 고딕", 9)
FONT_CODE  = ("Consolas", 10)

CAT_COLORS = {
    "gambling":       RED,
    "illegal_ott":    ORG,
    "illegal_sports": PURPLE,
    "adult":          PINK,
    "safe":           GRN,
}


def _label(parent, text, font=None, fg=TEXT_PRI, bg=BG_DARK, **kw):
    return tk.Label(parent, text=text, font=font or FONT,
                    fg=fg, bg=bg, **kw)


def _card(parent, **kw):
    return tk.Frame(parent, bg=BG_CARD,
                    highlightbackground=BORDER, highlightthickness=1, **kw)


class IllegalSiteDetector:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.results = []          # 탐지 결과 누적
        self.q = queue.Queue()     # 스레드→UI 통신

        root.title("🚨 불법·유해 사이트 탐지 시스템")
        root.geometry("1000x720")
        root.minsize(860, 620)
        root.configure(bg=BG_DARK)
        self._center(root)
        self._style()
        self._build_header()
        self._build_tabs()
        self._poll_queue()

    # ─── 유틸 ──────────────────────────────────────

    def _center(self, win):
        win.update_idletasks()
        w, h = 1000, 720
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")

    def _style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure(".", background=BG_DARK, foreground=TEXT_PRI,
                    font=FONT, borderwidth=0)
        s.configure("TNotebook", background=BG_DARK, borderwidth=0,
                    tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab", background=BG_CARD,
                    foreground=TEXT_SEC, padding=[14, 8], font=FONT)
        s.map("TNotebook.Tab",
              background=[("selected", BG_DARK)],
              foreground=[("selected", ACCENT)])
        s.configure("Treeview", background=BG_CARD, foreground=TEXT_PRI,
                    fieldbackground=BG_CARD, rowheight=26,
                    borderwidth=0, font=FONT_S)
        s.configure("Treeview.Heading", background=BG_INPUT,
                    foreground=TEXT_SEC, font=FONT_S)
        s.map("Treeview", background=[("selected", "#1f2937")])

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG_CARD, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🚨  불법·유해 사이트 탐지 시스템",
                 font=("맑은 고딕", 15, "bold"), bg=BG_CARD,
                 fg=TEXT_PRI).pack(side="left", padx=20, pady=12)
        self.stat_var = tk.StringVar(value="분석 대기 중")
        tk.Label(hdr, textvariable=self.stat_var, font=FONT_S,
                 bg=BG_CARD, fg=TEXT_SEC).pack(side="right", padx=20)

    def _build_tabs(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)
        self.nb = nb

        t1 = tk.Frame(nb, bg=BG_DARK)
        t2 = tk.Frame(nb, bg=BG_DARK)
        t3 = tk.Frame(nb, bg=BG_DARK)
        t4 = tk.Frame(nb, bg=BG_DARK)
        t5 = tk.Frame(nb, bg=BG_DARK)

        nb.add(t1, text="  🔍  단일 URL 분석  ")
        nb.add(t2, text="  📋  일괄 분석  ")
        nb.add(t3, text="  📊  탐지 결과 목록  ")
        nb.add(t5, text="  🛡️  KISA 위협정보  ")
        nb.add(t4, text="  📢  신고 안내  ")

        self._build_single_tab(t1)
        self._build_batch_tab(t2)
        self._build_results_tab(t3)
        self._build_kisa_tab(t5)
        self._build_report_tab(t4)

    # ─── 탭 1: 단일 URL 분석 ──────────────────────

    def _build_single_tab(self, parent):
        p = dict(padx=20, pady=6)

        # 입력
        _label(parent, "분석할 URL 입력", font=FONT_B).pack(anchor="w", padx=20, pady=(16, 2))
        row = tk.Frame(parent, bg=BG_DARK)
        row.pack(fill="x", **p)
        self.url_var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self.url_var, font=FONT_CODE,
                         bg=BG_INPUT, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                         relief="flat", bd=8)
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        entry.bind("<Return>", lambda e: self._run_single())
        tk.Button(row, text="  분석  ", font=FONT_B,
                  bg=ACCENT, fg=BG_DARK, relief="flat", cursor="hand2",
                  bd=0, padx=10, pady=6,
                  command=self._run_single).pack(side="left", padx=(8, 0))

        # 예시 버튼
        ex = tk.Frame(parent, bg=BG_DARK)
        ex.pack(fill="x", padx=20)
        _label(ex, "예시:", font=FONT_S, fg=TEXT_MUTED).pack(side="left")
        EXAMPLES = [
            ("정상 사이트", "https://www.naver.com"),
            ("도박 패턴", "http://casino-baccarat-bet.xyz/login"),
            ("불법OTT 패턴", "http://nunutv-free-drama.tk/watch"),
            ("성인 패턴", "http://adult-19-free.ml/enter"),
        ]
        for lbl, url in EXAMPLES:
            tk.Button(ex, text=lbl, font=FONT_S,
                      bg=BG_INPUT, fg=TEXT_SEC, relief="flat",
                      cursor="hand2", bd=0, padx=8,
                      command=lambda u=url: self.url_var.set(u)
                      ).pack(side="left", padx=3)

        # 진행 표시
        self.single_status = tk.StringVar(value="")
        _label(parent, "", textvariable=self.single_status,
               font=FONT_S, fg=TEXT_SEC).pack(anchor="w", padx=20, pady=(4, 0))

        # 결과 패널
        res_wrap = tk.Frame(parent, bg=BG_DARK)
        res_wrap.pack(fill="both", expand=True, padx=20, pady=8)

        # 왼쪽: 판정 카드
        left = _card(res_wrap)
        left.pack(side="left", fill="y", padx=(0, 12), ipadx=16, ipady=12)

        _label(left, "판정 결과", font=FONT_B, bg=BG_CARD).pack(pady=(8, 4))
        self.result_icon  = tk.StringVar(value="—")
        self.result_cat   = tk.StringVar(value="분석 전")
        self.result_conf  = tk.StringVar(value="")
        self.result_risk  = tk.StringVar(value="")

        tk.Label(left, textvariable=self.result_icon,
                 font=("Segoe UI Emoji", 36), bg=BG_CARD,
                 fg=TEXT_PRI).pack()
        tk.Label(left, textvariable=self.result_cat,
                 font=("맑은 고딕", 14, "bold"), bg=BG_CARD,
                 fg=TEXT_PRI).pack()
        tk.Label(left, textvariable=self.result_risk,
                 font=FONT_B, bg=BG_CARD, fg=ORG).pack(pady=2)

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", pady=8)

        # 신뢰도 바
        _label(left, "신뢰도", font=FONT_S, fg=TEXT_SEC, bg=BG_CARD).pack()
        self.conf_canvas = tk.Canvas(left, width=160, height=20,
                                     bg=BG_INPUT, highlightthickness=0)
        self.conf_canvas.pack(pady=4)
        tk.Label(left, textvariable=self.result_conf,
                 font=FONT_B, bg=BG_CARD, fg=TEXT_PRI).pack()

        # 신고 버튼
        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", pady=8)
        tk.Button(left, text="📋 결과 목록에 저장",
                  font=FONT_S, bg=BG_INPUT, fg=TEXT_SEC,
                  relief="flat", cursor="hand2", bd=0, pady=6,
                  command=self._save_current_to_list).pack(fill="x", padx=8)

        # 오른쪽: 상세 분석
        right = _card(res_wrap)
        right.pack(side="left", fill="both", expand=True)
        _label(right, "상세 분석", font=FONT_B, bg=BG_CARD).pack(anchor="w", padx=12, pady=8)
        self.detail_text = scrolledtext.ScrolledText(
            right, font=FONT_S, bg=BG_INPUT, fg=TEXT_PRI,
            relief="flat", bd=4, height=18, state="disabled", wrap="word")
        self.detail_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._current_result = None

    def _run_single(self):
        url = normalize_url(self.url_var.get().strip())
        if not url or url == "https://":
            return
        self.single_status.set("🔄 크롤링 중... (robots.txt 확인 → 페이지 수집 → 분석)")
        self._set_detail("분석 중입니다. 잠시 기다려 주세요...")
        threading.Thread(target=self._single_worker, args=(url,), daemon=True).start()

    def _single_worker(self, url):
        try:
            crawl = fetch_page(url)
            img_hashes = []
            if crawl.get("image_urls"):
                img_hashes = fetch_image_hashes(crawl["image_urls"])
            result = classify_site(crawl, img_hashes)
            result["crawl_error"] = crawl.get("error")
            result["status_code"] = crawl.get("status_code")
            self.q.put(("single_done", result))
        except Exception as e:
            self.q.put(("single_error", str(e)))

    def _show_single_result(self, r):
        self._current_result = r
        color = r["category_color"]

        self.result_icon.set(r["category_icon"])
        self.result_cat.set(r["category_name"] if r["category"] != "safe" else "안전")
        self.result_conf.set(f"{r['confidence']}%")
        self.result_risk.set(r["risk_label"])

        # 신뢰도 바
        self.conf_canvas.delete("all")
        fill_w = int(160 * r["confidence"] / 100)
        self.conf_canvas.create_rectangle(0, 0, 160, 20, fill=BG_INPUT, outline="")
        if fill_w > 0:
            self.conf_canvas.create_rectangle(0, 0, fill_w, 20, fill=color, outline="")

        # 상세 텍스트
        lines = []
        lines.append(f"URL:       {r['url']}")
        lines.append(f"제목:      {r.get('title') or '알 수 없음'}")
        lines.append(f"HTTP 상태: {r.get('status_code', '—')}")
        if r.get("crawl_error"):
            lines.append(f"크롤링 오류: {r['crawl_error']}")
        lines.append("")
        lines.append("─── 카테고리별 점수 ─────────────────")
        score_labels = {"gambling": "🎰 불법 도박", "illegal_ott": "🎬 불법 OTT·웹툰",
                        "illegal_sports": "⚽ 불법 스포츠 중계", "adult": "🔞 성인 유해"}
        for cat, label in score_labels.items():
            sc = r["scores"].get(cat, 0)
            bar = "█" * min(sc, 20)
            lines.append(f"  {label:<20} {sc:3}점  {bar}")
        lines.append("")
        lines.append("─── 탐지된 키워드 ───────────────────")
        any_kw = False
        for cat, kws in r.get("matched_keywords", {}).items():
            if kws:
                any_kw = True
                cat_label = score_labels.get(cat, cat)
                lines.append(f"  [{cat_label}]")
                for kw, cnt in kws[:6]:
                    lines.append(f"    • {kw}  (×{cnt})")
        if not any_kw:
            lines.append("  탐지된 키워드 없음")
        lines.append("")
        lines.append(f"이미지 수: {r.get('image_count', 0)}개")

        self._set_detail("\n".join(lines))
        self.single_status.set(f"✅ 분석 완료  |  {datetime.now().strftime('%H:%M:%S')}")

    def _set_detail(self, text):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.config(state="disabled")

    def _save_current_to_list(self):
        if self._current_result:
            self.results.append(self._current_result)
            self._refresh_results_tree()
            self.stat_var.set(f"저장 완료 — 총 {len(self.results)}건")
            messagebox.showinfo("저장됨", "결과 목록에 추가되었습니다.")

    # ─── 탭 2: 일괄 분석 ──────────────────────────

    def _build_batch_tab(self, parent):
        _label(parent, "URL 목록 입력 (줄바꿈으로 구분)",
               font=FONT_B).pack(anchor="w", padx=20, pady=(16, 4))
        self.batch_text = scrolledtext.ScrolledText(
            parent, font=FONT_CODE, bg=BG_INPUT, fg=TEXT_PRI,
            insertbackground=TEXT_PRI, relief="flat", bd=8, height=10, wrap="none")
        self.batch_text.pack(fill="x", padx=20)
        self.batch_text.insert("1.0",
            "https://www.naver.com\n"
            "http://casino-baccarat-bet.xyz/login\n"
            "http://nunutv-free-drama.tk/watch\n"
        )

        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", padx=20, pady=8)
        tk.Button(ctrl, text="  🔍  일괄 분석 시작  ",
                  font=FONT_B, bg=ACCENT, fg=BG_DARK, relief="flat",
                  cursor="hand2", bd=0, pady=8,
                  command=self._run_batch).pack(side="left")
        self.batch_prog_var = tk.StringVar(value="")
        _label(ctrl, "", textvariable=self.batch_prog_var,
               font=FONT_S, fg=TEXT_SEC).pack(side="left", padx=12)

        self.batch_progress = ttk.Progressbar(parent, length=600,
                                               mode="determinate")
        self.batch_progress.pack(padx=20, pady=4, fill="x")

        # 결과 로그
        _label(parent, "분석 로그", font=FONT_B).pack(anchor="w", padx=20, pady=(8, 2))
        self.batch_log = scrolledtext.ScrolledText(
            parent, font=FONT_S, bg=BG_INPUT, fg=TEXT_PRI,
            relief="flat", bd=8, height=12, state="disabled", wrap="word")
        self.batch_log.pack(fill="both", expand=True, padx=20, pady=(0, 16))

    def _run_batch(self):
        raw = self.batch_text.get("1.0", "end").strip()
        urls = [normalize_url(u.strip()) for u in raw.splitlines() if u.strip()]
        if not urls:
            return
        self.batch_progress["maximum"] = len(urls)
        self.batch_progress["value"] = 0
        self._batch_log_clear()
        threading.Thread(target=self._batch_worker,
                         args=(urls,), daemon=True).start()

    def _batch_worker(self, urls):
        for i, url in enumerate(urls, 1):
            self.q.put(("batch_progress", (i, len(urls), url)))
            try:
                crawl = fetch_page(url)
                img_hashes = fetch_image_hashes(crawl.get("image_urls", []))
                result = classify_site(crawl, img_hashes)
                result["crawl_error"] = crawl.get("error")
                result["status_code"] = crawl.get("status_code")
                self.results.append(result)
                self.q.put(("batch_item_done", result))
            except Exception as e:
                self.q.put(("batch_item_error", (url, str(e))))
        self.q.put(("batch_all_done", len(urls)))

    def _batch_log_clear(self):
        self.batch_log.config(state="normal")
        self.batch_log.delete("1.0", "end")
        self.batch_log.config(state="disabled")

    def _batch_log(self, text):
        self.batch_log.config(state="normal")
        self.batch_log.insert("end", text + "\n")
        self.batch_log.see("end")
        self.batch_log.config(state="disabled")

    # ─── 탭 3: 결과 목록 ──────────────────────────

    def _build_results_tab(self, parent):
        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", padx=20, pady=(12, 6))
        tk.Button(ctrl, text="📥 CSV 내보내기 (신고용)",
                  font=FONT_S, bg=GRN, fg=BG_DARK, relief="flat",
                  cursor="hand2", bd=0, padx=12, pady=6,
                  command=self._export_csv).pack(side="left")
        tk.Button(ctrl, text="📄 텍스트 리포트",
                  font=FONT_S, bg=BG_INPUT, fg=TEXT_PRI, relief="flat",
                  cursor="hand2", bd=0, padx=12, pady=6,
                  command=self._show_text_report).pack(side="left", padx=8)
        tk.Button(ctrl, text="🗑 목록 초기화",
                  font=FONT_S, bg=BG_INPUT, fg=TEXT_SEC, relief="flat",
                  cursor="hand2", bd=0, padx=12, pady=6,
                  command=self._clear_results).pack(side="right")

        cols = ("카테고리", "위험등급", "신뢰도", "URL", "제목")
        self.tree = ttk.Treeview(parent, columns=cols,
                                  show="headings", selectmode="browse")
        widths = [120, 100, 70, 380, 200]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical",
                             command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 8))
        self.tree.pack(fill="both", expand=True, padx=20, pady=(0, 16))

    def _refresh_results_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in self.results:
            self.tree.insert("", "end", values=(
                f"{r.get('category_icon','')} {r.get('category_name','')}",
                r.get("risk_label", ""),
                f"{r.get('confidence', 0)}%",
                r.get("url", ""),
                r.get("title", "")[:40],
            ))

    def _export_csv(self):
        if not self.results:
            messagebox.showwarning("결과 없음", "저장된 분석 결과가 없습니다.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 파일", "*.csv")],
            initialfile=f"불법사이트_탐지보고서_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if path:
            generate_csv_report(self.results, path)
            messagebox.showinfo("저장 완료", f"CSV 저장 완료:\n{path}")

    def _show_text_report(self):
        if not self.results:
            messagebox.showwarning("결과 없음", "저장된 분석 결과가 없습니다.")
            return
        win = tk.Toplevel(self.root)
        win.title("📄 탐지 보고서")
        win.geometry("700x520")
        win.configure(bg=BG_DARK)
        text = scrolledtext.ScrolledText(win, font=FONT_CODE, bg=BG_INPUT,
                                          fg=TEXT_PRI, relief="flat", bd=8)
        text.pack(fill="both", expand=True, padx=16, pady=16)
        text.insert("1.0", generate_text_report(self.results))
        text.config(state="disabled")

    def _clear_results(self):
        if messagebox.askyesno("초기화", "결과 목록을 모두 지울까요?"):
            self.results.clear()
            self._refresh_results_tree()


    # ─── KISA 위협정보 탭 ──────────────────────────

    def _build_kisa_tab(self, parent):
        # 상단 안내 카드
        info = _card(parent)
        info.pack(fill="x", padx=20, pady=(16, 8))
        _label(info, "🛡️  OpenPhish 위협 인텔리전스 연동",
               font=FONT_T, bg=BG_CARD).pack(anchor="w", padx=14, pady=(10, 2))
        _label(info,
               "OpenPhish 실시간 피싱 URL 공개 피드를 수신하여 "
               "URL 분석 시 공식 차단 목록과 자동으로 대조합니다. (API 키 불필요)",
               font=FONT_S, bg=BG_CARD, fg=TEXT_SEC, wraplength=880, justify="left"
               ).pack(anchor="w", padx=14, pady=(0, 10))

        # 제어 버튼 행
        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", padx=20, pady=6)

        tk.Button(ctrl, text="  🔄  목록 갱신 (OpenPhish 피드)  ",
                  font=FONT_B, bg=ACCENT, fg=BG_DARK,
                  relief="flat", cursor="hand2", bd=0, pady=8,
                  command=self._kisa_refresh).pack(side="left")

        self.kisa_stat_var = tk.StringVar(value="차단 목록 미로드")
        _label(ctrl, "", textvariable=self.kisa_stat_var,
               font=FONT_S, fg=TEXT_SEC).pack(side="left", padx=12)

        # 통계 카드 행
        stat_row = tk.Frame(parent, bg=BG_DARK)
        stat_row.pack(fill="x", padx=20, pady=4)

        self.kisa_total_var  = tk.StringVar(value="—")
        self.kisa_update_var = tk.StringVar(value="—")
        self.kisa_src_var    = tk.StringVar(value="—")

        for label_text, var, icon in [
            ("총 차단 URL 수",  self.kisa_total_var,  "📦"),
            ("마지막 갱신",     self.kisa_update_var, "🕐"),
            ("데이터 출처",     self.kisa_src_var,    "🏛️"),
        ]:
            sc = _card(stat_row)
            sc.pack(side="left", fill="y", padx=(0, 10), ipadx=16, ipady=10)
            _label(sc, f"{icon}  {label_text}", font=FONT_S, fg=TEXT_SEC, bg=BG_CARD).pack(anchor="w", padx=8, pady=(8,2))
            tk.Label(sc, textvariable=var, font=FONT_B,
                     bg=BG_CARD, fg=ACCENT).pack(anchor="w", padx=8, pady=(0,8))

        # 로그 영역
        _label(parent, "피드 수신 로그", font=FONT_B).pack(anchor="w", padx=20, pady=(10, 2))
        log_card = _card(parent)
        log_card.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        self.kisa_log = scrolledtext.ScrolledText(
            log_card, font=FONT_CODE, bg=BG_INPUT, fg=TEXT_PRI,
            relief="flat", bd=4, state="disabled", wrap="word")
        self.kisa_log.pack(fill="both", expand=True, padx=8, pady=8)

        # 사용 안내
        guide = _card(parent)
        guide.pack(fill="x", padx=20, pady=(0, 20))
        _label(guide, "📌 OpenPhish 피드 사용 안내", font=FONT_B, bg=BG_CARD
               ).pack(anchor="w", padx=14, pady=(10, 4))
        steps = [
            "① '🔄 목록 갱신' 버튼 → OpenPhish 실시간 피싱 URL 목록 수신 (API 키 불필요)",
            "② 수신된 목록은 cache/blocklist.json 에 저장 (24시간 캐시)",
            "③ URL 분석 시 이 목록과 자동 대조 → 적중 시 위험도 100% 고정",
            "",
            "  ※ OpenPhish는 전 세계 피싱 URL을 실시간 집계하는 무료 공개 위협 피드입니다.",
            "  ※ 국내 불법 사이트 신고는 '📢 신고 안내' 탭의 기관을 이용하세요.",
        ]
        for step in steps:
            _label(guide, step, font=FONT_S, fg=TEXT_SEC, bg=BG_CARD
                   ).pack(anchor="w", padx=14, pady=1)
        tk.Frame(guide, bg=BG_CARD, height=10).pack()

        # 초기 통계 로드
        self._kisa_load_stats()

    def _kisa_log_write(self, text):
        self.kisa_log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.kisa_log.insert("end", f"[{ts}]  {text}\n")
        self.kisa_log.see("end")
        self.kisa_log.config(state="disabled")

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
                self.kisa_stat_var.set("차단 목록 없음 — '🔄 목록 갱신' 버튼을 눌러주세요")
        except Exception as e:
            self.kisa_stat_var.set(f"통계 로드 실패: {e}")

    def _kisa_refresh(self):
        self.kisa_stat_var.set("🔄 OpenPhish 피드 수신 중...")
        self._kisa_log_write("피드 갱신 시작...")
        threading.Thread(target=self._kisa_refresh_worker, daemon=True).start()

    def _kisa_refresh_worker(self):
        try:
            from model.kisa_feed import refresh_blocklist
            entries, status = refresh_blocklist(force=True)
            self.q.put(("kisa_done", (entries, status)))
        except Exception as e:
            self.q.put(("kisa_error", str(e)))

    def _build_report_tab(self, parent):
        canvas = tk.Canvas(parent, bg=BG_DARK, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG_DARK)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: (canvas.configure(scrollregion=canvas.bbox("all")),
                               canvas.itemconfig(wid, width=e.width)))
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        _label(inner, "📢 불법 사이트 신고 기관 안내",
               font=FONT_T).pack(anchor="w", padx=24, pady=(20, 4))
        _label(inner, "탐지된 불법·유해 사이트는 아래 기관에 신고할 수 있습니다.",
               font=FONT_S, fg=TEXT_SEC).pack(anchor="w", padx=24, pady=(0, 12))

        AGENCIES = [
            ("🏛️  방송통신심의위원회",
             "인터넷 유해 정보 (불법 도박, 불법 스트리밍, 성인물 등) 신고",
             "https://www.kocsc.or.kr",
             "위법·유해 정보 신고 → '신고하기' 메뉴"),
            ("🛡️  KISA 사이버침해대응센터",
             "사이버 범죄, 피싱, 악성코드, 개인정보 침해 신고  /  전화: 118",
             "https://www.krcert.or.kr",
             "신고·상담 → 인터넷 침해사고 신고"),
            ("👮  경찰청 사이버범죄 신고시스템",
             "불법 도박, 불법 촬영물 유포, 사기 등 형사 사건 신고",
             "https://ecrm.police.go.kr",
             "사이버범죄 신고 → 범죄 유형 선택"),
            ("🎰  불법도박 신고센터 (사행산업통합감독위원회)",
             "불법 스포츠 도박, 온라인 카지노 등 전문 신고 채널",
             "https://www.kgef.or.kr",
             "불법도박 신고 메뉴"),
            ("📹  디지털성범죄피해자지원센터",
             "불법 촬영물, 성적 착취물 유포 피해 신고 및 삭제 지원",
             "https://d4u.stop.or.kr",
             "긴급 신고 및 삭제 지원 신청"),
        ]

        for icon_name, desc, url, guide in AGENCIES:
            c = _card(inner)
            c.pack(fill="x", padx=24, pady=6)
            _label(c, icon_name, font=FONT_B, bg=BG_CARD).pack(anchor="w", padx=14, pady=(10, 2))
            _label(c, desc, font=FONT_S, fg=TEXT_SEC, bg=BG_CARD).pack(anchor="w", padx=14)
            _label(c, f"🔗 {url}", font=("Consolas", 9), fg=ACCENT, bg=BG_CARD).pack(anchor="w", padx=14)
            _label(c, f"📌 {guide}", font=FONT_S, fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w", padx=14, pady=(0, 10))

        # 법적 안내
        law = _card(inner)
        law.pack(fill="x", padx=24, pady=(8, 24))
        _label(law, "⚖️  관련 법령", font=FONT_B, bg=BG_CARD).pack(anchor="w", padx=14, pady=(10, 4))
        laws = [
            "• 불법 도박 운영·이용: 국민체육진흥법, 형법 제247조 (도박장 개설)",
            "• 불법 스트리밍·웹툰 유포: 저작권법 제136조 (저작재산권 침해)",
            "• 불법 성인물 유포: 정보통신망법 제74조, 성폭력처벌법 제14조",
            "• 무단 크롤링/스크래핑: 정보통신망법 제48조 (무단 접근 금지)",
        ]
        for law_text in laws:
            _label(law, law_text, font=FONT_S, fg=TEXT_SEC, bg=BG_CARD).pack(anchor="w", padx=14, pady=2)
        tk.Frame(law, bg=BG_CARD, height=10).pack()

    # ─── 큐 폴링 (스레드 → UI) ────────────────────

    def _poll_queue(self):
        try:
            while True:
                msg, data = self.q.get_nowait()

                if msg == "single_done":
                    self._show_single_result(data)

                elif msg == "single_error":
                    self.single_status.set(f"❌ 오류: {data}")

                elif msg == "batch_progress":
                    i, total, url = data
                    self.batch_progress["value"] = i
                    self.batch_prog_var.set(f"{i}/{total}  —  {url[:50]}")

                elif msg == "batch_item_done":
                    r = data
                    self._batch_log(
                        f"[{r['risk_label']}] {r['category_icon']} {r['url'][:60]}  "
                        f"({r['confidence']}%)"
                    )
                    self._refresh_results_tree()

                elif msg == "batch_item_error":
                    url, err = data
                    self._batch_log(f"[오류] {url[:60]}  → {err}")

                elif msg == "batch_all_done":
                    self.batch_prog_var.set(f"✅ 완료 — {data}개 분석")
                    self.stat_var.set(f"총 {len(self.results)}건 누적")

                elif msg == "kisa_done":
                    entries, status = data
                    self.kisa_stat_var.set(f"✅ {status}")
                    self._kisa_log_write(f"갱신 완료: {status}")
                    self._kisa_load_stats()

                elif msg == "kisa_error":
                    self.kisa_stat_var.set(f"❌ 오류: {data}")
                    self._kisa_log_write(f"오류: {data}")

        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)
