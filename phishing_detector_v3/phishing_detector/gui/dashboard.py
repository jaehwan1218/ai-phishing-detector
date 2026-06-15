"""
피싱 탐지 시스템 v2 — Tkinter 대시보드
탭: URL 탐지 | 이메일 탐지 | 큐싱(QR) 스캐너 | XAI 분석 | 모델 비교
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import io
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# ─── 한글 폰트 설정 ────────────────────────────────
def _set_korean_font():
    candidates = [
        "Malgun Gothic", "맑은 고딕", "NanumGothic", "NotoSansCJK",
        "AppleGothic", "UnDotum",
    ]
    available = {f.name for f in fm.fontManager.ttflist}
    for name in candidates:
        if name in available:
            plt.rcParams["font.family"] = name
            break
    else:
        plt.rcParams["font.family"] = "DejaVu Sans"
    plt.rcParams["axes.unicode_minus"] = False

_set_korean_font()

# ─── 팔레트 ──────────────────────────────────────────
BG_DARK    = "#0d1117"
BG_CARD    = "#161b22"
BG_INPUT   = "#21262d"
BORDER     = "#30363d"
ACCENT_BLUE = "#58a6ff"
ACCENT_GRN  = "#3fb950"
ACCENT_RED  = "#f85149"
ACCENT_ORG  = "#d29922"
ACCENT_PUR  = "#bc8cff"
TEXT_PRI   = "#e6edf3"
TEXT_SEC   = "#8b949e"
TEXT_MUTED = "#484f58"
FONT_MAIN  = ("맑은 고딕", 11)
FONT_BOLD  = ("맑은 고딕", 11, "bold")
FONT_TITLE = ("맑은 고딕", 14, "bold")
FONT_SMALL = ("맑은 고딕", 9)
FONT_CODE  = ("Consolas", 10)


def risk_color(prob):
    if prob < 30: return ACCENT_GRN
    if prob < 65: return ACCENT_ORG
    return ACCENT_RED

def risk_label(prob):
    if prob < 30: return "✅ 안전"
    if prob < 65: return "⚠️  의심"
    return "🚨 피싱 위험"


# ─── 원형 게이지 ─────────────────────────────────────
class RiskGauge(tk.Canvas):
    def __init__(self, parent, size=150, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=BG_CARD, highlightthickness=0, **kw)
        self.size = size
        self._draw_empty()

    def _draw_empty(self):
        self.delete("all")
        cx = cy = self.size // 2
        r = cx - 12
        self.create_oval(cx-r, cy-r, cx+r, cy+r,
                         outline=BORDER, width=10, fill=BG_CARD)
        self.create_text(cx, cy,   text="—",    font=("맑은 고딕", 18, "bold"), fill=TEXT_SEC)
        self.create_text(cx, cy+22, text="분석 전", font=FONT_SMALL, fill=TEXT_MUTED)

    def update_gauge(self, prob):
        self.delete("all")
        cx = cy = self.size // 2
        r = cx - 12
        color = risk_color(prob)
        self.create_oval(cx-r, cy-r, cx+r, cy+r, outline=BORDER, width=10, fill=BG_CARD)
        if prob > 0:
            self.create_arc(cx-r, cy-r, cx+r, cy+r,
                            start=225, extent=-(prob/100)*270,
                            outline=color, width=10, style="arc")
        self.create_text(cx, cy-6,  text=f"{prob:.0f}%", font=("맑은 고딕", 20, "bold"), fill=color)
        self.create_text(cx, cy+18, text=risk_label(prob), font=FONT_SMALL, fill=color)


# ─── Matplotlib 다크 차트 헬퍼 ───────────────────────
def _make_figure(w=5.2, h=3.2):
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(BG_CARD)
    ax.set_facecolor(BG_INPUT)
    for spine in ax.spines.values():
        spine.set_edgecolor(BORDER)
    ax.tick_params(colors=TEXT_SEC, labelsize=8)
    ax.xaxis.label.set_color(TEXT_SEC)
    ax.yaxis.label.set_color(TEXT_SEC)
    ax.title.set_color(TEXT_PRI)
    return fig, ax

def _embed_figure(fig, parent):
    canvas = FigureCanvasTkAgg(fig, master=parent)
    canvas.draw()
    return canvas.get_tk_widget()


# ─────────────────────────────────────────────────────
# 메인 대시보드
# ─────────────────────────────────────────────────────
class PhishingDashboard:
    def __init__(self, root, trainer):
        self.root = root
        self.trainer = trainer
        self.q = queue.Queue()
        self._qr_result = None
        self._current_url_result = None

        root.title("🛡️  피싱 탐지 시스템 v2  |  QR + XAI")
        root.geometry("980x720")
        root.minsize(860, 620)
        root.configure(bg=BG_DARK)
        self._center(root)
        self._apply_style()
        self._build_header()
        self._build_tabs()
        self._poll()

    def _center(self, w):
        w.update_idletasks()
        x = (w.winfo_screenwidth()  - 980) // 2
        y = (w.winfo_screenheight() - 720) // 2
        w.geometry(f"980x720+{x}+{y}")

    def _apply_style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure(".", background=BG_DARK, foreground=TEXT_PRI,
                    font=FONT_MAIN, borderwidth=0)
        s.configure("TNotebook", background=BG_DARK, borderwidth=0, tabmargins=[0,0,0,0])
        s.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_SEC,
                    padding=[14, 8], font=FONT_MAIN, borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", BG_DARK)],
              foreground=[("selected", ACCENT_BLUE)])

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG_CARD, height=62)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🛡️  ML 피싱 탐지 시스템 v2",
                 font=("맑은 고딕", 16, "bold"), bg=BG_CARD, fg=TEXT_PRI
                 ).pack(side="left", padx=20, pady=14)
        badge = (f"URL 최적: {self.trainer.best_url_model_name}  │  "
                 f"이메일 최적: {self.trainer.best_email_model_name}  │  QR+XAI 탑재")
        tk.Label(hdr, text=badge, font=FONT_SMALL, bg=BG_CARD,
                 fg=ACCENT_BLUE).pack(side="right", padx=20)

    def _build_tabs(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)
        self.nb = nb
        tabs = [
            ("  🔗  URL 탐지  ",  self._build_url_tab),
            ("  📧  이메일 탐지  ", self._build_email_tab),
            ("  📷  QR 스캐너  ", self._build_qr_tab),
            ("  🧠  XAI 분석  ",  self._build_xai_tab),
            ("  📊  모델 비교  ",  self._build_compare_tab),
        ]
        for title, builder in tabs:
            frame = tk.Frame(nb, bg=BG_DARK)
            nb.add(frame, text=title)
            builder(frame)

    # ══════════════════════════════════════════════════
    # 탭 1: URL 탐지
    # ══════════════════════════════════════════════════
    def _build_url_tab(self, parent):
        p = dict(padx=20, pady=6)

        # 모델 선택
        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", **p)
        tk.Label(ctrl, text="사용 모델:", font=FONT_MAIN, bg=BG_DARK, fg=TEXT_SEC).pack(side="left")
        self.url_model_var = tk.StringVar(value=self.trainer.best_url_model_name)
        for name in self.trainer.url_models:
            tk.Radiobutton(ctrl, text=name, variable=self.url_model_var, value=name,
                           bg=BG_DARK, fg=TEXT_PRI, selectcolor=BG_CARD,
                           activebackground=BG_DARK, activeforeground=ACCENT_BLUE,
                           font=FONT_MAIN).pack(side="left", padx=10)

        tk.Label(parent, text="분석할 URL 입력", font=FONT_BOLD,
                 bg=BG_DARK, fg=TEXT_PRI).pack(anchor="w", padx=20, pady=(4,2))
        row = tk.Frame(parent, bg=BG_DARK)
        row.pack(fill="x", padx=20)
        self.url_entry = tk.Entry(row, font=FONT_CODE, bg=BG_INPUT, fg=TEXT_PRI,
                                  insertbackground=TEXT_PRI, relief="flat", bd=8)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.url_entry.insert(0, "https://")
        self.url_entry.bind("<Return>", lambda e: self._run_url())
        tk.Button(row, text="  분석  ", font=FONT_BOLD, bg=ACCENT_BLUE, fg=BG_DARK,
                  relief="flat", cursor="hand2", bd=0, padx=10, pady=6,
                  command=self._run_url).pack(side="left", padx=(8,0))

        # 예시
        ex = tk.Frame(parent, bg=BG_DARK)
        ex.pack(fill="x", padx=20, pady=(4,0))
        tk.Label(ex, text="예시:", font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED).pack(side="left")
        for lbl, url in [("정상", "https://www.google.com/search?q=python"),
                          ("피싱", "http://verify-account-abc123.xyz/login?user=test@fake")]:
            tk.Button(ex, text=lbl, font=FONT_SMALL, bg=BG_INPUT, fg=TEXT_SEC,
                      relief="flat", cursor="hand2", bd=0, padx=8,
                      command=lambda u=url: self._set_url(u)).pack(side="left", padx=3)
        # XAI 바로가기
        tk.Button(ex, text="🧠 XAI 분석 보기", font=FONT_SMALL,
                  bg=BG_INPUT, fg=ACCENT_PUR, relief="flat", cursor="hand2", bd=0, padx=8,
                  command=lambda: self.nb.select(3)).pack(side="right", padx=3)

        # 결과
        res = tk.Frame(parent, bg=BG_DARK)
        res.pack(fill="both", expand=True, padx=20, pady=8)

        gauge_card = tk.Frame(res, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        gauge_card.pack(side="left", fill="y", padx=(0,12))
        tk.Label(gauge_card, text="위험도", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_SEC).pack(pady=(12,4))
        self.url_gauge = RiskGauge(gauge_card)
        self.url_gauge.pack(padx=16, pady=(0,12))

        feat_card = tk.Frame(res, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        feat_card.pack(side="left", fill="both", expand=True)
        tk.Label(feat_card, text="📐 URL 구조 특징 분석", font=FONT_BOLD,
                 bg=BG_CARD, fg=TEXT_PRI).pack(anchor="w", padx=12, pady=8)
        self.url_feat_frame = tk.Frame(feat_card, bg=BG_CARD)
        self.url_feat_frame.pack(fill="both", expand=True, padx=12, pady=(0,12))
        tk.Label(self.url_feat_frame, text="URL을 입력하고 분석하세요.",
                 font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w")

    def _set_url(self, url):
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, url)

    def _run_url(self):
        url = self.url_entry.get().strip()
        if not url or url == "https://": return
        self._current_url = url
        result = self.trainer.predict_url(url, self.url_model_var.get())
        self._current_url_result = result
        prob = result["probability"]
        self.url_gauge.update_gauge(prob)

        from model.features import URL_FEATURE_NAMES
        for w in self.url_feat_frame.winfo_children(): w.destroy()
        feats = result["features"]
        for i, (name, val) in enumerate(zip(URL_FEATURE_NAMES, feats)):
            is_risky = (
                (i==1 and val>0) or (i==6 and val>0) or
                (i==7 and val==0) or (i==11 and val>2) or (i==0 and val>60)
            )
            color = ACCENT_RED if is_risky else ACCENT_GRN
            row = tk.Frame(self.url_feat_frame, bg=BG_CARD)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"• {name}:", font=FONT_SMALL, bg=BG_CARD,
                     fg=TEXT_SEC, width=18, anchor="w").pack(side="left")
            display = ("예" if val==1 and "여부" in name else
                       "아니오" if val==0 and "여부" in name else str(int(val)))
            tk.Label(row, text=display, font=("맑은 고딕",9,"bold"),
                     bg=BG_CARD, fg=color).pack(side="left")

    # ══════════════════════════════════════════════════
    # 탭 2: 이메일 탐지
    # ══════════════════════════════════════════════════
    def _build_email_tab(self, parent):
        p = dict(padx=20, pady=6)
        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", **p)
        tk.Label(ctrl, text="사용 모델:", font=FONT_MAIN, bg=BG_DARK, fg=TEXT_SEC).pack(side="left")
        self.email_model_var = tk.StringVar(value=self.trainer.best_email_model_name)
        for name in self.trainer.email_models:
            tk.Radiobutton(ctrl, text=name, variable=self.email_model_var, value=name,
                           bg=BG_DARK, fg=TEXT_PRI, selectcolor=BG_CARD,
                           activebackground=BG_DARK, activeforeground=ACCENT_BLUE,
                           font=FONT_MAIN).pack(side="left", padx=10)

        tk.Label(parent, text="이메일 본문 붙여넣기", font=FONT_BOLD,
                 bg=BG_DARK, fg=TEXT_PRI).pack(anchor="w", padx=20, pady=(4,2))
        inp = tk.Frame(parent, bg=BG_INPUT, highlightbackground=BORDER, highlightthickness=1)
        inp.pack(fill="x", padx=20)
        self.email_text = scrolledtext.ScrolledText(
            inp, font=FONT_CODE, bg=BG_INPUT, fg=TEXT_PRI,
            insertbackground=TEXT_PRI, relief="flat", height=7, wrap="word", bd=0)
        self.email_text.pack(fill="x", padx=8, pady=8)

        ex = tk.Frame(parent, bg=BG_DARK)
        ex.pack(fill="x", padx=20, pady=(4,0))
        tk.Label(ex, text="예시:", font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED).pack(side="left")
        EXMPL = [
            ("정상", "Dear John, your order #84921 has been shipped. Expected delivery: 2024-06-15."),
            ("피싱", "URGENT: Your account has been SUSPENDED! Click immediately: http://verify-account-abc.xyz/login  ACTION REQUIRED!!!"),
        ]
        for lbl, t in EXMPL:
            tk.Button(ex, text=lbl, font=FONT_SMALL, bg=BG_INPUT, fg=TEXT_SEC,
                      relief="flat", cursor="hand2", bd=0, padx=8,
                      command=lambda tt=t: self._set_email(tt)).pack(side="left", padx=3)
        tk.Button(ex, text="🧠 XAI 단어 기여도", font=FONT_SMALL,
                  bg=BG_INPUT, fg=ACCENT_PUR, relief="flat", cursor="hand2", bd=0, padx=8,
                  command=lambda: self.nb.select(3)).pack(side="right", padx=3)

        tk.Button(parent, text="  🔍  이메일 분석하기  ",
                  font=FONT_BOLD, bg=ACCENT_BLUE, fg=BG_DARK,
                  relief="flat", cursor="hand2", bd=0, pady=8,
                  command=self._run_email).pack(pady=8)

        res = tk.Frame(parent, bg=BG_DARK)
        res.pack(fill="both", expand=True, padx=20, pady=(0,16))

        gc = tk.Frame(res, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        gc.pack(side="left", fill="y", padx=(0,12))
        tk.Label(gc, text="위험도", font=FONT_SMALL, bg=BG_CARD, fg=TEXT_SEC).pack(pady=(12,4))
        self.email_gauge = RiskGauge(gc)
        self.email_gauge.pack(padx=16, pady=(0,12))

        kc = tk.Frame(res, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        kc.pack(side="left", fill="both", expand=True)
        tk.Label(kc, text="🔑 피싱 키워드 탐지", font=FONT_BOLD,
                 bg=BG_CARD, fg=TEXT_PRI).pack(anchor="w", padx=12, pady=8)
        self.kw_frame = tk.Frame(kc, bg=BG_CARD)
        self.kw_frame.pack(fill="both", expand=True, padx=12, pady=(0,12))
        tk.Label(self.kw_frame, text="이메일을 입력하고 분석하세요.",
                 font=FONT_SMALL, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w")

    def _set_email(self, text):
        self.email_text.delete("1.0", "end")
        self.email_text.insert("1.0", text)

    def _run_email(self):
        text = self.email_text.get("1.0", "end").strip()
        if not text: return
        self._current_email = text
        result = self.trainer.predict_email(text, self.email_model_var.get())
        self.email_gauge.update_gauge(result["probability"])

        for w in self.kw_frame.winfo_children(): w.destroy()
        from model.features import PHISHING_EMAIL_KEYWORDS
        text_lower = text.lower()
        found = [(kw, text_lower.count(kw)) for kw in PHISHING_EMAIL_KEYWORDS if text_lower.count(kw)>0]
        found.sort(key=lambda x: -x[1])
        if found:
            tk.Label(self.kw_frame, text="탐지된 피싱 키워드:", font=FONT_SMALL,
                     bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            for kw, cnt in found[:12]:
                row = tk.Frame(self.kw_frame, bg=BG_CARD)
                row.pack(fill="x", pady=1)
                color = ACCENT_RED if cnt>=2 else ACCENT_ORG
                tk.Label(row, text=f"  ⚠ {kw}", font=FONT_SMALL, bg=BG_CARD,
                         fg=color, width=22, anchor="w").pack(side="left")
                tk.Label(row, text=f"×{cnt}", font=("맑은 고딕",9,"bold"),
                         bg=BG_CARD, fg=color).pack(side="left")
        else:
            tk.Label(self.kw_frame, text="✅ 피싱 키워드 미탐지",
                     font=FONT_SMALL, bg=BG_CARD, fg=ACCENT_GRN).pack(anchor="w")

        import re
        urls_in = re.findall(r"https?://\S+", text)
        if urls_in:
            tk.Label(self.kw_frame, text=f"\n포함 URL ({len(urls_in)}개):",
                     font=FONT_SMALL, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            for u in urls_in[:3]:
                ur = self.trainer.predict_url(u)
                tk.Label(self.kw_frame,
                         text=f"  {u[:52]}…" if len(u)>52 else f"  {u}",
                         font=("Consolas",8), bg=BG_CARD,
                         fg=risk_color(ur["probability"])).pack(anchor="w")

    # ══════════════════════════════════════════════════
    # 탭 3: QR 스캐너 (큐싱 탐지)
    # ══════════════════════════════════════════════════
    def _build_qr_tab(self, parent):
        # 안내 카드
        info = tk.Frame(parent, bg=BG_CARD,
                        highlightbackground=ACCENT_ORG, highlightthickness=1)
        info.pack(fill="x", padx=20, pady=(16,8))
        tk.Label(info, text="📷  큐싱(Qshing) QR코드 피싱 탐지",
                 font=FONT_TITLE, bg=BG_CARD, fg=TEXT_PRI).pack(anchor="w", padx=14, pady=(10,2))
        tk.Label(info,
                 text="QR코드가 포함된 이미지(JPG/PNG/BMP)를 업로드하면, QR에 숨겨진 URL을 자동 추출하여 피싱 여부를 검사합니다.",
                 font=FONT_SMALL, bg=BG_CARD, fg=TEXT_SEC, wraplength=860, justify="left"
                 ).pack(anchor="w", padx=14, pady=(0,10))

        # 업로드 버튼
        btn_row = tk.Frame(parent, bg=BG_DARK)
        btn_row.pack(fill="x", padx=20, pady=4)
        tk.Button(btn_row, text="  📂  이미지 파일 열기  ",
                  font=FONT_BOLD, bg=ACCENT_BLUE, fg=BG_DARK,
                  relief="flat", cursor="hand2", bd=0, pady=8,
                  command=self._qr_open_file).pack(side="left")
        self.qr_file_label = tk.Label(btn_row, text="파일 미선택",
                                       font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED)
        self.qr_file_label.pack(side="left", padx=12)

        # 결과 영역
        res = tk.Frame(parent, bg=BG_DARK)
        res.pack(fill="both", expand=True, padx=20, pady=8)

        # 이미지 미리보기
        left = tk.Frame(res, bg=BG_CARD,
                        highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="y", padx=(0,12))
        tk.Label(left, text="이미지 미리보기", font=FONT_SMALL,
                 bg=BG_CARD, fg=TEXT_SEC).pack(pady=(10,4))
        self.qr_img_label = tk.Label(left, bg=BG_CARD, fg=TEXT_MUTED,
                                      text="이미지 없음\n(200×200)", width=22, height=10)
        self.qr_img_label.pack(padx=12, pady=(0,12))

        # 탐지 결과
        right = tk.Frame(res, bg=BG_CARD,
                         highlightbackground=BORDER, highlightthickness=1)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="🔍 QR 탐지 결과", font=FONT_BOLD,
                 bg=BG_CARD, fg=TEXT_PRI).pack(anchor="w", padx=12, pady=8)
        self.qr_result_text = scrolledtext.ScrolledText(
            right, font=FONT_CODE, bg=BG_INPUT, fg=TEXT_PRI,
            relief="flat", bd=4, height=18, state="disabled", wrap="word")
        self.qr_result_text.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # 발견된 URL → URL 탐지 탭 연동 버튼
        self.qr_goto_btn = tk.Button(
            right, text="→ 추출된 URL을 URL 탐지 탭으로 보내기",
            font=FONT_SMALL, bg=BG_INPUT, fg=ACCENT_BLUE,
            relief="flat", cursor="hand2", bd=0, pady=6,
            command=self._qr_send_to_url_tab, state="disabled")
        self.qr_goto_btn.pack(fill="x", padx=8, pady=(0,8))

    def _qr_open_file(self):
        path = filedialog.askopenfilename(
            title="QR코드 이미지 선택",
            filetypes=[("이미지 파일", "*.png *.jpg *.jpeg *.bmp *.gif *.webp"),
                       ("모든 파일", "*.*")]
        )
        if not path: return
        self.qr_file_label.config(text=os.path.basename(path), fg=TEXT_PRI)
        threading.Thread(target=self._qr_worker, args=(path,), daemon=True).start()

    def _qr_worker(self, path):
        try:
            # 이미지 미리보기
            from PIL import Image, ImageTk
            img = Image.open(path).convert("RGB")
            img.thumbnail((200, 200))
            photo = ImageTk.PhotoImage(img)
            self.q.put(("qr_preview", photo))

            # QR 디코딩
            from model.qr_scanner import decode_qr_from_path
            qr_items = decode_qr_from_path(path)
            self.q.put(("qr_decoded", (path, qr_items)))

        except Exception as e:
            self.q.put(("qr_error", str(e)))

    def _qr_show_result(self, path, qr_items):
        self.qr_result_text.config(state="normal")
        self.qr_result_text.delete("1.0", "end")
        lines = []

        if not qr_items:
            lines.append("❌ QR코드를 탐지하지 못했습니다.")
            lines.append("")
            lines.append("확인 사항:")
            lines.append("  • 이미지에 QR코드가 선명하게 포함되어 있는지 확인하세요.")
            lines.append("  • 지원 형식: JPG, PNG, BMP")
        else:
            lines.append(f"✅ QR코드 {len(qr_items)}개 탐지됨\n")
            self._qr_extracted_urls = []
            for i, item in enumerate(qr_items, 1):
                data   = item["data"]
                qrtype = item["type"]
                rect   = item["rect"]
                lines.append(f"[QR #{i}]  타입: {qrtype}")
                lines.append(f"  위치: x={rect['left']}, y={rect['top']}, "
                             f"w={rect['width']}, h={rect['height']}")
                lines.append(f"  내용: {data}")

                # URL이면 피싱 검사
                if data.startswith("http"):
                    self._qr_extracted_urls.append(data)
                    result = self.trainer.predict_url(data)
                    prob   = result["probability"]
                    label  = risk_label(prob)
                    lines.append(f"  ─ 피싱 검사 → {label}  ({prob:.1f}%)")
                    if prob >= 65:
                        lines.append(f"  🚨 고위험 URL 탐지! 접속하지 마세요.")
                    elif prob >= 30:
                        lines.append(f"  ⚠️  의심 URL 탐지. 주의가 필요합니다.")
                    else:
                        lines.append(f"  ✅ 안전한 URL로 판단됩니다.")
                else:
                    lines.append(f"  ℹ️  URL 아닌 데이터 (텍스트/연락처 등)")
                lines.append("")

            if self._qr_extracted_urls:
                self.qr_goto_btn.config(state="normal")

        self.qr_result_text.insert("1.0", "\n".join(lines))
        self.qr_result_text.config(state="disabled")

    def _qr_send_to_url_tab(self):
        if hasattr(self, "_qr_extracted_urls") and self._qr_extracted_urls:
            url = self._qr_extracted_urls[0]
            self._set_url(url)
            self.nb.select(0)
            self._run_url()

    # ══════════════════════════════════════════════════
    # 탭 4: XAI 분석
    # ══════════════════════════════════════════════════
    def _build_xai_tab(self, parent):
        # 서브탭
        nb2 = ttk.Notebook(parent)
        nb2.pack(fill="both", expand=True, padx=0, pady=0)

        t_url   = tk.Frame(nb2, bg=BG_DARK)
        t_email = tk.Frame(nb2, bg=BG_DARK)
        nb2.add(t_url,   text="  🔗  URL 특징 중요도  ")
        nb2.add(t_email, text="  📧  이메일 단어 기여도  ")

        self._build_xai_url_sub(t_url)
        self._build_xai_email_sub(t_email)

    # ─── XAI 서브탭: URL ─────────────────────────────
    def _build_xai_url_sub(self, parent):
        desc = ("랜덤 포레스트의 feature_importances_ 또는 로지스틱 회귀의 coef_ 를 사용하여 "
                "각 URL 구조 특징이 피싱 판별에 얼마나 기여하는지 시각화합니다.")
        tk.Label(parent, text=desc, font=FONT_SMALL, bg=BG_DARK,
                 fg=TEXT_SEC, wraplength=860, justify="left"
                 ).pack(anchor="w", padx=20, pady=(12,4))

        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", padx=20, pady=4)
        tk.Label(ctrl, text="모델:", font=FONT_MAIN, bg=BG_DARK, fg=TEXT_SEC).pack(side="left")
        self.xai_url_model_var = tk.StringVar(value=self.trainer.best_url_model_name)
        for name in self.trainer.url_models:
            tk.Radiobutton(ctrl, text=name, variable=self.xai_url_model_var, value=name,
                           bg=BG_DARK, fg=TEXT_PRI, selectcolor=BG_CARD,
                           activebackground=BG_DARK, activeforeground=ACCENT_BLUE,
                           font=FONT_MAIN,
                           command=self._draw_url_importance).pack(side="left", padx=8)

        # 현재 URL 기반 샘플 기여도
        srow = tk.Frame(parent, bg=BG_DARK)
        srow.pack(fill="x", padx=20, pady=4)
        tk.Label(srow, text="현재 URL 샘플 기여도:", font=FONT_MAIN,
                 bg=BG_DARK, fg=TEXT_SEC).pack(side="left")
        tk.Button(srow, text="  분석 실행  ", font=FONT_SMALL,
                  bg=ACCENT_PUR, fg=BG_DARK, relief="flat", cursor="hand2", bd=0, padx=8, pady=4,
                  command=self._draw_url_sample).pack(side="left", padx=8)
        tk.Label(srow, text="(URL 탐지 탭에서 먼저 URL을 분석하세요)",
                 font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED).pack(side="left")

        # 차트 영역 (2개 나란히)
        self.xai_url_chart_frame = tk.Frame(parent, bg=BG_DARK)
        self.xai_url_chart_frame.pack(fill="both", expand=True, padx=20, pady=8)
        self._draw_url_importance()

    def _draw_url_importance(self):
        for w in self.xai_url_chart_frame.winfo_children(): w.destroy()
        model_name = self.xai_url_model_var.get()
        data = self.trainer.xai_url_feature_importance(model_name)
        if not data: return

        names = [d["name"] for d in data]
        vals  = [d["importance"] for d in data]
        colors = [ACCENT_RED if d["direction"]=="위험" else ACCENT_BLUE for d in data]

        fig, ax = _make_figure(w=8.5, h=3.8)
        bars = ax.barh(names[::-1], vals[::-1], color=colors[::-1], height=0.6, alpha=0.85)
        ax.set_xlabel("중요도 (%)", color=TEXT_SEC, fontsize=8)
        ax.set_title(f"[{model_name}] URL 특징별 중요도 (Feature Importance)",
                     color=TEXT_PRI, fontsize=10, pad=8)
        ax.axvline(0, color=BORDER, linewidth=0.8)
        for bar, val in zip(bars, vals[::-1]):
            ax.text(val+0.3, bar.get_y()+bar.get_height()/2,
                    f"{val:.1f}%", va="center", ha="left",
                    color=TEXT_SEC, fontsize=7)
        fig.tight_layout()
        widget = _embed_figure(fig, self.xai_url_chart_frame)
        widget.pack(fill="both", expand=True)
        plt.close(fig)

    def _draw_url_sample(self):
        url = getattr(self, "_current_url", None) or self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showinfo("URL 없음", "먼저 URL 탐지 탭에서 URL을 분석하세요.")
            return

        model_name = self.xai_url_model_var.get()
        data = self.trainer.xai_url_sample(url, model_name)
        if not data: return

        # 기존 차트 옆에 샘플 기여도 추가
        for w in self.xai_url_chart_frame.winfo_children(): w.destroy()

        # 전체 중요도 (왼쪽)
        imp_data = self.trainer.xai_url_feature_importance(model_name)
        names_i = [d["name"] for d in imp_data]
        vals_i  = [d["importance"] for d in imp_data]
        colors_i = [ACCENT_RED if d["direction"]=="위험" else ACCENT_BLUE for d in imp_data]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        fig.patch.set_facecolor(BG_CARD)
        for ax in (ax1, ax2):
            ax.set_facecolor(BG_INPUT)
            for spine in ax.spines.values(): spine.set_edgecolor(BORDER)
            ax.tick_params(colors=TEXT_SEC, labelsize=7)
            ax.xaxis.label.set_color(TEXT_SEC)
            ax.title.set_color(TEXT_PRI)

        ax1.barh(names_i[::-1], vals_i[::-1], color=colors_i[::-1], height=0.6, alpha=0.85)
        ax1.set_title("전체 특징 중요도", color=TEXT_PRI, fontsize=9)
        ax1.set_xlabel("중요도 (%)", color=TEXT_SEC, fontsize=7)

        # 샘플 기여도 (오른쪽)
        s_names = [d["name"] for d in data[:10]]
        s_vals  = [d["contribution"] for d in data[:10]]
        s_colors = [ACCENT_RED if v>0 else ACCENT_GRN for v in s_vals]
        ax2.barh(s_names[::-1], s_vals[::-1], color=s_colors[::-1], height=0.6, alpha=0.85)
        ax2.set_title(f"이 URL의 특징 기여도\n{url[:50]}", color=TEXT_PRI, fontsize=8)
        ax2.axvline(0, color=BORDER, linewidth=0.8)
        ax2.set_xlabel("기여도 (양수=피싱방향, 음수=안전방향)", color=TEXT_SEC, fontsize=7)

        fig.tight_layout(pad=1.5)
        widget = _embed_figure(fig, self.xai_url_chart_frame)
        widget.pack(fill="both", expand=True)
        plt.close(fig)

    # ─── XAI 서브탭: 이메일 ──────────────────────────
    def _build_xai_email_sub(self, parent):
        desc = ("TF-IDF 벡터와 모델 계수의 곱으로 각 단어가 피싱 판별에 기여한 정도를 계산합니다.\n"
                "빨강=피싱 방향 기여, 초록=안전 방향 기여")
        tk.Label(parent, text=desc, font=FONT_SMALL, bg=BG_DARK,
                 fg=TEXT_SEC, wraplength=860, justify="left"
                 ).pack(anchor="w", padx=20, pady=(12,4))

        ctrl = tk.Frame(parent, bg=BG_DARK)
        ctrl.pack(fill="x", padx=20, pady=4)
        tk.Label(ctrl, text="모델:", font=FONT_MAIN, bg=BG_DARK, fg=TEXT_SEC).pack(side="left")
        self.xai_email_model_var = tk.StringVar(value=self.trainer.best_email_model_name)
        for name in self.trainer.email_models:
            tk.Radiobutton(ctrl, text=name, variable=self.xai_email_model_var, value=name,
                           bg=BG_DARK, fg=TEXT_PRI, selectcolor=BG_CARD,
                           activebackground=BG_DARK, activeforeground=ACCENT_BLUE,
                           font=FONT_MAIN).pack(side="left", padx=8)
        tk.Button(ctrl, text="  단어 기여도 분석  ", font=FONT_SMALL,
                  bg=ACCENT_PUR, fg=BG_DARK, relief="flat", cursor="hand2", bd=0, padx=10, pady=4,
                  command=self._draw_email_words).pack(side="left", padx=12)
        tk.Label(ctrl, text="(이메일 탐지 탭에서 먼저 이메일을 분석하세요)",
                 font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED).pack(side="left")

        self.xai_email_chart_frame = tk.Frame(parent, bg=BG_DARK)
        self.xai_email_chart_frame.pack(fill="both", expand=True, padx=20, pady=8)
        tk.Label(self.xai_email_chart_frame, text="이메일 탐지 탭에서 분석 후 이 버튼을 누르세요.",
                 font=FONT_SMALL, bg=BG_DARK, fg=TEXT_MUTED).pack(anchor="w")

    def _draw_email_words(self):
        text = getattr(self, "_current_email", None)
        if not text:
            try:
                text = self.email_text.get("1.0", "end").strip()
            except Exception:
                pass
        if not text:
            messagebox.showinfo("이메일 없음", "이메일 탐지 탭에서 이메일을 먼저 분석하세요.")
            return

        model_name = self.xai_email_model_var.get()
        data = self.trainer.xai_email_words(text, model_name)
        if not data:
            messagebox.showinfo("결과 없음", "단어 기여도를 계산할 수 없습니다.\n로지스틱 회귀 모델을 선택해보세요.")
            return

        for w in self.xai_email_chart_frame.winfo_children(): w.destroy()

        words  = [d["word"] for d in data]
        scores = [d["score"] for d in data]
        colors = [ACCENT_RED if s>0 else ACCENT_GRN for s in scores]

        fig, ax = _make_figure(w=8.5, h=3.8)
        bars = ax.barh(words[::-1], scores[::-1], color=colors[::-1], height=0.6, alpha=0.85)
        ax.set_xlabel("기여도 점수  (양수 = 피싱 방향)", color=TEXT_SEC, fontsize=8)
        ax.set_title(f"[{model_name}] 단어별 피싱 판별 기여도 (XAI)",
                     color=TEXT_PRI, fontsize=10, pad=8)
        ax.axvline(0, color=TEXT_PRI, linewidth=0.8, alpha=0.5)
        for bar, val in zip(bars, scores[::-1]):
            ax.text(val + (0.001 if val>=0 else -0.001),
                    bar.get_y()+bar.get_height()/2,
                    f"{val:+.4f}", va="center",
                    ha="left" if val>=0 else "right",
                    color=TEXT_SEC, fontsize=7)
        fig.tight_layout()
        widget = _embed_figure(fig, self.xai_email_chart_frame)
        widget.pack(fill="both", expand=True)
        plt.close(fig)

    # ══════════════════════════════════════════════════
    # 탭 5: 모델 비교 분석
    # ══════════════════════════════════════════════════
    def _build_compare_tab(self, parent):
        canvas = tk.Canvas(parent, bg=BG_DARK, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG_DARK)
        wid = canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: (canvas.configure(scrollregion=canvas.bbox("all")),
                               canvas.itemconfig(wid, width=e.width)))
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))
        self._build_compare_content(inner)

    def _build_compare_content(self, parent):
        tk.Label(parent, text="📊 알고리즘 성능 비교 분석",
                 font=("맑은 고딕",16,"bold"), bg=BG_DARK, fg=TEXT_PRI
                 ).pack(anchor="w", padx=24, pady=(20,4))
        tk.Label(parent,
                 text="Accuracy(정확도) · Precision(정밀도) · Recall(재현율) · F1-Score",
                 font=FONT_SMALL, bg=BG_DARK, fg=TEXT_SEC).pack(anchor="w", padx=24)

        # Matplotlib 비교 차트
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.2))
        fig.patch.set_facecolor(BG_DARK)
        metrics = ["accuracy", "precision", "recall", "f1"]
        m_labels = ["Acc", "Prec", "Rec", "F1"]
        bar_colors = [ACCENT_BLUE, ACCENT_GRN, ACCENT_ORG, ACCENT_PUR]
        x = np.arange(len(m_labels))
        width = 0.25

        for ax, (section, results, best) in zip(axes, [
            ("URL 탐지", self.trainer.url_results, self.trainer.best_url_model_name),
            ("이메일 탐지", self.trainer.email_results, self.trainer.best_email_model_name),
        ]):
            ax.set_facecolor(BG_CARD)
            for spine in ax.spines.values(): spine.set_edgecolor(BORDER)
            ax.tick_params(colors=TEXT_SEC, labelsize=8)
            ax.set_title(section, color=TEXT_PRI, fontsize=10)
            ax.set_xticks(x + width)
            ax.set_xticklabels(m_labels, color=TEXT_SEC)
            ax.set_ylim(0, 115)
            ax.set_ylabel("점수 (%)", color=TEXT_SEC, fontsize=8)
            model_names = list(results.keys())
            for j, (mname, res) in enumerate(results.items()):
                vals = [res[m] for m in metrics]
                offset = (j - 1) * width
                bars = ax.bar(x + offset, vals, width, alpha=0.85,
                              label=mname + (" ★" if mname==best else ""),
                              color=[c for c in bar_colors])
                for bar, val in zip(bars, vals):
                    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1,
                            f"{val:.0f}", ha="center", va="bottom",
                            fontsize=6, color=TEXT_SEC)
            ax.legend(fontsize=7, facecolor=BG_CARD, labelcolor=TEXT_PRI,
                      edgecolor=BORDER)

        fig.tight_layout(pad=1.5)
        chart_frame = tk.Frame(parent, bg=BG_DARK)
        chart_frame.pack(fill="x", padx=24, pady=8)
        widget = _embed_figure(fig, chart_frame)
        widget.pack(fill="x")
        plt.close(fig)

        # 카드형 수치 표
        metrics_full = ["accuracy", "precision", "recall", "f1"]
        m_labels_full = ["Accuracy", "Precision", "Recall", "F1-Score"]
        m_colors_full = [ACCENT_BLUE, ACCENT_GRN, ACCENT_ORG, ACCENT_PUR]

        for section_name, results, best in [
            ("🔗 URL 피싱 탐지", self.trainer.url_results, self.trainer.best_url_model_name),
            ("📧 이메일 피싱 탐지", self.trainer.email_results, self.trainer.best_email_model_name),
        ]:
            sec = tk.Frame(parent, bg=BG_DARK)
            sec.pack(fill="x", padx=24, pady=8)
            tk.Label(sec, text=section_name, font=FONT_TITLE,
                     bg=BG_DARK, fg=TEXT_PRI).pack(anchor="w", pady=(0,6))
            row_w = tk.Frame(sec, bg=BG_DARK)
            row_w.pack(fill="x")
            for mname, res in results.items():
                is_best = mname == best
                card = tk.Frame(row_w, bg=BG_CARD,
                                highlightbackground=ACCENT_BLUE if is_best else BORDER,
                                highlightthickness=2 if is_best else 1)
                card.pack(side="left", fill="y", padx=(0,10), pady=4, ipadx=12, ipady=10)
                hdr2 = tk.Frame(card, bg=BG_CARD)
                hdr2.pack(anchor="w")
                tk.Label(hdr2, text=mname, font=FONT_BOLD,
                         bg=BG_CARD, fg=TEXT_PRI).pack(side="left")
                if is_best:
                    tk.Label(hdr2, text=" ★ 최적", font=("맑은 고딕",9,"bold"),
                             bg=BG_CARD, fg=ACCENT_BLUE).pack(side="left", padx=4)
                tk.Frame(card, bg=BORDER, height=1).pack(fill="x", pady=6)
                for metric, label, color in zip(metrics_full, m_labels_full, m_colors_full):
                    val = res[metric]
                    r2 = tk.Frame(card, bg=BG_CARD)
                    r2.pack(fill="x", pady=2)
                    tk.Label(r2, text=label+":", font=FONT_SMALL, bg=BG_CARD,
                             fg=TEXT_SEC, width=10, anchor="w").pack(side="left")
                    tk.Label(r2, text=f"{val:.1f}%", font=("맑은 고딕",9,"bold"),
                             bg=BG_CARD, fg=color).pack(side="left")
                    bar_f = tk.Frame(card, bg=BG_INPUT, height=6)
                    bar_f.pack(fill="x", padx=4, pady=1)
                    bar_f.pack_propagate(False)
                    tk.Frame(bar_f, bg=color, height=6).place(
                        x=0, y=0, relwidth=val/100, relheight=1)

        # 해석 가이드
        guide = tk.Frame(parent, bg=BG_CARD,
                         highlightbackground=BORDER, highlightthickness=1)
        guide.pack(fill="x", padx=24, pady=(4,24))
        tk.Label(guide, text="📌 지표 해석 가이드", font=FONT_BOLD,
                 bg=BG_CARD, fg=TEXT_PRI).pack(anchor="w", padx=16, pady=(12,4))
        for term, desc in [
            ("Accuracy",  "전체 샘플 중 올바르게 분류한 비율."),
            ("Precision", "피싱으로 예측한 것 중 실제 피싱인 비율. 오탐 최소화."),
            ("Recall",    "실제 피싱 중 탐지 성공 비율. 미탐 최소화."),
            ("F1-Score",  "Precision과 Recall의 조화 평균. 불균형 데이터 적합."),
        ]:
            r2 = tk.Frame(guide, bg=BG_CARD)
            r2.pack(fill="x", padx=16, pady=2)
            tk.Label(r2, text=f"• {term}:", font=("맑은 고딕",10,"bold"),
                     bg=BG_CARD, fg=ACCENT_BLUE, width=12, anchor="w").pack(side="left")
            tk.Label(r2, text=desc, font=FONT_SMALL, bg=BG_CARD, fg=TEXT_SEC).pack(side="left")
        tk.Frame(guide, bg=BG_CARD, height=10).pack()

    # ══════════════════════════════════════════════════
    # 큐 폴링
    # ══════════════════════════════════════════════════
    def _poll(self):
        try:
            while True:
                msg, data = self.q.get_nowait()
                if msg == "qr_preview":
                    self._qr_photo = data   # 참조 유지
                    self.qr_img_label.config(image=data, text="")
                elif msg == "qr_decoded":
                    path, items = data
                    self._qr_show_result(path, items)
                elif msg == "qr_error":
                    messagebox.showerror("QR 오류", data)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)
