"""
머신러닝 기반 실시간 피싱(Phishing) URL 및 이메일 탐지 시스템
기말 프로젝트 - 인공지능 개론
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os

# 모듈 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from model.trainer import PhishingModelTrainer
from gui.dashboard import PhishingDashboard


def main():
    root = tk.Tk()
    root.withdraw()  # 로딩 중 메인 창 숨김

    # 스플래시 스크린
    splash = tk.Toplevel()
    splash.title("")
    splash.geometry("420x220")
    splash.resizable(False, False)
    splash.configure(bg="#0d1117")
    splash.overrideredirect(True)

    # 화면 중앙 정렬
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() - 420) // 2
    y = (splash.winfo_screenheight() - 220) // 2
    splash.geometry(f"420x220+{x}+{y}")

    tk.Label(splash, text="🛡️", font=("Segoe UI Emoji", 36),
             bg="#0d1117", fg="#58a6ff").pack(pady=(28, 4))
    tk.Label(splash, text="피싱 탐지 시스템 초기화 중...",
             font=("맑은 고딕", 13, "bold"), bg="#0d1117", fg="#e6edf3").pack()

    status_var = tk.StringVar(value="데이터 생성 중...")
    tk.Label(splash, textvariable=status_var,
             font=("맑은 고딕", 10), bg="#0d1117", fg="#8b949e").pack(pady=6)

    progress = ttk.Progressbar(splash, length=320, mode="indeterminate")
    progress.pack(pady=8)
    progress.start(12)

    trainer = PhishingModelTrainer()

    def load_models():
        try:
            status_var.set("합성 데이터셋 생성 중...")
            splash.update()
            trainer.generate_synthetic_data()

            status_var.set("특징 추출 (TF-IDF & 구조 분석) 중...")
            splash.update()
            trainer.prepare_features()

            status_var.set("분류 모델 학습 중 (LR / RF / DT)...")
            splash.update()
            trainer.train_all_models()

            status_var.set("완료! 대시보드 시작...")
            splash.update()

        except Exception as e:
            messagebox.showerror("초기화 오류", str(e))
            root.destroy()
            return

        splash.destroy()
        root.deiconify()
        PhishingDashboard(root, trainer)

    thread = threading.Thread(target=load_models, daemon=True)
    thread.start()

    root.mainloop()


if __name__ == "__main__":
    main()
