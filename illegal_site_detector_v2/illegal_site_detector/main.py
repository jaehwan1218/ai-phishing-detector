"""
불법·유해 사이트 탐지 시스템 — 진입점
실행: python main.py
"""

import tkinter as tk
from gui.dashboard import IllegalSiteDetector


def main():
    root = tk.Tk()
    app = IllegalSiteDetector(root)
    root.mainloop()


if __name__ == "__main__":
    main()
