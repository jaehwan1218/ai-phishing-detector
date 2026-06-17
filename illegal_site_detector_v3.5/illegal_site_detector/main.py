"""
불법·유해 사이트 탐지 시스템 — 진입점
실행: python main.py

[중요] 고해상도(HiDPI) 모니터에서 폰트가 흐려지거나 번지는 현상을 막기 위해,
다른 어떤 GUI 모듈보다 먼저 Windows의 DPI 인식(DPI Awareness)을 설정한다.
이 코드는 반드시 Tk / CustomTkinter 창이 생성되기 '전에' 실행되어야 한다.
"""

import sys
import ctypes


def enable_dpi_awareness():
    """
    Windows 화면 배율(125%·150%·200% 등) 환경에서 글자가 흐릿하게 번지지 않고
    픽셀 단위로 선명하게 렌더링되도록 시스템에 DPI 인식을 명시한다.

    - PER_MONITOR_AWARE_V2(2): 모니터별 배율을 각각 인식 (가장 선명, Win 8.1+)
    - SetProcessDPIAware(): 구형 윈도우 대비 폴백
    macOS / Linux 에서는 호출하지 않는다(자동 처리).
    """
    if not sys.platform.startswith("win"):
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # Per-Monitor v2 (가장 선명)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()      # 구형 OS 폴백
        except Exception:
            pass


# GUI 라이브러리를 import 하기 전에 가장 먼저 호출
enable_dpi_awareness()

import customtkinter as ctk
from gui.dashboard import IllegalSiteDetector


def main():
    root = ctk.CTk()
    app = IllegalSiteDetector(root)
    root.mainloop()


if __name__ == "__main__":
    main()
