"""
큐싱(Qshing) QR코드 스캐너 모듈
pyzbar + OpenCV로 이미지에서 QR코드를 탐지·디코딩합니다.
"""

import cv2
import numpy as np
from pyzbar import pyzbar
from PIL import Image
import io
import os


def decode_qr_from_path(image_path: str) -> list[dict]:
    """
    이미지 파일 경로에서 QR코드를 모두 탐지하고 디코딩합니다.
    반환: [{data, type, rect}, ...]
    """
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"이미지를 불러올 수 없습니다: {image_path}")
    return _decode_from_cv2(img)


def decode_qr_from_bytes(image_bytes: bytes) -> list[dict]:
    """
    바이트 데이터(파일 업로드 등)에서 QR코드를 탐지합니다.
    """
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("이미지 디코딩 실패")
    return _decode_from_cv2(img)


def _decode_from_cv2(img: np.ndarray) -> list[dict]:
    """
    OpenCV 이미지에서 QR코드를 탐지합니다.
    전처리(그레이스케일, 이진화, 대비 향상)를 거쳐 탐지율을 높입니다.
    """
    results = []
    seen = set()

    # 1차 시도: 원본 이미지
    _try_decode(img, results, seen)

    if not results:
        # 2차 시도: 그레이스케일 변환
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _try_decode(gray, results, seen)

    if not results:
        # 3차 시도: 적응형 이진화 (어두운 이미지 대응)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        thresh = cv2.adaptiveThreshold(
            gray, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 11, 2
        )
        _try_decode(thresh, results, seen)

    if not results:
        # 4차 시도: 대비 향상 (CLAHE)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        _try_decode(enhanced, results, seen)

    return results


def _try_decode(img: np.ndarray, results: list, seen: set):
    decoded = pyzbar.decode(img)
    for obj in decoded:
        try:
            data = obj.data.decode("utf-8")
        except Exception:
            data = obj.data.decode("latin-1", errors="replace")
        if data not in seen:
            seen.add(data)
            rect = obj.rect
            results.append({
                "data": data,
                "type": obj.type,   # QRCODE, CODE128, etc.
                "rect": {
                    "left": rect.left, "top": rect.top,
                    "width": rect.width, "height": rect.height,
                },
            })


def annotate_qr_image(image_path: str, output_path: str = None) -> str:
    """
    QR코드 위치에 바운딩 박스를 그린 주석 이미지를 저장합니다.
    """
    img = cv2.imread(image_path)
    decoded = pyzbar.decode(img)

    for obj in decoded:
        pts = np.array([[p.x, p.y] for p in obj.polygon], dtype=np.int32)
        cv2.polylines(img, [pts], True, (0, 255, 80), 3)
        x, y = obj.rect.left, obj.rect.top
        try:
            label = obj.data.decode("utf-8")[:40]
        except Exception:
            label = "?"
        cv2.putText(img, label, (x, y - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 80), 2)

    if output_path is None:
        base, ext = os.path.splitext(image_path)
        output_path = base + "_annotated" + (ext or ".png")
    cv2.imwrite(output_path, img)
    return output_path
