"""
신고용 리포트 생성 모듈
- CSV 저장 (수사기관 제출용)
- 텍스트 요약 리포트
"""

import csv
import os
from datetime import datetime


def generate_csv_report(results: list, output_path: str = None) -> str:
    """탐지 결과를 CSV로 저장 (수사기관 제출 포맷)"""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(os.path.expanduser("~"), f"불법사이트_탐지보고서_{ts}.csv")

    fieldnames = [
        "탐지시각", "URL", "사이트 제목", "카테고리", "위험등급",
        "신뢰도(%)", "도박점수", "불법OTT점수", "불법스포츠점수", "성인점수",
        "이미지수", "탐지키워드"
    ]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            kw_list = []
            for cat, kws in r.get("matched_keywords", {}).items():
                for kw, cnt in kws[:3]:
                    kw_list.append(f"{kw}({cnt})")
            scores = r.get("scores", {})
            writer.writerow({
                "탐지시각": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "URL": r.get("url", ""),
                "사이트 제목": r.get("title", ""),
                "카테고리": r.get("category_name", ""),
                "위험등급": r.get("risk_label", ""),
                "신뢰도(%)": r.get("confidence", 0),
                "도박점수": scores.get("gambling", 0),
                "불법OTT점수": scores.get("illegal_ott", 0),
                "불법스포츠점수": scores.get("illegal_sports", 0),
                "성인점수": scores.get("adult", 0),
                "이미지수": r.get("image_count", 0),
                "탐지키워드": " / ".join(kw_list[:8]),
            })

    return output_path


def generate_text_report(results: list) -> str:
    """수사기관 제출용 텍스트 요약 리포트"""
    lines = []
    now = datetime.now().strftime("%Y년 %m월 %d일 %H:%M:%S")
    high_risk = [r for r in results if r.get("risk_level") == "HIGH"]

    lines.append("=" * 60)
    lines.append("  불법·유해 사이트 탐지 보고서")
    lines.append(f"  생성일시: {now}")
    lines.append("=" * 60)
    lines.append(f"\n총 분석 사이트: {len(results)}개")
    lines.append(f"고위험 탐지:    {len(high_risk)}개")
    lines.append(f"안전:           {len(results) - len(high_risk)}개\n")

    lines.append("─" * 60)
    lines.append("[ 탐지 상세 내역 ]")
    lines.append("─" * 60)

    for i, r in enumerate(results, 1):
        lines.append(f"\n[{i}] {r.get('url', '')}")
        lines.append(f"    제목:     {r.get('title', '알 수 없음')}")
        lines.append(f"    카테고리: {r.get('category_icon','')} {r.get('category_name','')}")
        lines.append(f"    위험등급: {r.get('risk_label','')}")
        lines.append(f"    신뢰도:   {r.get('confidence', 0)}%")
        kw_all = []
        for cat, kws in r.get("matched_keywords", {}).items():
            for kw, cnt in kws[:3]:
                kw_all.append(kw)
        if kw_all:
            lines.append(f"    탐지키워드: {', '.join(kw_all[:6])}")

    lines.append("\n" + "=" * 60)
    lines.append("  신고 안내")
    lines.append("=" * 60)
    lines.append("  • 방송통신심의위원회: https://www.kocsc.or.kr")
    lines.append("  • KISA 인터넷 침해사고 신고: https://www.krcert.or.kr  /  전화: 118")
    lines.append("  • 경찰청 사이버범죄 신고: https://ecrm.police.go.kr")
    lines.append("  • 불법도박신고센터: https://www.kgef.or.kr")
    lines.append("=" * 60)

    return "\n".join(lines)
