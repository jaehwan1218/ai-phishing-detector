# 🚨 불법·유해 사이트 탐지 시스템

## 설치 및 실행

```bash
pip install -r requirements.txt
python main.py
```

---

## 📂 구조

```
illegal_site_detector/
├── main.py
├── requirements.txt
├── model/
│   ├── keywords.py     # 카테고리별 키워드·패턴 규칙
│   └── analyzer.py     # URL + 텍스트 + 이미지 종합 분류
├── crawler/
│   └── fetcher.py      # robots.txt 준수 크롤러 + 이미지 해시 수집
├── gui/
│   └── dashboard.py    # Tkinter 4탭 대시보드
└── report/
    └── generator.py    # CSV·텍스트 신고용 리포트 생성
```

---

## 🔍 탐지 카테고리

| 카테고리 | 탐지 방식 |
|---|---|
| 🎰 불법 도박 | 베팅·카지노·토토 키워드, 입금계좌 패턴 |
| 🎬 불법 OTT·웹툰 | 무료 스트리밍·다운로드·토렌트 키워드 |
| ⚽ 불법 스포츠 중계 | 무료 중계·생중계 키워드 |
| 🔞 성인 유해 콘텐츠 | 성인·음란 관련 키워드 |

---

## ⚖️ 법적 준수 사항

- **robots.txt 자동 확인**: 크롤링 불허 사이트는 분석 건너뜀
- **Rate Limiting**: 요청 간 1.5초 대기 (서버 부하 방지)
- **이미지 미저장**: 해시값만 수집 (불법 콘텐츠 소지 방지)
- 탐지 결과는 방통심의위·KISA·경찰청 신고용으로만 활용

---

## 📢 신고 기관

| 기관 | URL |
|---|---|
| 방송통신심의위원회 | https://www.kocsc.or.kr |
| KISA (118) | https://www.krcert.or.kr |
| 경찰청 사이버범죄 | https://ecrm.police.go.kr |
| 불법도박신고센터 | https://www.kgef.or.kr |
| 디지털성범죄피해자지원 | https://d4u.stop.or.kr |
