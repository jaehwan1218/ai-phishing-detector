# 🛡️ ML 기반 실시간 피싱 탐지 시스템

## 기말 프로젝트 | 인공지능 개론

---

## 📦 설치 방법

```bash
# 1. 의존성 설치 (Python 3.8 이상 필요)
pip install -r requirements.txt

# 2. 프로그램 실행
python main.py
```

---

## 🗂️ 프로젝트 구조

```
phishing_detector/
├── main.py                  # 진입점 (스플래시 + 모델 로딩)
├── requirements.txt
├── model/
│   ├── features.py          # URL 구조 특징 추출 / 이메일 키워드 분석
│   └── trainer.py           # 데이터 생성 + 3종 모델 학습 + 예측
└── gui/
    └── dashboard.py         # Tkinter 다크 테마 대시보드 (3탭)
```

---

## 🤖 사용 알고리즘

| 알고리즘 | 용도 | 특징 |
|---|---|---|
| 로지스틱 회귀 (LR) | URL / 이메일 | 빠른 기준점(Baseline) 모델 |
| 랜덤 포레스트 (RF) | URL / 이메일 | 구조 특징 분류에 탁월 |
| 의사결정나무 (DT) | URL / 이메일 | 해석 가능성 높음 |

---

## 🔍 추출 특징 (Features)

### URL (14개 특징)
- URL 전체 길이, @ 포함 여부, 하이픈/언더스코어 수
- IP 주소 형태 포함 여부, HTTPS 여부
- 서브도메인 수, 경로 길이, 쿼리 파라미터 수
- 피싱 의심 키워드 수 (login, verify, account 등)
- 특수문자 총 수
- 도메인 랜덤화 점수 (계속 바뀌는 무작위 숫자 도메인 탐지)

### 이메일 (TF-IDF + 메타 특징)
- 우회 정제(normalize_text) 후 TF-IDF Vectorizer (최대 3,000 특징, 1~2 gram)
  · 특수문자 끼워넣기(성*인), 자모 분리(ㅅㅓㅇㅇㅣㄴ), 전각/제로폭 문자 표준화
- 피싱 키워드 총 등장 횟수
- 포함된 URL 수, 느낌표 수, 대문자 비율, 우회 강도 점수

---

## 📊 성능 지표 (합성 데이터 기준)

- Accuracy(정확도), Precision(정밀도), Recall(재현율), F1-Score
- 프로그램 내 "모델 비교 분석" 탭에서 실시간 확인 가능

---

## ⚠️ 주의사항

본 프로그램은 교육 목적으로 **합성 데이터(Synthetic Data)**를 사용합니다.  
실제 환경에서는 Kaggle의 UCI Phishing URL Dataset 또는  
Spam/Ham Email Dataset으로 `trainer.py`의 데이터 생성 부분을 교체하세요.
