"""
머신러닝 모델 훈련 모듈
- 합성 데이터 생성 (Kaggle 데이터 대용)
- 로지스틱 회귀 / 랜덤 포레스트 / 의사결정나무 비교
- URL 탐지 & 이메일 탐지 이중 모델
"""

import numpy as np
import random
import re
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack, csr_matrix

from model.features import (
    extract_url_features,
    extract_email_meta_features,
    normalize_text,
)


# ─────────────────────────────────────────
# 합성 데이터 생성기
# ─────────────────────────────────────────

LEGIT_DOMAINS = [
    "google.com", "naver.com", "kakao.com", "samsung.com",
    "youtube.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "wikipedia.org", "stackoverflow.com", "reddit.com",
    "netflix.com", "twitter.com", "instagram.com", "facebook.com",
    "linkedin.com", "daum.net", "nate.com", "hankyung.com",
]

LEGIT_PATHS = [
    "/", "/about", "/search", "/products", "/blog", "/news",
    "/contact", "/login", "/home", "/help", "/faq",
]

PHISHING_PATTERNS = [
    "verify-account-{}.xyz",
    "secure-login-{}.info",
    "update-your-{}.net",
    "bank-confirm-{}.ru",
    "paypal-secure-{}.com.phish.net",
    "amazon-prize-winner-{}.tk",
    "click-here-free-{}.ml",
    "urgent-action-{}.gq",
    "account-suspend-{}.cf",
    "login-verify-bank-{}.pw",
]

LEGIT_EMAIL_TEMPLATES = [
    "Dear {name}, your order #{num} has been shipped. Expected delivery: {date}. Thank you for shopping with us.",
    "Hello {name}, here is your monthly newsletter. Check out our latest blog posts and updates this week.",
    "Hi {name}, your meeting at {time} tomorrow has been confirmed. Please let us know if you need to reschedule.",
    "Good morning {name}, your subscription renewal is due on {date}. No action needed, it renews automatically.",
    "Hi {name}, your support ticket #{num} has been resolved. Please rate your experience with us.",
    "Dear {name}, we have received your application. We will review and get back to you within 3-5 business days.",
    "Hello {name}, your password was changed successfully on {date}. If this wasn't you, contact support.",
    "Hi {name}, your invoice #{num} is ready. You can download it from your account dashboard.",
]

PHISHING_EMAIL_TEMPLATES = [
    "URGENT: Dear Customer, your account has been SUSPENDED! Click here immediately to verify: http://verify-account-{num}.xyz/login",
    "Congratulations! You have won a FREE prize worth $1000! ACT NOW! Click http://free-prize-winner-{num}.tk to claim!",
    "Security Alert! Unusual activity detected on your account. Verify your password immediately: http://secure-login-{num}.ru",
    "Dear User, your bank account requires immediate verification. Provide your SSN and credit card: http://bank-{num}.phish.net",
    "LIMITED TIME: Your account will be closed in 24 hours! UPDATE your information NOW: http://update-{num}.ml/verify",
    "ACTION REQUIRED: Confirm your identity to avoid suspension. Enter your login credentials: http://confirm-{num}.gq",
    "Warning! Your email account storage is full. Click to verify ownership: http://email-verify-{num}.cf/login",
    "Dear Customer, you have a pending transaction of $500. Confirm or CANCEL immediately: http://transaction-{num}.pw",
]


def _random_str(n=6):
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))


def generate_url_dataset(n_legit=2000, n_phish=2000):
    urls, labels = [], []

    # 정상 URL
    for _ in range(n_legit):
        domain = random.choice(LEGIT_DOMAINS)
        path = random.choice(LEGIT_PATHS)
        scheme = "https" if random.random() > 0.1 else "http"
        url = f"{scheme}://{domain}{path}"
        if random.random() > 0.7:
            url += f"?q={_random_str(4)}"
        urls.append(url)
        labels.append(0)

    # 피싱 URL
    for _ in range(n_phish):
        pattern = random.choice(PHISHING_PATTERNS)
        domain = pattern.format(_random_str())
        scheme = "http" if random.random() > 0.2 else "https"
        path_parts = random.choice([
            f"/login?user={_random_str()}&redirect={_random_str()}",
            f"/verify@{_random_str()}/account",
            f"/secure_{_random_str()}/update",
            f"/{_random_str()}-free-prize/claim",
        ])
        url = f"{scheme}://{domain}{path_parts}"
        urls.append(url)
        labels.append(1)

    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


def generate_email_dataset(n_legit=2000, n_phish=2000):
    texts, labels = [], []

    for _ in range(n_legit):
        template = random.choice(LEGIT_EMAIL_TEMPLATES)
        text = template.format(
            name=random.choice(["John", "Emily", "Michael", "Sarah", "James"]),
            num=random.randint(10000, 99999),
            date=f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
            time=f"{random.randint(9,17)}:00",
        )
        texts.append(text)
        labels.append(0)

    for _ in range(n_phish):
        template = random.choice(PHISHING_EMAIL_TEMPLATES)
        text = template.format(num=_random_str(8))
        # 변형 추가 (대문자, 느낌표 등)
        if random.random() > 0.5:
            text = text + " DO NOT IGNORE THIS MESSAGE!!!"
        texts.append(text)
        labels.append(1)

    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)
    return list(texts), list(labels)


# ─────────────────────────────────────────
# 모델 학습기
# ─────────────────────────────────────────

class PhishingModelTrainer:
    def __init__(self):
        self.url_data = None
        self.email_data = None

        # URL 모델들
        self.url_models = {}
        self.url_scaler = StandardScaler()
        self.url_results = {}

        # 이메일 모델들
        self.email_models = {}
        self.email_tfidf = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
        self.email_results = {}

        # 베스트 모델
        self.best_url_model_name = None
        self.best_email_model_name = None

    def generate_synthetic_data(self):
        urls, url_labels = generate_url_dataset(2000, 2000)
        emails, email_labels = generate_email_dataset(2000, 2000)
        self.url_data = (urls, url_labels)
        self.email_data = (emails, email_labels)

    def prepare_features(self):
        # URL 특징 행렬
        urls, url_labels = self.url_data
        X_url = np.array([extract_url_features(u) for u in urls])
        X_url_scaled = self.url_scaler.fit_transform(X_url)
        self._url_X = X_url_scaled
        self._url_y = np.array(url_labels)

        # 이메일 특징 행렬 (TF-IDF + 메타 특징)
        emails, email_labels = self.email_data
        # 우회 정제본으로 TF-IDF 학습 → 변종 텍스트도 표준 토큰으로 학습됨
        emails_norm = [normalize_text(t) for t in emails]
        X_tfidf = self.email_tfidf.fit_transform(emails_norm)
        X_meta = np.array([extract_email_meta_features(t) for t in emails])
        X_email = hstack([X_tfidf, csr_matrix(X_meta)])
        self._email_X = X_email
        self._email_y = np.array(email_labels)

    def _evaluate(self, model, X_test, y_test):
        y_pred = model.predict(X_test)
        return {
            "accuracy": round(accuracy_score(y_test, y_pred) * 100, 2),
            "precision": round(precision_score(y_test, y_pred, zero_division=0) * 100, 2),
            "recall": round(recall_score(y_test, y_pred, zero_division=0) * 100, 2),
            "f1": round(f1_score(y_test, y_pred, zero_division=0) * 100, 2),
        }

    def train_all_models(self):
        model_defs = {
            "로지스틱 회귀": LogisticRegression(max_iter=1000, random_state=42),
            "랜덤 포레스트": RandomForestClassifier(n_estimators=100, random_state=42),
            "의사결정나무": DecisionTreeClassifier(max_depth=12, random_state=42),
        }

        # URL 모델 학습
        X_tr, X_te, y_tr, y_te = train_test_split(
            self._url_X, self._url_y, test_size=0.2, random_state=42, stratify=self._url_y
        )
        best_f1 = -1
        for name, clf in model_defs.items():
            clf.fit(X_tr, y_tr)
            result = self._evaluate(clf, X_te, y_te)
            self.url_models[name] = clf
            self.url_results[name] = result
            if result["f1"] > best_f1:
                best_f1 = result["f1"]
                self.best_url_model_name = name

        # 이메일 모델 학습
        X_tr, X_te, y_tr, y_te = train_test_split(
            self._email_X, self._email_y, test_size=0.2, random_state=42, stratify=self._email_y
        )
        best_f1 = -1
        for name, clf in {
            "로지스틱 회귀": LogisticRegression(max_iter=1000, random_state=42),
            "랜덤 포레스트": RandomForestClassifier(n_estimators=100, random_state=42),
            "의사결정나무": DecisionTreeClassifier(max_depth=12, random_state=42),
        }.items():
            clf.fit(X_tr, y_tr)
            result = self._evaluate(clf, X_te, y_te)
            self.email_models[name] = clf
            self.email_results[name] = result
            if result["f1"] > best_f1:
                best_f1 = result["f1"]
                self.best_email_model_name = name

    # ─────────────────────────────────────────
    # 실시간 예측
    # ─────────────────────────────────────────

    def predict_url(self, url: str, model_name: str = None):
        model_name = model_name or self.best_url_model_name
        model = self.url_models[model_name]
        feat = extract_url_features(url).reshape(1, -1)
        feat_scaled = self.url_scaler.transform(feat)

        prob = model.predict_proba(feat_scaled)[0]
        phish_prob = float(prob[1]) * 100
        label = model.predict(feat_scaled)[0]
        return {
            "label": int(label),
            "probability": round(phish_prob, 1),
            "model": model_name,
            "features": extract_url_features(url).tolist(),
        }

    def predict_email(self, text: str, model_name: str = None):
        model_name = model_name or self.best_email_model_name
        model = self.email_models[model_name]

        X_tfidf = self.email_tfidf.transform([normalize_text(text)])
        X_meta = csr_matrix(extract_email_meta_features(text).reshape(1, -1))
        X = hstack([X_tfidf, X_meta])

        prob = model.predict_proba(X)[0]
        phish_prob = float(prob[1]) * 100
        label = model.predict(X)[0]
        return {
            "label": int(label),
            "probability": round(phish_prob, 1),
            "model": model_name,
        }

    # ─────────────────────────────────────────
    # XAI 접근자
    # ─────────────────────────────────────────

    def xai_url_feature_importance(self, model_name: str = None) -> list:
        """URL 모델 전체 feature importance 반환"""
        from model.xai import get_url_feature_importance
        model_name = model_name or self.best_url_model_name
        return get_url_feature_importance(
            self.url_models[model_name], model_name
        )

    def xai_url_sample(self, url: str, model_name: str = None) -> list:
        """URL 하나에 대한 특징별 기여도 반환"""
        from model.xai import get_url_sample_contributions
        model_name = model_name or self.best_url_model_name
        return get_url_sample_contributions(
            self.url_models[model_name], model_name,
            self.url_scaler, url
        )

    def xai_email_words(self, text: str, model_name: str = None) -> list:
        """이메일 텍스트에서 단어별 기여도 반환"""
        from model.xai import get_email_word_contributions
        model_name = model_name or self.best_email_model_name
        return get_email_word_contributions(
            self.email_models[model_name], model_name,
            self.email_tfidf, text
        )
