"""
설명 가능한 AI (XAI) 모듈
- Random Forest feature_importances_ 추출
- Logistic Regression 계수(coef_) 추출
- 사용자 입력 문장의 단어별 기여도 계산
"""

import numpy as np
from model.features import URL_FEATURE_NAMES, PHISHING_EMAIL_KEYWORDS


# ─────────────────────────────────────────
# URL 모델 XAI: Feature Importance
# ─────────────────────────────────────────

def get_url_feature_importance(model, model_name: str) -> list[dict]:
    """
    URL 분류 모델에서 각 특징(feature)의 중요도를 반환합니다.
    반환: [{name, importance, direction}, ...]
    """
    try:
        if model_name == "랜덤 포레스트":
            importances = model.feature_importances_
            directions = ["위험" if i > 0 else "안전"
                          for i in importances]
        elif model_name == "로지스틱 회귀":
            coef = model.coef_[0]
            importances = np.abs(coef)
            directions = ["위험" if c > 0 else "안전" for c in coef]
        elif model_name == "의사결정나무":
            importances = model.feature_importances_
            directions = ["위험" for _ in importances]
        else:
            return []

        # 정규화 (0~1)
        total = importances.sum()
        if total == 0:
            return []
        norm = importances / total

        result = []
        for name, imp, direction in zip(URL_FEATURE_NAMES, norm, directions):
            result.append({
                "name": name,
                "importance": round(float(imp) * 100, 2),  # % 단위
                "direction": direction,
            })

        result.sort(key=lambda x: -x["importance"])
        return result

    except Exception as e:
        return []


# ─────────────────────────────────────────
# 이메일 모델 XAI: 단어 기여도
# ─────────────────────────────────────────

def get_email_word_contributions(
    model,
    model_name: str,
    tfidf,
    text: str,
    top_n: int = 15,
) -> list[dict]:
    """
    이메일 텍스트에서 각 단어가 피싱 판별에 기여한 정도를 계산합니다.
    반환: [{word, score, is_phishing}, ...]  (내림차순 정렬)
    """
    try:
        from scipy.sparse import hstack, csr_matrix
        from model.features import extract_email_meta_features, normalize_text

        # TF-IDF 어휘 가져오기
        vocab = tfidf.vocabulary_          # {word: idx}
        feature_names = tfidf.get_feature_names_out()

        # 모델 계수/중요도 추출
        if model_name == "로지스틱 회귀":
            # coef_는 전체 feature(tfidf + meta)에 대한 계수
            coef = model.coef_[0]
            # tfidf 부분만 (앞 len(feature_names)개)
            tfidf_coef = coef[:len(feature_names)]
        elif model_name in ("랜덤 포레스트", "의사결정나무"):
            importances = model.feature_importances_
            tfidf_coef = importances[:len(feature_names)]
        else:
            return []

        # 입력 텍스트의 TF-IDF 벡터 (학습과 동일하게 정제본 사용)
        X_tfidf = tfidf.transform([normalize_text(text)])
        tfidf_arr = X_tfidf.toarray()[0]   # shape: (n_features,)

        # 단어별 기여도 = TF-IDF값 × 계수(또는 중요도)
        contributions = tfidf_arr * tfidf_coef

        # 0이 아닌 것만 (실제로 입력 텍스트에 등장한 단어)
        word_scores = []
        for idx, score in enumerate(contributions):
            if tfidf_arr[idx] > 0:
                word_scores.append({
                    "word": feature_names[idx],
                    "score": float(score),
                    "tfidf": float(tfidf_arr[idx]),
                    "coef": float(tfidf_coef[idx]),
                    "is_phishing": score > 0,
                })

        # 절댓값 기준 정렬
        word_scores.sort(key=lambda x: -abs(x["score"]))
        return word_scores[:top_n]

    except Exception as e:
        return []


# ─────────────────────────────────────────
# URL 입력 단일 샘플 기여도 (LIME 유사 간이 구현)
# ─────────────────────────────────────────

def get_url_sample_contributions(
    model,
    model_name: str,
    scaler,
    url: str,
) -> list[dict]:
    """
    URL 하나에 대해 각 특징값이 피싱 판별에 얼마나 기여했는지 반환합니다.
    기여도 = 특징값(정규화 후) × 모델 계수(또는 중요도)
    """
    from model.features import extract_url_features

    raw_feat = extract_url_features(url)
    scaled_feat = scaler.transform(raw_feat.reshape(1, -1))[0]

    try:
        if model_name == "로지스틱 회귀":
            coef = model.coef_[0]
            contributions = scaled_feat * coef
        elif model_name in ("랜덤 포레스트", "의사결정나무"):
            importances = model.feature_importances_
            contributions = scaled_feat * importances
        else:
            return []

        result = []
        for name, raw_val, contrib in zip(
            URL_FEATURE_NAMES, raw_feat, contributions
        ):
            result.append({
                "name": name,
                "raw_value": float(raw_val),
                "contribution": float(contrib),
                "is_phishing": contrib > 0,
            })

        result.sort(key=lambda x: -abs(x["contribution"]))
        return result

    except Exception as e:
        return []
