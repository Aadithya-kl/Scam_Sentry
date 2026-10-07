"""API tests for /health and /predict (uses the real model artifact)."""

from tests.conftest import requires_model

PHISHING = (
    "URGENT: Your bank account has been suspended due to suspicious activity. "
    "Verify your account immediately and share the OTP at http://secure-bank-login.xyz/verify"
)


@requires_model
def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True


@requires_model
def test_predict_scam(client):
    response = client.post("/predict", json={"text": PHISHING})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "SCAM"
    assert body["risk_level"] == "CRITICAL"
    assert 0 <= body["confidence"] <= 1
    assert 0 <= body["spam_probability"] <= 1
    assert "Suspicious URL" in body["flags"]
    assert "OTP / PIN / PASSWORD request" in body["flags"]
    assert len(body["explanation"]) >= 2
    for key in ("risk_score", "top_terms", "score_breakdown", "model_version"):
        assert key in body


@requires_model
def test_predict_safe(client):
    response = client.post("/predict", json={"text": "Are we still on for dinner at 8 tonight?"})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "SAFE"
    assert body["risk_level"] == "LOW"


@requires_model
def test_predict_spam(client):
    text = "FREE entry to our weekly competition! Text WIN to 80086 to get 50% off ringtones. Reply STOP to opt out."
    body = client.post("/predict", json={"text": text}).json()
    assert body["prediction"] == "SPAM"


def test_empty_text_rejected(client):
    for text in ("",):
        response = client.post("/predict", json={"text": text})
        assert response.status_code == 422


def test_missing_field_rejected(client):
    assert client.post("/predict", json={}).status_code == 422


def test_too_long_text_rejected(client):
    assert client.post("/predict", json={"text": "a" * 5001}).status_code == 422


def test_cors_preflight(client):
    response = client.options(
        "/predict",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"

def test_scan_url(client):
    response = client.post("/scan-url", json={"url": "https://example.com/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] in ("SAFE", "SUSPICIOUS", "SPAM", "SCAM")
    assert "url_analysis" in body
    assert len(body["iocs"]["urls"]) == 1
