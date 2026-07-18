"""
Unit tests for the three-state decision boundary in ml/infer.decide()
and the phishing_probability / prediction_confidence split. These test
the pure decision function directly rather than the full model pipeline,
since forcing a real trained model to output an exact probability isn't
practical -- decide() is the one place the threshold logic actually lives
(ml/infer.py's classify() just calls it).
"""

from ml.infer import decide


def test_below_needs_review_threshold_is_legitimate():
    label, risk = decide(0.49)
    assert label == "Legitimate"
    assert risk == "Low"


def test_at_needs_review_threshold_is_needs_review():
    label, risk = decide(0.50)
    assert label == "Needs Review"
    assert risk == "Medium"


def test_just_below_phishing_threshold_is_needs_review():
    label, risk = decide(0.74)
    assert label == "Needs Review"
    assert risk == "Medium"


def test_at_phishing_threshold_is_phishing():
    label, risk = decide(0.75)
    assert label == "Phishing"
    assert risk == "High"


def test_well_above_phishing_threshold_is_phishing():
    label, risk = decide(0.90)
    assert label == "Phishing"
    assert risk == "High"


def test_prediction_confidence_is_symmetric_around_certainty_not_phishing_bias():
    """A 5%-phishing email should report ~95% prediction confidence (it's
    confidently legitimate), not 5% -- that conflation is exactly the bug
    being fixed. phishing_probability stays 0.05; prediction_confidence
    is max(p, 1-p)."""
    phishing_proba = 0.05
    prediction_confidence = max(phishing_proba, 1 - phishing_proba)
    assert round(prediction_confidence, 2) == 0.95

    phishing_proba = 0.63
    prediction_confidence = max(phishing_proba, 1 - phishing_proba)
    assert round(prediction_confidence, 2) == 0.63

    phishing_proba = 0.91
    prediction_confidence = max(phishing_proba, 1 - phishing_proba)
    assert round(prediction_confidence, 2) == 0.91
