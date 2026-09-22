"""
Unit tests for FeedbackSubmission validation.
"""

import pytest
from pydantic import ValidationError

from models import FeedbackSubmission


def test_valid_attack_feedback():
    feedback = FeedbackSubmission(
        analyst_id=" analyst-1 ",
        is_false_positive=False,
        true_label=" attack ",
    )

    assert feedback.analyst_id == "analyst-1"
    assert feedback.true_label == "ATTACK"


def test_valid_benign_false_positive_feedback():
    feedback = FeedbackSubmission(
        analyst_id="analyst-1",
        is_false_positive=True,
        true_label=" benign ",
    )

    assert feedback.true_label == "BENIGN"


@pytest.mark.parametrize("label", ["", "unknown", "MALWARE", "BENIGN_ATTACK"])
def test_rejects_unsupported_true_label(label):
    with pytest.raises(ValidationError, match="true_label"):
        FeedbackSubmission(
            analyst_id="analyst-1",
            is_false_positive=False,
            true_label=label,
        )


def test_rejects_inconsistent_benign_feedback():
    with pytest.raises(ValidationError, match="BENIGN.*false positive"):
        FeedbackSubmission(
            analyst_id="analyst-1",
            is_false_positive=False,
            true_label="BENIGN",
        )


def test_rejects_inconsistent_attack_feedback():
    with pytest.raises(ValidationError, match="ATTACK.*false positive"):
        FeedbackSubmission(
            analyst_id="analyst-1",
            is_false_positive=True,
            true_label="ATTACK",
        )


def test_rejects_blank_analyst_id():
    with pytest.raises(ValidationError, match="analyst_id"):
        FeedbackSubmission(
            analyst_id="   ",
            is_false_positive=False,
        )


def test_allows_feedback_without_ground_truth_label():
    feedback = FeedbackSubmission(
        analyst_id="analyst-1",
        is_false_positive=False,
    )

    assert feedback.true_label is None
