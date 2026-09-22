import pandas as pd

from services.retraining.retrain import filter_valid_feedback_labels


def test_normalizes_supported_labels_and_preserves_valid_rows():
    df = pd.DataFrame(
        [
            {"true_label": " benign ", "is_false_positive": True},
            {"true_label": "ATTACK", "is_false_positive": False},
        ]
    )

    result = filter_valid_feedback_labels(df)

    assert result["true_label"].tolist() == ["BENIGN", "ATTACK"]
    assert len(result) == 2


def test_rejects_unsupported_labels():
    df = pd.DataFrame(
        [
            {"true_label": "MALWARE", "is_false_positive": False},
            {"true_label": "BENIGN", "is_false_positive": True},
        ]
    )

    result = filter_valid_feedback_labels(df)

    assert len(result) == 1
    assert result.iloc[0]["true_label"] == "BENIGN"


def test_rejects_inconsistent_label_and_false_positive_flag():
    df = pd.DataFrame(
        [
            {"true_label": "BENIGN", "is_false_positive": False},
            {"true_label": "ATTACK", "is_false_positive": True},
        ]
    )

    result = filter_valid_feedback_labels(df)

    assert result.empty


def test_does_not_mutate_input_dataframe():
    df = pd.DataFrame([{"true_label": " attack ", "is_false_positive": False}])
    original = df.copy(deep=True)

    filter_valid_feedback_labels(df)

    pd.testing.assert_frame_equal(df, original)


def test_empty_dataframe_returns_empty_copy():
    df = pd.DataFrame(columns=["true_label", "is_false_positive"])

    result = filter_valid_feedback_labels(df)

    assert result.empty
    assert result is not df
