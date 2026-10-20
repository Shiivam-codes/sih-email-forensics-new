from collections.abc import Iterable


def confusion_matrix(
    truth: Iterable[int], predicted: Iterable[int]
) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for actual, guess in zip(truth, predicted, strict=True):
        if actual and guess:
            tp += 1
        elif not actual and guess:
            fp += 1
        elif not actual and not guess:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def binary_metrics(
    truth: list[int], predicted: list[int], scores: list[float]
) -> dict[str, float | int]:
    matrix = confusion_matrix(truth, predicted)
    tp, fp, tn, fn = matrix["tp"], matrix["fp"], matrix["tn"], matrix["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / max(1, len(truth))
    return {
        **matrix,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "average_precision": round(average_precision(truth, scores), 4),
    }


def average_precision(truth: list[int], scores: list[float]) -> float:
    if not truth:
        return 0.0
    ranked = sorted(zip(scores, truth, strict=True), key=lambda item: item[0], reverse=True)
    positives = sum(truth)
    if positives == 0:
        return 0.0
    tp = 0
    fp = 0
    previous_recall = 0.0
    area = 0.0
    for _, actual in ranked:
        if actual:
            tp += 1
        else:
            fp += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return area


def format_percent(value: float | int | None) -> str:
    if value is None:
        return "—"
    return f"{value * 100:.1f}%"
