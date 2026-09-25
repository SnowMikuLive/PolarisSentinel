import numpy as np
from evaluate_inference import rf_alert_mask

def test_rf_threshold_and_benign_routing():
    # 低于阈值交给 IF；等于阈值的攻击由 RF 返回；良性仍交给 IF。
    # Below-threshold attacks and benign predictions go to IF.
    probabilities = np.array([[0.41, 0.59], [0.40, 0.60], [0.01, 0.99], [0.99, 0.01]], dtype=np.float32)
    result = rf_alert_mask(probabilities, benign=0, threshold=0.60)
    np.testing.assert_array_equal(result, [False, True, True, False])

def test_rf_uses_supplied_threshold():
    probabilities = np.array([[0.30, 0.70]], dtype=np.float32)
    assert rf_alert_mask(probabilities, benign=0, threshold=0.60)[0]
    assert not rf_alert_mask(probabilities, benign=0, threshold=0.80)[0]