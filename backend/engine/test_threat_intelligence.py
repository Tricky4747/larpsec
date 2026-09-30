import numpy as np

from backend.engine.threat_intelligence import (
    CARFFilter,
    ContrastiveNLPEngine,
    ThreatIntelligencePredictor,
)


def test_carf_keeps_mode_relevant_signals():
    carf = CARFFilter()

    assert carf.apply_filter(0.7, "Maritime congestion at the port.", " SEA ") == 0.7
    assert carf.apply_filter(0.7, "Aviation cargo backlogs at airports.", "AIR") == 0.7
    assert carf.apply_filter(0.7, "Highway traffic is increasing.", "road") == 0.7
    assert carf.apply_filter(0.7, "Railway freight tracks are closed.", "rail") == 0.7


def test_carf_rejects_cross_modal_signals():
    carf = CARFFilter()

    assert carf.apply_filter(0.7, "Airport flight delays reported.", "sea") == 0.0
    assert carf.apply_filter(0.7, "Port vessel backlog reported.", "air") == 0.0


class _FakeScore:
    def __init__(self, value):
        self.value = value

    def cpu(self):
        return self

    def numpy(self):
        return np.array([[self.value]])


def _semantic_engine(disaster_score, safe_score):
    engine = ContrastiveNLPEngine(lazy_load=True)
    engine._ready = True
    engine.model = type("FakeModel", (), {"encode": lambda *_args, **_kwargs: None})()
    engine.disaster_matrix = "disaster"
    engine.safe_matrix = "safe"

    def cos_sim(_embedding, anchor):
        return _FakeScore(disaster_score if anchor == "disaster" else safe_score)

    engine.util = type("FakeUtil", (), {"cos_sim": staticmethod(cos_sim)})
    return engine


def test_nlp_scores_strong_disaster_margin():
    engine = _semantic_engine(0.8, 0.2)

    assert abs(engine.get_semantic_score("Strong maritime disruption") - 0.21) < 1e-9


def test_nlp_suppresses_below_floor_and_negative_margins():
    weak_engine = _semantic_engine(0.23, 0.2)
    negative_engine = _semantic_engine(0.1, 0.2)

    assert weak_engine.get_semantic_score("Weak signal") == 0.0
    assert negative_engine.get_semantic_score("Safe conditions") == 0.0


class _FakeEncoder:
    classes_ = ["Kochi Port", "Other Hub"]

    def transform(self, values):
        return [self.classes_.index(values[0])]


def test_predictor_resolves_canonical_hub_to_model_label():
    model_predictor = ThreatIntelligencePredictor(lazy_load=True)
    model_predictor.encoders = {"Origin_Node": _FakeEncoder()}

    assert model_predictor._encode_feature("PORT-KOCHI", "Origin_Node") == 0


def test_predictor_unknown_hub_uses_mode_prior():
    model_predictor = ThreatIntelligencePredictor(lazy_load=True)
    model_predictor.is_trained = True
    model_predictor.encoders = {"Origin_Node": _FakeEncoder()}

    result = model_predictor.predict_worst_case_delay(
        "UNKNOWN-HUB", "PORT-KOCHI", "sea"
    )

    assert result["final_delay_presented"] == 48.0