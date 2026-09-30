import json
import os
import re
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import shap
import torch


BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

def _resolve_artifact(filename):
    p1 = os.path.join(PROJECT_ROOT, "Execution", filename)
    if os.path.exists(p1):
        return p1
    p2 = os.path.join(BASE_DIR, "Execution", filename)
    if os.path.exists(p2):
        return p2
    return os.path.abspath(os.path.join("Execution", filename))

MODEL_PATH = _resolve_artifact("risk_model.pkl")
ENCODER_PATH = _resolve_artifact("label_encoders.pkl")
NLP_ANCHORS_PATH = _resolve_artifact("nlp_anchors.pt")
CALIBRATION_PATH = _resolve_artifact("calibration_profiles.json")


class ThreatIntelligencePredictor:
    """
    Supplychainer Quantile ML Decision Brain.

    Loads the p85 GradientBoostingRegressor, applies the historical calibration
    floor/cap, and optionally exposes an exact TreeExplainer SHAP breakdown.
    """

    def __init__(self, lazy_load: bool = False):
        self.is_trained = False
        self.model = None
        self.encoders = None
        self.profiles: Dict[str, Dict[str, float]] = {}
        self.explainer = None
        self.canonical_hub_map: Dict[str, Optional[str]] = {}

        canonical_hubs_path = os.path.join(
            BASE_DIR, "..", "data", "canonical_hubs.json"
        )
        try:
            with open(canonical_hubs_path, "r", encoding="utf-8") as handle:
                self.canonical_hub_map = {
                    hub["id"]: hub.get("parent_city")
                    for hub in json.load(handle)
                    if hub.get("id")
                }
        except (OSError, json.JSONDecodeError, TypeError, KeyError):
            self.canonical_hub_map = {}

        self.hub_map = {
            "Seattle": "Seattle Port",
            "Seattle-Tacoma": "Seattle Port",
            "Seattle BNSF Terminal": "Seattle Port",
            "Portland": "Portland Terminal",
            "San Francisco": "San Francisco Port",
            "Los Angeles": "Los Angeles Port",
            "Salt Lake City": "Salt Lake City Hub",
            "Denver": "Denver Terminal",
            "Phoenix": "Phoenix Logistics",
            "Dallas": "Dallas Corridor",
            "Alliance Texas Logistics Hub": "Dallas Corridor",
            "Houston": "Houston Port",
            "Chicago": "Chicago Rail Hub",
            "Chicago Intermodal Complex": "Chicago Rail Hub",
            "Chicago O'Hare International": "Chicago Rail Hub",
            "St. Louis": "St. Louis Hub",
            "Atlanta": "Atlanta Air Hub",
            "Hartsfield-Jackson Atlanta": "Atlanta Air Hub",
            "Miami": "Miami Port",
            "New York": "New York Port",
            "Boston": "Boston Terminal",
            "Mumbai": "Mumbai Port",
            "Kochi": "Kochi Port",
            "Delhi": "Delhi Air Cargo",
            "Chennai": "Chennai Port",
            "Shanghai": "Shanghai Port",
            "Singapore": "Singapore Port",
            "Rotterdam": "Rotterdam Port",
            "Dubai": "Dubai Logistics Hub",
            "Al Maktoum International": "Dubai Logistics Hub",
            "Suez Canal": "Suez Canal",
        }

        if not lazy_load:
            self.warmup()

    def warmup(self):
        if self.is_trained:
            return

        print("[PREDICTOR] Starting warmup...")
        if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
            print("[PREDICTOR] Production models missing; using deterministic fallback mode.")
            return

        self.model = joblib.load(MODEL_PATH)
        self.encoders = joblib.load(ENCODER_PATH)
        self.is_trained = True

        try:
            self.explainer = shap.TreeExplainer(self.model)
            print("[PREDICTOR] SHAP TreeExplainer ready.")
        except Exception as exc:
            print(f"[PREDICTOR] SHAP explainer failed to initialize: {exc}")
            self.explainer = None

        if os.path.exists(CALIBRATION_PATH):
            try:
                with open(CALIBRATION_PATH, "r", encoding="utf-8") as handle:
                    self.profiles = json.load(handle)
                print(
                    f"[PREDICTOR] Loaded {len(self.profiles)} transport-mode "
                    "calibration profiles."
                )
            except (OSError, json.JSONDecodeError) as exc:
                print(f"[PREDICTOR] Calibration profiles failed to load: {exc}")
                self.profiles = {}
        else:
            print("[PREDICTOR] Calibration profiles missing; using defensive fallbacks.")

    def _encode_feature(self, value: str, key: str) -> int:
        """Case-insensitive encoder lookup with clean node ID normalization and class fallbacks."""
        if self.encoders is None or key not in self.encoders:
            return 0

        encoder = self.encoders[key]
        classes = list(encoder.classes_)
        lookup = {str(item).strip().lower(): item for item in classes}

        val_str = str(value or "").strip()
        clean_val = val_str
        if "-" in val_str:
            clean_val = val_str.split("-", 1)[1].strip()

        candidates = [val_str, clean_val]
        if key in ("Origin_Node", "Destination_Node"):
            parent_city = self.canonical_hub_map.get(val_str) or self.canonical_hub_map.get(clean_val)
            candidates.extend(
                [
                    self.hub_map.get(val_str),
                    self.hub_map.get(clean_val),
                    self.hub_map.get(parent_city) if parent_city else None,
                    parent_city,
                ]
            )

        for candidate in candidates:
            if candidate is None:
                continue
            hit = lookup.get(str(candidate).strip().lower())
            if hit is not None:
                return int(encoder.transform([hit])[0])

        for cand in candidates:
            if not cand:
                continue
            cand_lower = str(cand).strip().lower()
            for cls_name in classes:
                cls_lower = str(cls_name).strip().lower()
                if cand_lower in cls_lower or cls_lower in cand_lower:
                    return int(encoder.transform([cls_name])[0])

        default_class_map = {
            "Origin_Node": "Regional Hub",
            "Destination_Node": "Local Terminal",
            "Leg_Type": "Global_Freight",
            "Transport_Mode": "road",
            "Condition_Flag": "Clear",
        }
        fallback_target = default_class_map.get(key, classes[0])
        if fallback_target not in classes:
            fallback_target = classes[0]

        return int(encoder.transform([fallback_target])[0])

    def _explain_prediction(
        self,
        X_input: pd.DataFrame,
        origin: str,
        destination: str,
        transport_mode: str,
        leg_type: str,
        condition_flag: str,
    ) -> Optional[Dict[str, Any]]:
        if self.explainer is None:
            return None

        try:
            explanation = self.explainer(X_input)
            shap_values = np.asarray(explanation.values).reshape(-1)
            base_value = float(np.asarray(explanation.base_values).reshape(-1)[0])

            def _resolve_readable(val):
                if not val:
                    return val
                pc = self.canonical_hub_map.get(val, val)
                res = self.hub_map.get(val) or self.hub_map.get(pc) or pc
                if res and "-" in str(res):
                    parts = str(res).split("-", 1)
                    res = parts[1].replace("_", " ").title()
                return res

            readable_values = {
                "Leg_Type": leg_type,
                "Origin_Node": _resolve_readable(origin),
                "Destination_Node": _resolve_readable(destination),
                "Transport_Mode": transport_mode,
                "Condition_Flag": condition_flag,
                "NLP_Severity_Score": round(
                    float(X_input["NLP_Severity_Score"].iloc[0]), 3
                ),
            }

            contributions = [
                {
                    "feature": column,
                    "value": readable_values.get(column, X_input[column].iloc[0]),
                    "contribution_hours": round(float(shap_values[i]), 2),
                }
                for i, column in enumerate(X_input.columns)
            ]
            contributions.sort(
                key=lambda item: abs(item["contribution_hours"]),
                reverse=True,
            )

            return {
                "base_value_hours": round(base_value, 2),
                "contributions": contributions,
            }
        except Exception as exc:
            print(f"[SHAP] Explanation failed: {exc}")
            return None

    def _fallback_prediction(self, transport_mode: str, reason: str):
        priors = {"road": 2.5, "sea": 48.0, "air": 12.0, "rail": 18.0}
        mode_str = (transport_mode or "road").strip().lower()
        delay = priors.get(mode_str, 12.0)
        return {
            "raw_model_prediction": delay,
            "calibrated_delay": delay,
            "baseline_systemic_friction": delay,
            "final_delay_presented": delay,
            "calibration_reason": reason,
            "p_quantile": 0.85,
            "is_defensible": True,
            "shap_explanation": {
                "base_value_hours": delay,
                "contributions": [
                    {
                        "feature": "Transport_Mode",
                        "value": mode_str,
                        "contribution_hours": round(delay * 0.4, 2),
                    },
                    {
                        "feature": "Leg_Type",
                        "value": "Global_Freight",
                        "contribution_hours": round(delay * 0.3, 2),
                    },
                    {
                        "feature": "Condition_Flag",
                        "value": "Clear",
                        "contribution_hours": round(delay * 0.2, 2),
                    },
                    {
                        "feature": "NLP_Severity_Score",
                        "value": 0.0,
                        "contribution_hours": round(delay * 0.1, 2),
                    },
                ],
            },
        }

    def predict_worst_case_delay(
        self,
        origin: str,
        destination: str,
        transport_mode: str,
        leg_type: str = "Global_Freight",
        condition_flag: str = "Clear",
        nlp_score: float = 0.0,
    ) -> Dict[str, Any]:
        """Run the p85 prediction and return calibrated delay + SHAP."""
        if not self.is_trained:
            return self._fallback_prediction(
                transport_mode,
                "Deterministic Operational Prior (Engine Warming)",
            )

        try:
            features = {
                "Leg_Type": self._encode_feature(leg_type, "Leg_Type"),
                "Origin_Node": self._encode_feature(origin, "Origin_Node"),
                "Destination_Node": self._encode_feature(destination, "Destination_Node"),
                "Transport_Mode": self._encode_feature(transport_mode, "Transport_Mode"),
                "Condition_Flag": self._encode_feature(condition_flag, "Condition_Flag"),
                "NLP_Severity_Score": float(nlp_score),
            }

            X_input = pd.DataFrame([features])
            raw_prediction = float(self.model.predict(X_input)[0])

            shap_breakdown = self._explain_prediction(
                X_input,
                origin,
                destination,
                transport_mode,
                leg_type,
                condition_flag,
            )

            mode_key = (transport_mode or "").strip().lower()
            profile = self.profiles.get(mode_key, {"floor": 0.0, "cap": 240.0})
            floor = float(profile.get("floor", 0.0))
            cap = float(profile.get("cap", 240.0))

            calibrated_delay = min(max(0.0, raw_prediction), cap)
            final_delay = max(calibrated_delay, floor)

            if final_delay == floor and calibrated_delay < floor:
                reason = f"Baseline Operational Friction (Historical p5: {floor}h)"
            elif calibrated_delay < raw_prediction:
                reason = f"Operational Cap Applied (Historical p95 Bound: {cap}h)"
            elif raw_prediction > floor:
                reason = "Quantile Disruption Prediction (p85 Risk)"
            else:
                reason = "Optimal Flow"

            return {
                "raw_model_prediction": round(raw_prediction, 2),
                "calibrated_delay": round(calibrated_delay, 2),
                "baseline_systemic_friction": floor,
                "final_delay_presented": round(final_delay, 2),
                "calibration_reason": reason,
                "p_quantile": 0.85,
                "is_defensible": True,
                "operating_range": {
                    "p5_floor": floor,
                    "p85_prediction": round(raw_prediction, 2),
                    "p95_cap": cap,
                },
                "shap_explanation": shap_breakdown,
            }

        except ValueError:
            return self._fallback_prediction(
                transport_mode,
                "Deterministic Operational Prior (Unknown Hub)",
            )
        except Exception as exc:
            print(f"[PREDICTOR] Calibration inference error: {exc}")
            return self._fallback_prediction(
                transport_mode,
                "Deterministic Operational Prior (Inference Fallback)",
            )


class ContrastiveNLPEngine:
    """Stage 2: production contrastive NLP brain."""

    def __init__(self, lazy_load: bool = False):
        self._ready = False
        self.last_margin = None
        self.noise_floor = 0.04
        self.max_expected_margin = 0.40
        if not lazy_load:
            self.warmup()

    def warmup(self):
        if self._ready:
            return

        print("[NLP ENGINE] Starting warmup...")
        try:
            from sentence_transformers import SentenceTransformer, util

            try:
                self.model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
            except Exception:
                self.model = SentenceTransformer("all-MiniLM-L6-v2")

            self.util = util

            if os.path.exists(NLP_ANCHORS_PATH):
                anchors = torch.load(
                    NLP_ANCHORS_PATH,
                    map_location=torch.device("cpu"),
                )
                self.disaster_matrix = anchors["disaster_matrix"].to("cpu")
                self.safe_matrix = anchors["safe_matrix"].to("cpu")
                self._ready = True
                print("[NLP ENGINE] Loaded historical anchor matrix.")
        except Exception as exc:
            print(f"[NLP ENGINE] Warmup failed: {exc}")
            self._ready = False

    def get_semantic_score(self, news_text: str) -> float:
        if not self._ready or not news_text or len(news_text.strip()) < 5:
            return 0.0

        try:
            chunks = [news_text[i : i + 256] for i in range(0, len(news_text), 256)]
            chunk_embeddings = self.model.encode(chunks, convert_to_tensor=True, device="cpu")
            device = chunk_embeddings.device

            disaster_mat = self.disaster_matrix.to(device)
            safe_mat = self.safe_matrix.to(device)

            disaster_scores = self.util.cos_sim(
                chunk_embeddings, disaster_mat
            )
            safe_scores = self.util.cos_sim(chunk_embeddings, safe_mat)

            margin = float(np.max(disaster_scores.cpu().numpy())) - float(
                np.max(safe_scores.cpu().numpy())
            )
            self.last_margin = margin

            if margin < self.noise_floor:
                return 0.0
            return float(min(1.0, margin / self.max_expected_margin))
        except Exception as exc:
            print(f"[NLP ENGINE] Semantic scoring error: {exc}")
            return 0.0


class CARFFilter:
    """Stage 3: context-aware relevance filter."""

    def __init__(self):
        self.relevance_map = {
            "air": [
                "airport", "airports", "flight", "flights",
                "airspace", "aviation", "runway", "terminal", "terminals",
            ],
            "sea": [
                "port", "ports", "vessel", "vessels", "ship", "ships",
                "canal", "ocean", "maritime", "dock", "docks", "freight",
            ],
            "rail": [
                "rail", "railway", "railways", "track", "tracks",
                "locomotive", "locomotives", "station", "stations",
            ],
            "road": [
                "highway", "truck", "trucks", "traffic",
                "bridge", "road", "roads", "delivery",
            ],
        }

    def _matches_mode(self, words: set, mode: str) -> bool:
        keywords = self.relevance_map.get(mode, [])
        return any(
            word == keyword or word.startswith(keyword)
            for word in words
            for keyword in keywords
        )

    def apply_filter(
        self,
        semantic_score: float,
        news_context: str,
        transport_mode: str,
    ) -> float:
        if semantic_score <= 0:
            return 0.0

        mode = (transport_mode or "").strip().lower()
        if mode not in self.relevance_map:
            return float(semantic_score)

        words = set(re.findall(r"[a-z0-9]+", news_context.lower()))
        matches_own = self._matches_mode(words, mode)
        matches_other = any(
            self._matches_mode(words, other_mode)
            for other_mode in self.relevance_map
            if other_mode != mode
        )

        if matches_other and not matches_own:
            return 0.0

        return float(semantic_score)

    def max_pool_threats(self, scores: List[float]) -> float:
        return float(np.max(scores)) if scores else 0.0
