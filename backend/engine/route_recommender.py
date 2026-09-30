import os
import time
from typing import Any, Dict, List, Optional

import networkx as nx

try:
    from .multimodal_network import MODE_PROFILES, create_multimodal_network
    from .threat_intelligence import (
        ThreatIntelligencePredictor,
        ContrastiveNLPEngine,
        CARFFilter,
    )
    from .news_ingestion import DynamicNewsIngestor
    from .node_resolver import NodeResolver
except ImportError:
    from multimodal_network import MODE_PROFILES, create_multimodal_network
    from threat_intelligence import (
        ThreatIntelligencePredictor,
        ContrastiveNLPEngine,
        CARFFilter,
    )
    from news_ingestion import DynamicNewsIngestor
    from node_resolver import NodeResolver


class RouteRecommender:
    """
    Route optimization layer.

    The important ML path is:
        live/scenario threat -> p85 delay model -> edge weight -> route choice

    Each scored leg also carries its SHAP explanation into audit_trace when
    the predictor/model can produce one.
    """

    def __init__(
        self,
        unified_graph=None,
        scenario_mgr=None,
        predictor=None,
        resolver=None,
        live_news_enabled: Optional[bool] = None,
        live_news_fetch_budget: Optional[int] = None,
    ):
        self.unified_graph = unified_graph
        if self.unified_graph is None:
            try:
                self.unified_graph = create_multimodal_network()
            except TypeError:
                # Some versions expose the network builder with no usable
                # zero-argument constructor. Keep initialization explicit.
                self.unified_graph = None

        self.predictor = predictor or ThreatIntelligencePredictor()
        self.resolver = resolver or NodeResolver()

        self.nlp = ContrastiveNLPEngine(lazy_load=True)
        self.carf = CARFFilter()
        self.news_ingestor = DynamicNewsIngestor()
        self.live_intelligence_cache = {}

        self.live_news_enabled = (
            os.getenv("LIVE_NEWS_ENABLED", "false").lower() == "true"
            if live_news_enabled is None
            else bool(live_news_enabled)
        )
        self.live_news_fetch_budget = (
            int(os.getenv("LIVE_NEWS_FETCH_BUDGET", "12"))
            if live_news_fetch_budget is None
            else int(live_news_fetch_budget)
        )

        self.scenario_mgr = scenario_mgr
        if self.scenario_mgr is None:
            try:
                from .scenario_manager import ScenarioManager
            except ImportError:
                try:
                    from scenario_manager import ScenarioManager
                except ImportError:
                    ScenarioManager = None
            if ScenarioManager is not None:
                try:
                    self.scenario_mgr = ScenarioManager()
                except TypeError:
                    self.scenario_mgr = ScenarioManager(self.unified_graph)

    def _get_live_intelligence(self, location, mode, fetch_state=None):
        """Fetch, NLP-score and CARF-filter live news with bounded requests."""
        cache_key = (location, (mode or "").lower())
        now = time.time()

        cached = self.live_intelligence_cache.get(cache_key)
        if cached and now - cached[0] < self.news_ingestor.cache_ttl:
            return cached[1:]

        if fetch_state is not None and fetch_state["count"] >= self.live_news_fetch_budget:
            fallback = self.news_ingestor.fallback_news.get(
                (mode or "").lower(),
                "Normal operational conditions reported.",
            )
            return fallback, 0.0, "FALLBACK"

        if fetch_state is not None:
            fetch_state["count"] += 1

        news, source = self.news_ingestor.get_latest_news_with_source(location, mode)
        score = self.nlp.get_semantic_score(news)
        threat = self.carf.apply_filter(score, news, mode)

        self.live_intelligence_cache[cache_key] = (
            now,
            news,
            threat,
            source,
        )
        return news, threat, source

    def _activate_scenario(self, scenario):
        if self.scenario_mgr is None:
            return scenario, {}

        active = self.scenario_mgr.activate_scenario(scenario)
        disruptions = self.scenario_mgr.get_active_disruptions()
        return active, disruptions

    @staticmethod
    def _safe_physical_id(graph, node):
        data = graph.nodes[node]
        return data.get("physical_id", node)

    def recommend(
        self,
        source: str,
        destination: str,
        transport_preference: str = "any",
        routing_policy: str = "STRICT",
        cargo_type: str = "general",
        priority: str = "normal",
        scenario: str = None,
        overrides: dict = None,
    ) -> dict:
        t0 = time.perf_counter()
        overrides = overrides or {}

        if self.unified_graph is None:
            return {"error": "Multimodal network is not initialized."}

        avoid_hubs = overrides.get("avoid_chokepoints", [])
        cost_ceiling = overrides.get("cost_ceiling", 999999)
        max_delay = overrides.get("max_delay", 9999)

        # Resolve external city/hub names to the graph's virtual entry points.
        res_s = self.resolver.resolve_node_to_entry_point(source)
        res_d = self.resolver.resolve_node_to_entry_point(destination)

        if "error" in res_s:
            return {"error": res_s["error"]}
        if "error" in res_d:
            return {"error": res_d["error"]}

        s_vnode, d_vnode = res_s["id"], res_d["id"]
        active_scenario, disruptions = self._activate_scenario(scenario)

        candidates: List[dict] = []
        live_fetch_state = {"count": 0}

        for persona in ("FASTEST", "SAFEST", "BALANCED"):
            try:
                G_p = self.unified_graph.copy()

                for hub_id in avoid_hubs:
                    nodes_to_remove = [
                        node
                        for node, data in G_p.nodes(data=True)
                        if data.get("physical_id") == hub_id
                    ]
                    G_p.remove_nodes_from(nodes_to_remove)

                if scenario == "SUEZ_BLOCK":
                    affected_nodes = set(disruptions)
                    blocked_edges = [
                        (u, v)
                        for u, v, _data in G_p.edges(data=True)
                        if G_p.nodes[v].get("physical_id") in affected_nodes
                    ]
                    G_p.remove_edges_from(blocked_edges)

                if transport_preference != "any" and routing_policy == "STRICT":
                    allowed_modes = [transport_preference, "transfer", "road"]
                    edges_to_remove = [
                        (u, v)
                        for u, v, data in G_p.edges(data=True)
                        if data.get("transport_mode") not in allowed_modes
                    ]
                    G_p.remove_edges_from(edges_to_remove)

                live_edge_threats = {}
                predicted_edge_delays = {}
                prediction_details = {}

                def weight_func(u, v, data):
                    mode = data["transport_mode"]
                    base_time = float(data["baseline_time"])
                    base_cost = float(data.get("cost", 0))

                    v_data = G_p.nodes[v]
                    physical_id = v_data.get("physical_id")

                    threat = live_edge_threats.get(
                        (u, v), float(data.get("base_threat", 0.05))
                    )
                    delay = 0.0

                    if physical_id in disruptions:
                        threat = max(threat, disruptions[physical_id]["threat"])
                        delay += disruptions[physical_id]["delay"]

                    predicted_delay = 0.0
                    if data.get("type") != "transfer":
                        origin_id = G_p.nodes[u].get("physical_id", u)
                        condition = (
                            "Disrupted" if physical_id in disruptions else "Clear"
                        )
                        prediction_key = (
                            origin_id,
                            physical_id,
                            mode,
                            condition,
                            round(threat, 6),
                        )

                        if prediction_key not in prediction_details:
                            prediction_details[prediction_key] = (
                                self.predictor.predict_worst_case_delay(
                                    origin_id,
                                    physical_id,
                                    mode,
                                    condition_flag=condition,
                                    nlp_score=threat,
                                )
                            )

                        prediction = prediction_details[prediction_key]
                        predicted_delay = float(
                            prediction.get("final_delay_presented", 0.0)
                        )
                        predicted_edge_delays[(u, v)] = predicted_delay

                    delay += predicted_delay

                    if persona == "FASTEST":
                        return base_time + delay
                    if persona == "SAFEST":
                        return (base_time + delay) * (1.0 + threat * 12.0)

                    time_weight = 0.3
                    cost_weight = 0.5
                    risk_weight = 0.2
                    return (
                        (base_time + delay) * time_weight
                        + (base_cost / 150.0) * cost_weight
                        + (threat * 40.0) * risk_weight
                    )

                path = nx.dijkstra_path(
                    G_p, s_vnode, d_vnode, weight=weight_func
                )

                # Re-score live intelligence and reroute until stable.
                last_scored_path = path
                path_stable = False

                for _ in range(3):
                    previous_path = path

                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        data = G_p[u][v]
                        if data["type"] == "transfer" or not self.live_news_enabled:
                            continue

                        v_data = G_p.nodes[v]
                        _, live_threat, _ = self._get_live_intelligence(
                            v_data.get(
                                "display_name",
                                v_data.get("physical_id", v),
                            ),
                            data["transport_mode"],
                            live_fetch_state,
                        )
                        live_edge_threats[(u, v)] = max(
                            data.get("base_threat", 0.05),
                            live_threat,
                        )

                    last_scored_path = previous_path
                    path = nx.dijkstra_path(
                        G_p, s_vnode, d_vnode, weight=weight_func
                    )

                    if path == previous_path:
                        path_stable = True
                        break

                if not path_stable:
                    path = last_scored_path

                legs = []
                total_time = 0.0
                total_cost = 0.0
                max_threat = 0.0
                shap_entries = []

                trace = {
                    "eta": {"transit": 0.0, "transfer": 0.0, "scenario": 0.0},
                    "cost": {"transit": 0.0, "transfer": 0.0, "scenario": 0.0},
                    "risk": {"baseline": 0.0, "scenario": 0.0},
                    "p85_predictions": [],
                    "shap_explanations": [],
                    "scenario": active_scenario,
                }

                for i in range(len(path) - 1):
                    u, v = path[i], path[i + 1]
                    data = G_p[u][v]
                    mode = data["transport_mode"]
                    v_data = G_p.nodes[v]
                    physical_id = v_data.get("physical_id")

                    predicted_delay = float(
                        predicted_edge_delays.get((u, v), 0.0)
                    )
                    leg_time = float(data["baseline_time"]) + predicted_delay
                    leg_cost = float(data.get("cost", 0))
                    leg_threat = float(data.get("base_threat", 0.05))
                    leg_news = data.get("base_news", "Standard conditions")
                    leg_source = "FALLBACK"

                    if physical_id in disruptions:
                        disruption = disruptions[physical_id]
                        leg_time += float(disruption["delay"])
                        leg_threat = max(
                            leg_threat, float(disruption["threat"])
                        )
                        leg_news = disruption["reason"]
                        leg_source = "SCENARIO"

                        trace["eta"]["scenario"] += float(disruption["delay"])
                        trace["risk"]["scenario"] = max(
                            trace["risk"]["scenario"], leg_threat
                        )
                        trace["cost"]["scenario"] += leg_cost * 0.1

                    elif data["type"] != "transfer" and self.live_news_enabled:
                        live_news, live_threat, live_source = (
                            self._get_live_intelligence(
                                v_data.get("display_name", physical_id),
                                mode,
                                live_fetch_state,
                            )
                        )
                        leg_news = live_news
                        leg_threat = max(leg_threat, live_threat)
                        leg_source = live_source

                    # Reuse the exact prediction that affected routing so the
                    # audit trace cannot disagree with the route's edge weight.
                    if data["type"] != "transfer":
                        origin_id = G_p.nodes[u].get("physical_id", u)
                        condition = (
                            "Disrupted"
                            if physical_id in disruptions
                            else "Clear"
                        )
                        key = (
                            origin_id,
                            physical_id,
                            mode,
                            condition,
                            round(leg_threat, 6),
                        )
                        prediction = prediction_details.get(key)
                        if prediction is None:
                            prediction = self.predictor.predict_worst_case_delay(
                                origin_id,
                                physical_id,
                                mode,
                                condition_flag=condition,
                                nlp_score=leg_threat,
                            )
                            prediction_details[key] = prediction

                        predicted_delay = float(
                            prediction.get("final_delay_presented", 0.0)
                        )
                        leg_time = float(data["baseline_time"]) + predicted_delay
                        if physical_id in disruptions:
                            leg_time += float(disruptions[physical_id]["delay"])

                        trace["p85_predictions"].append(
                            {
                                "origin": origin_id,
                                "destination": physical_id,
                                "transport_mode": mode,
                                "delay_hours": round(predicted_delay, 2),
                                "raw_model_prediction": prediction.get(
                                    "raw_model_prediction"
                                ),
                                "calibration_reason": prediction.get(
                                    "calibration_reason"
                                ),
                            }
                        )

                        shap_explanation = prediction.get("shap_explanation")
                        if shap_explanation:
                            entry = {
                                "origin": origin_id,
                                "destination": physical_id,
                                "transport_mode": mode,
                                **shap_explanation,
                            }
                            shap_entries.append(entry)

                    total_time += leg_time
                    total_cost += leg_cost
                    max_threat = max(max_threat, leg_threat)

                    if data["type"] == "transfer":
                        trace["eta"]["transfer"] += leg_time
                        trace["cost"]["transfer"] += leg_cost
                    else:
                        trace["eta"]["transit"] += leg_time
                        trace["cost"]["transit"] += leg_cost
                        trace["risk"]["baseline"] = max(
                            trace["risk"]["baseline"], leg_threat
                        )

                    legs.append(
                        {
                            "from": G_p.nodes[u].get(
                                "display_name",
                                G_p.nodes[u].get("physical_id", u),
                            ),
                            "to": v_data.get(
                                "display_name",
                                v_data.get("physical_id", v),
                            ),
                            "transport_mode": mode,
                            "baseline_time": round(float(data["baseline_time"]), 2),
                            "predicted_delay": round(predicted_delay, 2),
                            "time": round(leg_time, 2),
                            "cost": round(leg_cost, 2),
                            "threat_level": round(leg_threat, 4),
                            "news": leg_news,
                            "news_source": leg_source,
                        }
                    )

                trace["shap_explanations"] = shap_entries

                if total_cost > cost_ceiling or total_time > max_delay:
                    continue

                candidates.append(
                    {
                        "persona": persona,
                        "legs": legs,
                        "adjusted_eta": round(total_time, 2),
                        "total_cost": round(total_cost, 2),
                        "threat_level": round(max_threat, 4),
                        "audit_trace": trace,
                        "explanation": (
                            f"{persona} route selected with p85 ML delay "
                            "included in edge scoring."
                        ),
                        "cargo_type": cargo_type,
                        "priority": priority,
                    }
                )

            except (nx.NetworkXNoPath, nx.NodeNotFound) as exc:
                candidates.append(
                    {
                        "persona": persona,
                        "error": f"No feasible route: {exc}",
                    }
                )
            except Exception as exc:
                print(f"[ROUTER] {persona} recommendation failed: {exc}")
                candidates.append(
                    {
                        "persona": persona,
                        "error": str(exc),
                    }
                )

        valid_candidates = [
            candidate for candidate in candidates if "error" not in candidate
        ]

        return {
            "source": source,
            "destination": destination,
            "active_scenario": active_scenario,
            "recommendations": candidates,
            # Keep the compact alias used by the UI/sample response format.
            "personas": valid_candidates,
            "meta": {
                "routing_policy": routing_policy,
                "transport_preference": transport_preference,
                "cargo_type": cargo_type,
                "priority": priority,
                "live_news_enabled": self.live_news_enabled,
                "live_news_fetches": live_fetch_state["count"],
                "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            },
        }
