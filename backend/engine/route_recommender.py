import networkx as nx
import math
import time
from typing import List, Dict, Any, Optional
from .multimodal_network import MODE_PROFILES, create_multimodal_network
from .threat_intelligence import ThreatIntelligencePredictor, ContrastiveNLPEngine, CARFFilter
from .news_ingestion import DynamicNewsIngestor
from .node_resolver import NodeResolver

PERSONAS = ["FASTEST", "SAFEST", "BALANCED"]


class RouteRecommender:
    """
    Supplychainer Unified Multimodal Optimization Engine.
    V8: Virtual-Node Forensic Edition.

    Patched: live news -> NLP -> CARF now drives threat on the corridor being
    routed, and the p85 quantile model adds a worst-case delay buffer to the
    SAFEST and BALANCED weights. Both are computed lazily for candidate-path
    edges only (not the whole graph) and iterated until the candidate set is stable.
    """

    def __init__(self, network, predictor, simulator, scenario_mgr, demo_mode=False):
        self.network = network # Legacy
        self.predictor = predictor
        self.simulator = simulator
        self.scenario_mgr = scenario_mgr
        self.demo_mode = demo_mode
        self.is_warmed_up = False
        self.warmup_failed = False

        self.nlp = ContrastiveNLPEngine(lazy_load=True)
        self.carf = CARFFilter()
        self.news_ingestor = DynamicNewsIngestor()
        self.resolver = NodeResolver()

        self._score_cache = {}   # (news_text, mode) -> CARF-filtered threat
        self._ml_cache = {}      # (origin, dest, mode, nlp_bucket) -> p85 hours or None

        print(f"[STARTUP] Initializing Split-Node Global Topology...")
        self.unified_graph = create_multimodal_network()


        if self.demo_mode:
            print("[DEMO MODE] Running synchronous warmup...")
            self.run_background_warmup()

        print(f"[STARTUP] Unified Engine Ready.")

    def run_background_warmup(self):
        if self.is_warmed_up: return
        print("[WARMUP] Calibrating global threat floor...")
        try:
            self.predictor.warmup()
            self.nlp.warmup()

            # Offline baseline intelligence (used when live news is unavailable)
            for u, v, d in self.unified_graph.edges(data=True):
                mode = d.get("transport_mode", "road")
                if mode == "transfer": continue
                news = self.news_ingestor.fallback_news.get(mode, "Normal conditions.")
                score = self.nlp.get_semantic_score(news)
                threat = self.carf.apply_filter(score, news, mode)
                self.unified_graph[u][v]["base_threat"] = threat
                self.unified_graph[u][v]["base_news"] = news

            self.is_warmed_up = True
            print("[WARMUP] Unified Calibration Complete.")
        except Exception as e:
            print(f"[WARMUP] Error during warmup: {e}")
            self.warmup_failed = True

    # ------------------------------------------------------------------
    # Live intelligence + ML buffer (computed only for edges we actually consider)
    # ------------------------------------------------------------------
    def _live_intel(self, G, pairs):
        """pairs: [(physical_id, mode)] -> {(physical_id, mode): {threat, news, source}}"""
        keyed = []
        for pid, mode in pairs:
            node = f"{pid}:{mode}"
            name = G.nodes[node].get("display_name", pid) if node in G else pid
            keyed.append(((pid, mode), (name, mode)))

        fetched = self.news_ingestor.prefetch([k for _, k in keyed])
        out = {}
        for pair, k in keyed:
            text, source = fetched[k]
            ck = (text, pair[1])
            if ck not in self._score_cache:
                score = self.nlp.get_semantic_score(text)          # 0.0 if NLP not ready
                self._score_cache[ck] = self.carf.apply_filter(score, text, pair[1])
            out[pair] = {"threat": self._score_cache[ck], "news": text, "source": source}
        return out

    def _ml_buffer(self, G, u, v, nlp_score, disruptions=None):
        if not getattr(self.predictor, "is_trained", False):
            return None
        d = G[u][v]
        disruptions = disruptions or {}

        # Derive condition from active disruptions on the destination node
        p_id = G.nodes[v].get("physical_id", "")
        if p_id in disruptions:
            threat_level = disruptions[p_id].get("threat", 0.0)
            condition_flag = "Disrupted" if threat_level >= 0.75 else "Degraded"
        else:
            condition_flag = "Clear"

        key = (G.nodes[u].get("display_name"), G.nodes[v].get("display_name"),
            d["transport_mode"], round(nlp_score, 1), condition_flag)

        if key not in self._ml_cache:
            try:
                r = self.predictor.predict_worst_case_delay(
                    key[0], key[1], key[2],
                    nlp_score=nlp_score,
                    condition_flag=condition_flag
                )
                self._ml_cache[key] = float(r["final_delay_presented"]) if r.get("covered", True) else None
            except Exception as e:
                print(f"[ML] p85 lookup failed for {key}: {e}")
                self._ml_cache[key] = None
        return self._ml_cache[key]
    def _enrich(self, G, edges, disruptions, intel, buffers):
        transit = [(u, v) for u, v in edges if G[u][v]["type"] != "transfer"]
        pairs = {(G.nodes[v].get("physical_id"), G[u][v]["transport_mode"]) for u, v in transit}
        pairs = [p for p in pairs if p not in intel]
        if pairs:
            intel.update(self._live_intel(G, pairs))
        for u, v in transit:
            d = G[u][v]
            pid = G.nodes[v].get("physical_id")
            # Scenario delay already dominates a disrupted hub; don't stack the model on top.
            if pid in disruptions:
                buffers[(u, v)] = None
                continue
            threat = self._edge_threat(d, pid, d["transport_mode"], intel)
            buffers[(u, v)] = self._ml_buffer(G, u, v, threat, disruptions=disruptions)

    @staticmethod
    def _edge_threat(d, p_id, mode, intel):
        live = intel.get((p_id, mode))
        if live and live["source"] == "LIVE":
            return live["threat"]
        return d.get("base_threat", 0.05)

    # ------------------------------------------------------------------
    def recommend(self, source: str, destination: str, transport_preference: str = "any",
                  routing_policy: str = "STRICT", cargo_type: str = "general",
                  priority: str = "normal", scenario: str = None,
                  overrides: dict = None) -> dict:
        t0 = time.perf_counter()
        overrides = overrides or {}
        avoid_hubs = overrides.get("avoid_chokepoints", [])
        cost_ceiling = overrides.get("cost_ceiling", 999999)
        max_delay = overrides.get("max_delay", 9999)

        # 1. Resolve Entry/Exit (Virtual Nodes)
        res_s = self.resolver.resolve_node_to_entry_point(source)
        res_d = self.resolver.resolve_node_to_entry_point(destination)

        if "error" in res_s: return {"error": res_s["error"]}
        if "error" in res_d: return {"error": res_d["error"]}

        s_vnode, d_vnode = res_s["id"], res_d["id"]

        # 2. Scenario Activation
        active_scenario = self.scenario_mgr.activate_scenario(scenario)
        disruptions = self.scenario_mgr.get_active_disruptions()

        G_base = self.unified_graph.copy()
        for hub_id in avoid_hubs:
            G_base.remove_nodes_from([n for n, d in G_base.nodes(data=True)
                                      if d.get("physical_id") == hub_id])
        refs = {
            "air":     self._reference_route(G_base, s_vnode, d_vnode, ["air", "transfer", "road"], disruptions),
            "surface": self._reference_route(G_base, s_vnode, d_vnode, ["sea", "rail", "road", "transfer"], disruptions),
        }

        # Persona graph: the STRICT filter is identical for every persona, so build it once.
        G_p = G_base
        if transport_preference != "any" and routing_policy == "STRICT":
            allowed_modes = [transport_preference, "transfer", "road"]
            G_p.remove_edges_from([(u, v) for u, v, d in G_p.edges(data=True)
                                   if d["transport_mode"] not in allowed_modes])

        intel: Dict[Any, Any] = {}      # (physical_id, mode) -> live intel
        buffers: Dict[Any, Any] = {}    # (u, v) -> p85 buffer hours (None = not covered)

        def make_weight(persona):
            def weight_func(u, v, d):
                mode = d["transport_mode"]
                base_t = d["baseline_time"]
                base_c = d.get("cost", 0)
                p_id = G_p.nodes[v].get("physical_id")

                threat = self._edge_threat(d, p_id, mode, intel)
                delay = 0
                if p_id in disruptions:
                    threat = max(threat, disruptions[p_id]["threat"])
                    delay += disruptions[p_id]["delay"]
                buf = buffers.get((u, v)) or 0.0

                if persona == "FASTEST":
                    return base_t + delay
                elif persona == "SAFEST":
                    return (base_t + delay + buf) * (1.0 + threat * 12.0)
                else:  # BALANCED
                    return ((base_t + delay + buf) * 0.3
                            + (base_c / 150.0) * 0.5
                            + (threat * 40.0) * 0.2)
            return weight_func

        # 3a. Discovery: route with what we know, fetch intel for the edges those routes use,
        #     re-route, repeat until no new edges show up (max 3 rounds).
        seen_edges = set()
        for _ in range(3):
            edges = set()
            for persona in PERSONAS:
                try:
                    p = nx.dijkstra_path(G_p, s_vnode, d_vnode, weight=make_weight(persona))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                edges.update(zip(p, p[1:]))
            fresh = edges - seen_edges
            if not fresh:
                break
            self._enrich(G_p, fresh, disruptions, intel, buffers)
            seen_edges |= fresh

        # 3b. Final persona optimization
        candidates = []
        for persona in PERSONAS:
            try:
                path = nx.dijkstra_path(G_p, s_vnode, d_vnode, weight=make_weight(persona))

                legs = []
                total_time, total_cost, max_threat, total_buffer = 0, 0, 0, 0.0
                trace = {
                    "eta": {"transit": 0, "transfer": 0, "scenario": 0, "p85_buffer": 0},
                    "cost": {"transit": 0, "transfer": 0, "scenario": 0},
                    "risk": {"baseline": 0, "scenario": 0}
                }

                for i in range(len(path)-1):
                    u, v = path[i], path[i+1]
                    d = G_p[u][v]
                    mode = d["transport_mode"]
                    v_data = G_p.nodes[v]
                    p_id = v_data.get("physical_id")

                    l_time = d["baseline_time"]
                    l_cost = d.get("cost", 0)
                    l_delay = 0.0
                    l_premium = 0.0
                    l_threat = d.get("base_threat", 0.05)
                    l_news = d.get("base_news", "Standard conditions")
                    l_source = "FALLBACK"

                    live = intel.get((p_id, mode))
                    if live and live["source"] == "LIVE":
                        l_threat = live["threat"]
                        l_news = live["news"]
                        l_source = "LIVE"

                    if p_id in disruptions:
                        l_delay = disruptions[p_id]["delay"]
                        l_premium = l_cost * 0.1
                        l_threat = max(l_threat, disruptions[p_id]["threat"])
                        l_news = disruptions[p_id]["reason"]
                        l_source = "SCENARIO"
                        trace["eta"]["scenario"] += l_delay
                        trace["cost"]["scenario"] += l_premium
                        trace["risk"]["scenario"] = max(trace["risk"]["scenario"], l_threat)

                    l_buffer = buffers.get((u, v))

                    if d["type"] == "transfer":
                        trace["eta"]["transfer"] += l_time
                        trace["cost"]["transfer"] += l_cost
                    else:
                        trace["eta"]["transit"] += l_time
                        trace["cost"]["transit"] += l_cost
                        trace["risk"]["baseline"] = max(trace["risk"]["baseline"], l_threat)

                    if l_buffer:
                        trace["eta"]["p85_buffer"] += l_buffer
                        total_buffer += l_buffer

                    total_time += l_time + l_delay
                    total_cost += l_cost + l_premium
                    max_threat = max(max_threat, l_threat)

                    legs.append({
                        "from": G_p.nodes[u].get("physical_id", u),
                        "to": p_id,
                        "to_name": v_data.get("display_name", p_id),
                        "mode": mode.upper(),
                        "type": d["type"],
                        "eta": round(l_time + l_delay, 1),
                        "eta_transit": round(l_time, 1),
                        "eta_delay": round(l_delay, 1),
                        "cost": round(l_cost + l_premium, 2),
                        "cost_base": round(l_cost, 2),
                        "cost_premium": round(l_premium, 2),
                        "p85_buffer": round(l_buffer, 1) if l_buffer is not None else None,
                        "threat": round(l_threat, 2),
                        "reason": l_news,
                        "intel_source": l_source
                    })

                if total_cost > cost_ceiling or total_time > (max_delay * 24): continue

                candidates.append({
                    "persona": persona,
                    "primary_mode": "MULTIMODAL",
                    "legs": legs,
                    "adjusted_eta": round(total_time, 1),
                    "p85_eta": round(total_time + total_buffer, 1),
                    "total_cost": round(total_cost, 2),
                    "threat_level": round(max_threat, 2),
                    "audit_trace": trace,
                    "override_applied": bool(avoid_hubs or cost_ceiling < 999999)
                })

            except nx.NetworkXNoPath:
                continue
            except Exception as e:
                print(f"[ROUTING ERROR] {persona}: {e}")

        if not candidates:
            return {"error": "No valid multimodal route established under current strategic constraints."}

        # Deduplicate and sort
        final = []
        seen = set()
        for c in sorted(candidates, key=lambda x: x["adjusted_eta"]):
            path_sig = tuple((l["mode"], l["to"]) for l in c["legs"])
            if path_sig not in seen:
                final.append(c)
                seen.add(path_sig)
        peer_threats = [c["threat_level"] for c in final]
        for c in final:
            c["explanation"] = self._generate_forensic_explanation(
                c["persona"], c["audit_trace"], c["threat_level"], c["legs"], refs, peer_threats)
        return {
            "origin": source, "destination": destination,
            "active_scenario": active_scenario["name"] if active_scenario else None,
            "recommendations": final[:3]
        }

    def _reference_route(self, G, s_vnode, d_vnode, allowed_modes, disruptions):
        """Single-mode baseline (pure AIR / pure surface) for explanations. None if no route."""
        G_ref = G.copy()
        G_ref.remove_edges_from([(u, v) for u, v, d in G_ref.edges(data=True)
                                 if d["transport_mode"] not in allowed_modes])
        try:
            path = nx.dijkstra_path(G_ref, s_vnode, d_vnode, weight="baseline_time")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

        eta = cost = 0.0
        for u, v in zip(path, path[1:]):
            d = G_ref[u][v]
            leg_t, leg_c = d["baseline_time"], d.get("cost", 0.0)
            hit = disruptions.get(G_ref.nodes[v].get("physical_id"))
            if hit:
                leg_t += hit["delay"]
                leg_c += leg_c * 0.1
            eta += leg_t
            cost += leg_c
        return {"eta": round(eta, 1), "cost": round(cost, 2)}

    def _generate_forensic_explanation(self, persona, trace, threat, legs, refs, peer_threats):
        eta = trace["eta"]["transit"] + trace["eta"]["transfer"] + trace["eta"]["scenario"]
        cost = trace["cost"]["transit"] + trace["cost"]["transfer"] + trace["cost"]["scenario"]
        transfer_count = sum(1 for l in legs if l["type"] == "transfer")

        if persona == "FASTEST":
            ref = refs["surface"]
            if ref and ref["eta"] > eta:
                claim = f"Arrives {round(ref['eta'] - eta, 1)}h sooner than the fastest surface-only alternative."
            elif ref:
                claim = f"Matches the surface-only alternative within {round(abs(ref['eta'] - eta), 1)}h."
            else:
                claim = "No surface-only alternative exists for this lane."
            return (f"Velocity-optimized. {claim} {transfer_count} strategic transfer(s) "
                    f"totalling {round(trace['eta']['transfer'], 1)}h.")

        if persona == "SAFEST":
            worse = [t for t in peer_threats if t > threat]
            if worse:
                peak = max(worse)
                claim = (f"Holds threat exposure {round((peak - threat) / peak * 100)}% below the "
                         f"{round(peak * 100)}% ceiling of the alternatives evaluated.")
            else:
                claim = (f"Ties the lowest threat exposure of the alternatives evaluated "
                         f"at {round(threat * 100)}%.")
            return f"Resilience-optimized. {claim} Lead-time integrity prioritized over cost."

        ref = refs["air"]
        if ref and ref["cost"] > 0:
            delta = (ref["cost"] - cost) / ref["cost"] * 100
            claim = (f"Lands {round(delta)}% below the air-only alternative (${round(ref['cost'] - cost)} saved)."
                     if delta >= 0 else
                     f"Priced {round(-delta)}% above the air-only alternative (${round(cost - ref['cost'])} premium).")
        elif ref:
            claim = "Air-only alternative priced at zero; no cost basis to compare."
        else:
            claim = "No air-only alternative exists for this lane."
        scen = (f" Scenario adds ${round(trace['cost']['scenario'])} and {round(trace['eta']['scenario'])}h."
                if trace["cost"]["scenario"] or trace["eta"]["scenario"] else "")
        return f"Economic-optimized. {claim} Lead time {round(eta, 1)}h at ${round(cost)} landed.{scen}"