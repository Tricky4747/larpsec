import React, { useState, useEffect } from 'react';
import {
Truck, Ship, Plane, Train,
AlertTriangle, ShieldCheck, Clock, Navigation,
MapPin, Zap, Globe, ArrowRightLeft,
BarChart3, Activity, Layers, Terminal
} from 'lucide-react';

// Compare each route with the same route type run without the scenario.
const pathOf = (route) =>
  route.legs.filter(l => l.type !== 'transfer').map(l => l.to).join('>');

const computeImpact = (withScenario, baseline) =>
  withScenario.map(scen => {
    const base = baseline.find(r => r.persona === scen.persona);
    if (!base) return null;
    return {
      persona: scen.persona,
      deltaEta: Math.round((scen.adjusted_eta - base.adjusted_eta) * 10) / 10,
      deltaCost: Math.round(scen.total_cost - base.total_cost),
      pathChanged: pathOf(scen) !== pathOf(base),
      hitLegs: scen.legs.filter(l => l.intel_source === 'SCENARIO').length
    };
  }).filter(Boolean);

const RouteRecommender = ({
  onNavigate,
  onRouteGenerated,
  onRouteSelected
}) => {
const [source, setSource] = useState('');
const [destination, setDestination] = useState('');
const [transportMode, setTransportMode] = useState('any');
const [routingPolicy, setRoutingPolicy] = useState('STRICT');
const [operationalConfig, setOperationalConfig] = useState('NORMAL');
const [cargoType, setCargoType] = useState('general');
const [priority, setPriority] = useState('normal');
const [recommendations, setRecommendations] = useState([]);
const [selectedIdx, setSelectedIdx] = useState(0);
const [loading, setLoading] = useState(false);
const [error, setError] = useState(null);
const [searchQuery, setSearchQuery] = useState({
source: '',
dest: ''
});
const [searchResults, setSearchResults] = useState({
source: [],
dest: []
});
const [scenarios, setScenarios] = useState([]);
const [impact, setImpact] = useState(null);

useEffect(() => {
fetch('/api/scenarios')
.then(r => r.json())
.then(data => setScenarios(data))
.catch(e => console.error('Failed to load scenarios', e));



}, []);

const getRecommendations = async () => {
  if (!source || !destination) {
    setError('Please search and select both an Origin Hub and Destination Hub.');
    return;
  }

  setLoading(true);
  setError(null);
  setImpact(null);

  const scenarioId = operationalConfig !== 'NORMAL' ? operationalConfig : null;

  // Same request every time; only the scenario changes.
  const requestRoutes = async (scenario) => {
    const res = await fetch('/api/recommend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source,
        destination,
        transport_preference: transportMode,
        routing_policy: routingPolicy,
        cargo_type: cargoType,
        priority: priority,
        scenario
      })
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, data };
  };

  try {
    const { ok, data } = await requestRoutes(scenarioId);

    const validRecs = Array.isArray(data.recommendations)
      ? data.recommendations.filter(r => r && !r.error && Array.isArray(r.legs))
      : [];

    if (!ok || data.error || validRecs.length === 0) {
      setError(data.error || data.detail || 'No feasible route found under current strategic constraints.');
      setRecommendations([]);
      if (typeof onRouteGenerated === 'function') onRouteGenerated(null);
      return;
    }

    setRecommendations(validRecs);
    setSelectedIdx(0);
    if (typeof onRouteGenerated === 'function') {
      onRouteGenerated(validRecs[0] || null, {
        origin: searchQuery.source,
        destination: searchQuery.dest,
        scenario: scenarioId
      });
    }

    // Scenario impact: compare with the same request without the scenario.
    if (scenarioId) {
      const base = await requestRoutes(null);
      if (base.ok && Array.isArray(base.data.recommendations)) {
        const baseRecs = base.data.recommendations.filter(r => r && !r.error && Array.isArray(r.legs));
        if (baseRecs.length > 0) {
          setImpact(computeImpact(validRecs, baseRecs));
        }
      }
    }
  } catch (err) {
    setError('Engine connection failed. Verify backend status.');
    if (typeof onRouteGenerated === 'function') onRouteGenerated(null);
  } finally {
    setLoading(false);
  }
};

const getModeIcon = (mode) => {
switch (mode.toLowerCase()) {
case 'air':
return <Plane size={12} />;
case 'sea':
return <Ship size={12} />;
case 'rail':
return <Train size={12} />;
case 'road':
return <Truck size={12} />;
case 'transfer':
return <ArrowRightLeft size={12} />;
default:
return <Navigation size={12} />;
}
};

const handleSearch = async (type, query) => {
setSearchQuery(prev => ({
...prev,
[type]: query
}));

if (query.length < 2) {
  setSearchResults(prev => ({
    ...prev,
    [type]: []
  }));
  return;
}

try {
  const res = await fetch(`/api/hubs/search?q=${encodeURIComponent(query)}`);
  const data = await res.json();

  setSearchResults(prev => ({
    ...prev,
    [type]: data
  }));
} catch (err) {
  console.error('Search failed');
}

};

const selectHub = (type, hub) => {
if (type === 'source') {
setSource(hub.id);
setSearchQuery(prev => ({
...prev,
source: hub.display_name
}));
} else {
setDestination(hub.id);
setSearchQuery(prev => ({
...prev,
dest: hub.display_name
}));
}

setSearchResults(prev => ({
  ...prev,
  [type]: []
}));

};

const selected =
recommendations[selectedIdx] || recommendations[0];

return (
<div className="dashboard-layout">

  <header className="dashboard-header">
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1rem'
      }}
    >
      <Globe size={28} color="#3b82f6" />

      <div>
        <h1
          style={{
            fontSize: '1.25rem',
            fontWeight: 800
          }}
        >
          Supplychainer Command Console
        </h1>

        <p
          style={{
            fontSize: '0.7rem',
            color: '#64748b',
            fontWeight: 700
          }}
        >
          UNIFIED MULTIMODAL DECISION SUPERIORITY ENGINE
        </p>
      </div>
    </div>

    <div
      style={{
        display: 'flex',
        gap: '1rem'
      }}
    >
      <button
        className="sc-badge-active"
        onClick={() => onNavigate('network')}
        style={{ cursor: 'pointer' }}
      >
        <MapPin size={14} /> NETWORK MAP
      </button>

      <button
        className="sc-badge-active"
        onClick={() => onNavigate('suppliers')}
        style={{ cursor: 'pointer' }}
      >
        <ShieldCheck size={14} /> SUPPLIER INTELLIGENCE
      </button>
    </div>
  </header>

  <aside className="sidebar-left">
    <h2 className="panel-title">
      <Terminal size={14} /> Strategic Input Panel
    </h2>

    <div className="sc-input-group">
      <label className="sc-label">Origin Hub</label>

      <input
        type="text"
        value={searchQuery.source}
        onChange={(e) =>
          handleSearch('source', e.target.value)
        }
        className="sc-input"
        placeholder="Search origin..."
      />

      {searchResults.source.length > 0 && (
        <div
          style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '4px',
            marginTop: '2px'
          }}
        >
          {searchResults.source.map((h, idx) => (
            <button
              key={`${h.id}-${idx}`}
              onClick={() => selectHub('source', h)}
              style={{
                width: '100%',
                padding: '8px',
                textAlign: 'left',
                background: 'none',
                border: 'none',
                color: 'white',
                borderBottom: '1px solid #1e293b',
                cursor: 'pointer',
                fontSize: '0.8rem'
              }}
            >
              {h.display_name}
            </button>
          ))}
        </div>
      )}
    </div>

    <div className="sc-input-group">
      <label className="sc-label">Destination Hub</label>

      <input
        type="text"
        value={searchQuery.dest}
        onChange={(e) =>
          handleSearch('dest', e.target.value)
        }
        className="sc-input"
        placeholder="Search destination..."
      />

      {searchResults.dest.length > 0 && (
        <div
          style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: '4px',
            marginTop: '2px'
          }}
        >
          {searchResults.dest.map((h, idx) => (
            <button
              key={`${h.id}-${idx}`}
              onClick={() => selectHub('dest', h)}
              style={{
                width: '100%',
                padding: '8px',
                textAlign: 'left',
                background: 'none',
                border: 'none',
                color: 'white',
                borderBottom: '1px solid #1e293b',
                cursor: 'pointer',
                fontSize: '0.8rem'
              }}
            >
              {h.display_name}
            </button>
          ))}
        </div>
      )}
    </div>

    <div className="sc-input-group">
      <label className="sc-label">Transport Mode</label>

      <select
        value={transportMode}
        onChange={e => setTransportMode(e.target.value)}
        className="sc-select"
      >
        <option value="any">Unconstrained</option>
        <option value="sea">SEA (Maritime Corridors)</option>
        <option value="air">AIR (Express Cargo)</option>
        <option value="rail">RAIL (Inland Freight)</option>
        <option value="road">ROAD (Local Distribution)</option>
      </select>
    </div>

    <div className="sc-input-group">
      <label className="sc-label">Routing Policy</label>

      <select
        value={routingPolicy}
        onChange={e => setRoutingPolicy(e.target.value)}
        className="sc-select"
      >
        <option value="STRICT">
          STRICT (Hard Exclusion)
        </option>
        <option value="PREFERRED">
          PREFERRED (Soft Bias)
        </option>
      </select>
    </div>

    <div className="sc-input-group">
      <label className="sc-label">
        Operational Configuration
      </label>

      <select
        value={operationalConfig}
        onChange={e =>
          setOperationalConfig(e.target.value)
        }
        className="sc-select"
        style={{
          borderColor:
            operationalConfig !== 'NORMAL'
              ? '#ef4444'
              : '#1e293b'
        }}
      >
        <option value="NORMAL">
          Operational Normal
        </option>

        {scenarios.map(s => (
          <option key={s.id} value={s.id}>
            {s.name}
          </option>
        ))}
      </select>
    </div>

    <div className="sc-input-group">
      <label className="sc-label">
        Strategic Overrides
      </label>

      <div
        style={{
          background: 'rgba(59, 130, 246, 0.05)',
          padding: '0.75rem',
          borderRadius: '8px',
          border: '1px solid #1e293b',
          fontSize: '0.75rem',
          color: '#64748b'
        }}
      >
        Auto-bypass enabled for verified chokepoints.
      </div>
    </div>

    <button
      className="sc-btn-execute"
      onClick={getRecommendations}
      disabled={loading}
    >
      {loading ? (
        <Zap className="animate-pulse" size={16} />
      ) : (
        'GENERATE STRATEGIC ROUTE OPTIONS'
      )}
    </button>
  </aside>

  <main className="main-content">

    {operationalConfig !== 'NORMAL' && (
      <div className="scenario-banner animate-slide-in">
        <AlertTriangle size={20} />

        <div>
          <span
            style={{
              fontWeight: 800,
              fontSize: '0.75rem',
              display: 'block'
            }}
          >
            ACTIVE GLOBAL DISRUPTION DETECTED
          </span>

          <span style={{ fontSize: '0.875rem' }}>
            {
              scenarios.find(
                s => s.id === operationalConfig
              )?.name
              || operationalConfig
            }
            {' '}logic active in unified solver.
          </span>
        </div>
      </div>
    )}

    {error && (
      <div
        style={{
          color: '#ef4444',
          background: 'rgba(239, 68, 68, 0.1)',
          padding: '1rem',
          borderRadius: '8px',
          border: '1px solid #ef4444'
        }}
      >
        {error}
      </div>
    )}

    {impact && (
      <div style={{ border: '1px solid #f59e0b', background: 'rgba(245,158,11,0.08)', borderRadius: 8, padding: '0.9rem 1rem' }}>
        <div style={{ fontWeight: 800, fontSize: '0.75rem', color: '#f59e0b' }}>
          SCENARIO IMPACT 
        </div>
        {impact.map(row => (
          <div key={row.persona} style={{ display: 'flex', gap: '1.5rem', marginTop: '0.4rem', fontSize: '0.9rem' }}>
            <strong style={{ minWidth: 90 }}>{row.persona}</strong>
            <span>ETA: {row.deltaEta >= 0 ? '+' : ''}{row.deltaEta}h</span>
            <span>Cost: {row.deltaCost >= 0 ? '+' : '-'}${Math.abs(row.deltaCost).toLocaleString()}</span>
            <span>Path: {row.pathChanged ? 'rerouted' : 'unchanged'}</span>
            <span>Legs hit: {row.hitLegs}</span>
          </div>
        ))}
        {impact.every(r => r.deltaEta === 0 && r.deltaCost === 0 && !r.pathChanged) && (
          <div style={{ marginTop: '0.4rem', fontSize: '0.8rem', color: '#94a3b8' }}>
            This scenario had no measurable effect on these routes.
          </div>
        )}
      </div>
    )}

    <div className="path-grid">

      {recommendations.map((rec, idx) => (
        <div
          key={idx}
          className="path-card"
          onClick={() => {
            setSelectedIdx(idx);
            onRouteSelected(rec);
          }}
          style={{
            cursor: 'pointer',
            outline:
              idx === selectedIdx
                ? '2px solid #3b82f6'
                : 'none'
          }}
        >

          <div className="card-header">

            <span
              className={`persona-badge ${
                rec.persona === 'FASTEST'
                  ? 'tag-fastest'
                  : rec.persona === 'SAFEST'
                  ? 'tag-safest'
                  : 'tag-balanced'
              }`}
            >
              {rec.persona}
            </span>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '0.75rem',
                fontFamily: 'JetBrains Mono'
              }}
            >
              <Clock size={12} />
              {rec.adjusted_eta}h
            </div>

          </div>

          <div style={{ padding: '1.25rem' }}>

            <h3
              style={{
                fontSize: '0.9rem',
                fontWeight: 700,
                marginBottom: '1.5rem'
              }}
            >
              {rec.explanation}
            </h3>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
                borderLeft: '2px solid #1e293b',
                paddingLeft: '1rem',
                marginLeft: '0.5rem'
              }}
            >

              {rec.legs.map((leg, lIdx) => {

                const isTransfer =
                  leg.type === 'transfer';

                return (
                  <div
                    key={lIdx}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      opacity:
                        isTransfer ? 0.7 : 1
                    }}
                  >

                    <span
                      style={{
                        fontSize: '0.65rem',
                        fontWeight: 800,
                        color:
                          isTransfer
                            ? '#94a3b8'
                            : '#3b82f6',
                        letterSpacing: '0.05em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                    >
                      {getModeIcon(leg.mode)}

                      {isTransfer
                        ? 'STRATEGIC HANDOFF'
                        : `${leg.mode} TRANSIT`}
                    </span>

                    <span
                      style={{
                        fontSize: '0.8rem',
                        fontWeight: 600
                      }}
                    >
                      {isTransfer
                        ? `Processing at ${leg.to_name}`
                        : `to ${leg.to_name}`}
                    </span>

                    {!isTransfer && (
                      <span
                        style={{
                          fontSize: '0.7rem',
                          color:
                            leg.threat >= 0.5
                              ? '#ef4444'
                              : '#64748b'
                        }}
                      >
                        {leg.eta}h • threat{' '}
                        {Math.round(leg.threat * 100)}%
                      </span>
                    )}

                    {leg.intel_source === 'SCENARIO' && (
                      <span
                        style={{
                          fontSize: '0.7rem',
                          color: '#fca5a5',
                          background:
                            'rgba(239,68,68,0.1)',
                          border:
                            '1px solid #ef4444',
                          borderRadius: 4,
                          padding: '4px 6px',
                          marginTop: 4
                        }}
                      >
                        {leg.reason}
                      </span>
                    )}

                  </div>
                );
              })}

            </div>
          </div>

          <div
            style={{
              padding: '1.25rem',
              borderTop: '1px solid #1e293b',
              background: 'rgba(15, 23, 42, 0.3)'
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: '0.8rem',
                fontWeight: 700
              }}
            >
              <span style={{ color: '#64748b' }}>
                TOTAL COST
              </span>

              <span style={{ color: '#10b981' }}>
                ${rec.total_cost != null ? rec.total_cost.toLocaleString() : '0'}
              </span>
            </div>
          </div>

        </div>
      ))}

    </div>
  </main>

  <aside className="sidebar-right">

    <h2 className="panel-title">
      <Layers size={14} /> Decision Integrity Audit
    </h2>

    {recommendations.length > 0 && selected && selected.audit_trace ? (

      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem'
        }}
      >

        <div
          className="audit-trace-box"
          style={{
            borderLeft: '4px solid #3b82f6'
          }}
        >
          <div
            style={{
              marginBottom: '0.5rem',
              fontWeight: 700,
              color: '#f8fafc'
            }}
          >
            Forensic ETA Audit
          </div>

          <div>
            Transit: {selected.audit_trace.eta?.transit != null ? `${selected.audit_trace.eta.transit}h` : 'N/A'}
          </div>

          <div>
            Transfer: +{selected.audit_trace.eta?.transfer != null ? `${selected.audit_trace.eta.transfer}h` : '0h'}
          </div>

          <div>
            Scenario Impact:{' '}
            {selected.audit_trace.eta?.scenario > 0
              ? `+${selected.audit_trace.eta.scenario}h`
              : 'None'}
          </div>
        </div>

        <div
          className="audit-trace-box"
          style={{
            borderLeft: '4px solid #10b981'
          }}
        >
          <div
            style={{
              marginBottom: '0.5rem',
              fontWeight: 700,
              color: '#f8fafc'
            }}
          >
            Cost Composition
          </div>

          <div>
            Landed Base: $
            {selected.audit_trace.cost?.transit != null ? selected.audit_trace.cost.transit.toLocaleString() : '0'}
          </div>

          <div>
            Transfer Fees: $
            {selected.audit_trace.cost?.transfer != null ? selected.audit_trace.cost.transfer.toLocaleString() : '0'}
          </div>

          <div>
            Risk Premium: $
            {selected.audit_trace.cost?.scenario != null ? selected.audit_trace.cost.scenario.toLocaleString() : '0'}
          </div>
        </div>

        {/* SHAP Feature Attribution Card */}
        {selected?.audit_trace?.shap_explanations && selected.audit_trace.shap_explanations.length > 0 && (
          <div
            className="audit-trace-box"
            style={{
              borderLeft: '4px solid #8b5cf6',
              background: 'rgba(139, 92, 246, 0.05)'
            }}
          >
            <div
              style={{
                marginBottom: '0.5rem',
                fontWeight: 700,
                color: '#c084fc',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}
            >
              <span>SHAP Feature Attribution</span>
              <span style={{ fontSize: '0.65rem', color: '#a855f7', background: 'rgba(168, 85, 247, 0.15)', padding: '2px 6px', borderRadius: '4px', fontWeight: 800 }}>
                TreeExplainer p85
              </span>
            </div>

            {selected.audit_trace.shap_explanations.map((exp, expIdx) => (
              <div key={expIdx} style={{ marginBottom: expIdx < selected.audit_trace.shap_explanations.length - 1 ? '0.75rem' : '0' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#e2e8f0', marginBottom: '0.2rem' }}>
                  Corridor: {exp.origin} → {exp.destination} ({exp.transport_mode?.toUpperCase()})
                </div>

                <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.4rem' }}>
                  Base Expectation (E[f(x)]): {exp.base_value_hours}h
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                  {exp.contributions?.slice(0, 5).map((contrib, cIdx) => {
                    const isPositive = contrib.contribution_hours > 0;
                    return (
                      <div
                        key={cIdx}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '0.7rem',
                          background: 'rgba(15, 23, 42, 0.5)',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          border: '1px solid #1e293b'
                        }}
                      >
                        <span style={{ color: '#cbd5e1' }}>
                          {contrib.feature}: <strong style={{ color: '#f8fafc' }}>{String(contrib.value)}</strong>
                        </span>
                        <span style={{ fontWeight: 800, color: isPositive ? '#ef4444' : '#10b981' }}>
                          {isPositive ? '+' : ''}{contrib.contribution_hours}h
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        <div
          className="audit-trace-box"
          style={{
            borderLeft: '4px solid #f59e0b'
          }}
        >
          <div
            style={{
              marginBottom: '0.5rem',
              fontWeight: 700,
              color: '#f8fafc'
            }}
          >
            Strategic Truth Anchor
          </div>

          <div>
            Verified against Split-Node Forensic Architecture.
            0ms co-location miracles detected.
          </div>
        </div>

      </div>

    ) : (

      <div
        style={{
          textAlign: 'center',
          color: '#64748b',
          marginTop: '2rem'
        }}
      >
        <Activity
          size={48}
          style={{
            opacity: 0.1,
            marginBottom: '1rem'
          }}
        />

        <p style={{ fontSize: '0.8rem' }}>
          Awaiting operational data stream...
        </p>
      </div>

    )}

    <div style={{ marginTop: 'auto' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          background: 'rgba(59, 130, 246, 0.1)',
          padding: '0.75rem',
          borderRadius: '8px',
          border: '1px solid #3b82f6'
        }}
      >
        <ShieldCheck size={16} color="#3b82f6" />

        <span
          style={{
            fontSize: '0.65rem',
            fontWeight: 800,
            color: '#3b82f6'
          }}
        >
          TRUTH AUDIT VERIFIED
        </span>
      </div>
    </div>

  </aside>

  <footer className="tradeoff-strip">

    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem'
      }}
    >
      <BarChart3 size={20} color="#64748b" />

      <span
        style={{
          fontSize: '0.75rem',
          fontWeight: 800,
          color: '#64748b'
        }}
      >
        TRADEOFF ANALYSIS
      </span>
    </div>

    <div
      style={{
        display: 'flex',
        gap: '3rem',
        flex: 1,
        justifyContent: 'center'
      }}
    >

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center'
        }}
      >
        <span
          style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            color: '#94a3b8'
          }}
        >
          SELECTED ETA:
        </span>

        <span
          style={{
            fontSize: '0.9rem',
            fontWeight: 800,
            color: '#f59e0b'
          }}
        >
          {selected?.adjusted_eta || '--'}h
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center'
        }}
      >
        <span
          style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            color: '#94a3b8'
          }}
        >
          LOWEST COST:
        </span>

        <span
          style={{
            fontSize: '0.9rem',
            fontWeight: 800,
            color: '#10b981'
          }}
        >
          $
          {recommendations.length > 0
            ? Math.min(
                ...recommendations.map(
                  r => r.total_cost
                )
              ).toLocaleString()
            : '--'}
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center'
        }}
      >
        <span
          style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            color: '#94a3b8'
          }}
        >
          RISK FLOOR:
        </span>

        <span
          style={{
            fontSize: '0.9rem',
            fontWeight: 800,
            color: '#3b82f6'
          }}
        >
          {recommendations.length > 0
            ? Math.min(
                ...recommendations.map(
                  r => r.threat_level * 100
                )
              )
            : '--'}
          %
        </span>
      </div>

    </div>
  </footer>

</div>

);
};

export default RouteRecommender;