import React, { useState, useEffect } from 'react';
import BenchmarkCharts from './BenchmarkCharts.jsx';
import RouteRecommender from './RouteRecommender.jsx';
import SupplierIntelligence from './SupplierIntelligence.jsx';
import NetworkMap from './NetworkMap.jsx';

export default function App() {
  const [network, setNetwork] = useState({ nodes: [], edges: [] });
  const [hubs, setHubs] = useState([]);
  const [routeForMap, setRouteForMap] = useState(null);
  const [routeHistory, setRouteHistory] = useState([]);
  const [selectedHistory, setSelectedHistory] = useState(null);
  const [status, setStatus] = useState(null);
  const [currentView, setCurrentView] = useState('recommend');
  
  
  useEffect(() => {
    fetch('/api/hubs')
      .then(r => r.json())
      .then(data => setHubs(data))
      .catch(e => console.error(e));
    fetch('/api/network')
      .then(r => r.json())
      .then(data => setNetwork(data))
      .catch(e => console.error(e));
      try {
      const savedHistory = localStorage.getItem('routeHistory');
      if (savedHistory) {
        const parsed = JSON.parse(savedHistory);
        if (Array.isArray(parsed)) setRouteHistory(parsed);
      }
    } catch (e) {
      // Corrupted saved history must never crash the app: start fresh instead.
      localStorage.removeItem('routeHistory');
    }

      
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (event) => {
      const state = JSON.parse(event.data);
      setStatus(state);
    };
    
    return () => ws.close();
  }, []);
  const exportRouteCSV = (route) => {
  if (!route) {
    return;
  }

  const rows = [];

  // Route summary
  rows.push([
    'Strategy',
    'ETA (hours)',
    'Total Cost',
    'Threat Level',
    'Explanation'
  ]);

  rows.push([
    route.persona || '',
    route.adjusted_eta || '',
    route.total_cost || '',
    route.threat_level != null
      ? `${route.threat_level * 100}%`
      : '',
    route.explanation || ''
  ]);

  // Empty row
  rows.push([]);

  // Leg details
  rows.push([
    'Leg',
    'Type',
    'Mode',
    'Destination',
    'ETA (hours)',
    'Threat',
    'Intel Source',
    'Reason'
  ]);

  route.legs?.forEach((leg, index) => {
    rows.push([
      index + 1,
      leg.type || '',
      leg.mode || '',
      leg.to_name || '',
      leg.eta || '',
      leg.threat != null
        ? `${leg.threat * 100}%`
        : '',
      leg.intel_source || '',
      leg.reason || ''
    ]);
  });

  // Audit trace
  if (route.audit_trace) {
    rows.push([]);

    rows.push([
      'Audit Trace',
      'Value'
    ]);

    rows.push([
      'Transit ETA',
      route.audit_trace.eta?.transit ?? ''
    ]);

    rows.push([
      'Transfer ETA',
      route.audit_trace.eta?.transfer ?? ''
    ]);

    rows.push([
      'Scenario ETA',
      route.audit_trace.eta?.scenario ?? ''
    ]);

    rows.push([
      'Transit Cost',
      route.audit_trace.cost?.transit ?? ''
    ]);

    rows.push([
      'Transfer Cost',
      route.audit_trace.cost?.transfer ?? ''
    ]);

    rows.push([
      'Scenario Cost',
      route.audit_trace.cost?.scenario ?? ''
    ]);
  }

  const csv = rows
    .map(row =>
      row.map(value => {
        const text = String(value ?? '');
        return `"${text.replace(/"/g, '""')}"`;
      }).join(',')
    )
    .join('\n');

  const blob = new Blob(
    [csv],
    { type: 'text/csv;charset=utf-8;' }
  );

  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = `route-audit-${Date.now()}.csv`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
};
  const handleRouteGenerated = (route,meta) => {
  setRouteForMap(route);

  if (!route) {
    return;
  }

  const historyItem = {
    id: Date.now(),
    timestamp: new Date().toLocaleString(),
    route: route,
    meta: meta || null
  };

  const updatedHistory = [
    historyItem,
    ...routeHistory
  ].slice(0, 10);

  setRouteHistory(updatedHistory);

  localStorage.setItem(
    'routeHistory',
    JSON.stringify(updatedHistory)
  );
};
  if (currentView === 'recommend') {
                  return <RouteRecommender
                    onNavigate={setCurrentView}
                    onRouteGenerated={handleRouteGenerated}
                    onRouteSelected={setRouteForMap}
                  />;
  }

  if (currentView === 'suppliers') {
    return <SupplierIntelligence onNavigate={setCurrentView} />;
  }

  if (currentView === 'benchmark') {
    return <BenchmarkCharts onBack={() => setCurrentView('recommend')} />;
  }
  if (currentView === 'network') {
  return (
    <div className="dashboard-container">

      {/* LEFT PANEL */}
      <div className="panel">
        <h2 className="panel-title">System Console</h2>

        <div className="metrics-grid">
          <div className="metric-card">
            <div style={{
              fontSize: '0.875rem',
              color: 'var(--text-muted)'
            }}>
              Active Hubs
            </div>

            <div className="metric-value">
              {network?.nodes?.length || 0}
            </div>
          </div>

          <div className="metric-card">
            <div style={{
              fontSize: '0.875rem',
              color: 'var(--text-muted)'
            }}>
              Transit Corridors
            </div>

            <div className="metric-value">
              {network?.edges?.length || 0}
            </div>
          </div>

          <div className="metric-card">
            <div style={{
              fontSize: '0.875rem',
              color: 'var(--text-muted)'
            }}>
              ML Brain
            </div>

            <div
              className="metric-value"
              style={{
                fontSize: '1rem',
                color: 'var(--supply-accent)'
              }}
            >
              p85 Real-Data (Active)
            </div>
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
            marginTop: 'auto'
          }}
        >
          <button
            className="dispatch-btn"
            onClick={() => setCurrentView('recommend')}
          >
            Return to Optimization Dashboard
          </button>

          <button
            className="benchmark-btn"
            onClick={() => setCurrentView('benchmark')}
          >
            View Scientific Benchmarks
          </button>

          <button
            className="dispatch-btn"
            style={{ backgroundColor: '#8b5cf6' }}
            onClick={() => setCurrentView('suppliers')}
          >
            Execute Supplier Intelligence Audit
          </button>
        </div>
      </div>


      {/* CENTER PANEL */}
      <div
        className="panel"
        style={{
          padding: 0,
          overflow: 'hidden'
        }}
      >

        {/* MAP */}
        <div
          className="map-container"
          style={{
            position: 'relative'
          }}
        >
          <NetworkMap
            hubs={hubs}
            route={routeForMap}
          />
        </div>


        {/* ROUTE HISTORY */}
        <div
          style={{
            padding: '1rem',
            borderTop: '1px solid var(--border-color)'
          }}
        >

          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '1rem'
            }}
          >
            <h2 className="panel-title" style={{ margin: 0 }}>
              Route History
            </h2>

            {routeHistory.length > 0 && (
              <button
                className="benchmark-btn"
                onClick={() => {
                  setRouteHistory([]);
                  setSelectedHistory(null);
                  localStorage.removeItem('routeHistory');
                }}
              >
                Clear History
              </button>
            )}
          </div>


          {routeHistory.length === 0 ? (

            <div
              style={{
                padding: '1rem',
                textAlign: 'center',
                color: 'var(--text-muted)'
              }}
            >
              No routes generated yet.
            </div>

          ) : (

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem'
              }}
            >

              {routeHistory.map((item, index) => {

                const route = item.route;

                return (
                  <div
                    key={item.id}
                    onClick={() => {
                      setSelectedHistory(item.id);
                      setRouteForMap(route);
                    }}
                    style={{
                      padding: '0.8rem',
                      border: '1px solid',
                      borderColor:
                        selectedHistory === item.id
                          ? 'var(--supply-accent)'
                          : 'var(--border-color)',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      background:
                        selectedHistory === item.id
                          ? 'rgba(255,255,255,0.03)'
                          : 'transparent'
                    }}
                  >

                    <div
  style={{
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  }}
>
  <strong>
    Route {routeHistory.length - index}{item.meta?.origin ? ` · ${item.meta.origin} → ${item.meta.destination}` : ''}
  </strong>

  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem'
    }}
  >
    <span
      style={{
        fontSize: '0.75rem',
        color: 'var(--text-muted)'
      }}
    >
      {item.timestamp}
    </span>

    <button
      className="benchmark-btn"
      onClick={(e) => {
        e.stopPropagation();
        exportRouteCSV(route);
      }}
    >
      Export CSV
    </button>
  </div>
</div>


                    <div
                      style={{
                        display: 'flex',
                        gap: '1.5rem',
                        marginTop: '0.5rem',
                        fontSize: '0.8rem'
                      }}
                    >

                      <span>
                        Strategy: {route?.persona || 'N/A'}{item.meta?.scenario ? ` (scenario: ${item.meta.scenario})` : ''}
                      </span>

                      <span>
                        ETA: {route?.adjusted_eta ?? 'N/A'}
                      </span>

                      <span>
                        Cost: {route?.total_cost != null
                          ? `$${route.total_cost.toLocaleString()}`
                          : 'N/A'}
                      </span>

                    </div>

                  </div>
                );
              })}

            </div>
          )}

        </div>
      </div>


      {/* RIGHT PANEL */}
      <div className="panel">
        <h2 className="panel-title">
          Inference Status
        </h2>

        <div className="log-feed">

          <div
            className="decision-card"
            style={{
              borderColor: 'var(--supply-accent)'
            }}
          >
            <div className="decision-header">
              <span>
                PROVENANCE: UNCTAD/STB
              </span>
            </div>

            <div className="decision-body">
              Real-world historical metrics loaded for all nodes.
              No synthetic fallback active.
            </div>
          </div>


          <div className="decision-card">
            <div className="decision-header">
              <span>
                LATENCY: SUB-SECOND
              </span>
            </div>

            <div className="decision-body">
              Live geocoding and news-anchored semantic scoring active.
            </div>
          </div>

        </div>
      </div>

    </div>
  );
}
}

