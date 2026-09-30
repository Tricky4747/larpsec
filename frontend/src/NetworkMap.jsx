import { useMemo, useEffect } from 'react';
import {
  MapContainer,
  TileLayer,
  Polyline,
  CircleMarker,
  Tooltip,
  useMap
} from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

const MODE_COLORS = {
  sea: '#3b82f6',
  air: '#f59e0b',
  rail: '#a855f7',
  road: '#10b981',
};

const ALERT_COLOR = '#ef4444';

function FitToRoute({ points }) {
  const map = useMap();

  useEffect(() => {
    if (points.length > 0) {
      map.fitBounds(points, {
        padding: [40, 40],
        maxZoom: 6
      });
    }
  }, [points, map]);

  return null;
}

export default function NetworkMap({ hubs = [], route = null }) {
  const hubById = useMemo(() => {
    const table = {};

    hubs.forEach((hub) => {
      table[hub.id] = hub;
    });

    return table;
  }, [hubs]);

  const { segments, stops, points } = useMemo(() => {
    const segments = [];
    const stopMap = {};

    (route?.legs || []).forEach((leg) => {
      if (leg.type === 'transfer') {
        return;
      }

      const fromHub = hubById[leg.from];
      const toHub = hubById[leg.to];

      if (!fromHub || !toHub) {
        return;
      }

      const from = [fromHub.lat, fromHub.lon];
      const to = [toHub.lat, toHub.lon];

      const mode = leg.mode.toLowerCase();
      const alert = leg.intel_source === 'SCENARIO';

      segments.push({
        from,
        to,
        mode,
        alert,
        label: `${fromHub.display_name} → ${toHub.display_name}`,
        detail: `${leg.mode} • ${leg.eta}h • threat ${Math.round(leg.threat * 100)}%`,
        reason: leg.reason
      });

      stopMap[fromHub.id] = {
        hub: fromHub,
        alert: stopMap[fromHub.id]?.alert || false
      };

      stopMap[toHub.id] = {
        hub: toHub,
        alert: alert || stopMap[toHub.id]?.alert || false
      };
    });

    const points = segments.flatMap((segment) => [
      segment.from,
      segment.to
    ]);

    return {
      segments,
      stops: Object.values(stopMap),
      points
    };
  }, [route, hubById]);

  return (
    <div
      style={{
        height: 340,
        borderRadius: 8,
        overflow: 'hidden',
        border: '1px solid #1e293b'
      }}
    >
      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={2}
        style={{
          height: '100%',
          width: '100%',
          background: '#020617'
        }}
        worldCopyJump
      >
        <TileLayer
          url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution="&copy; OpenStreetMap contributors"
        />

        <FitToRoute points={points} />
        {hubs.map((hub) => (
  <CircleMarker
    key={`hub-${hub.id}`}
    center={[hub.lat, hub.lon]}
    radius={3}
    pathOptions={{
      color: '#64748b',
      fillColor: '#94a3b8',
      fillOpacity: 0.7,
      weight: 1
    }}
  >
    <Tooltip>{hub.display_name}</Tooltip>
  </CircleMarker>
))}
        {segments.map((segment, index) => (
          <Polyline
            key={index}
            positions={[segment.from, segment.to]}
            pathOptions={{
              color: segment.alert
                ? ALERT_COLOR
                : (MODE_COLORS[segment.mode] || '#94a3b8'),
              weight: segment.alert ? 5 : 3,
              dashArray:
                segment.mode === 'air' ? '8 8' : undefined
            }}
          >
            <Tooltip sticky>
              <strong>{segment.label}</strong>
              <br />
              {segment.detail}

              {segment.alert && segment.reason && (
                <>
                  <br />
                  {segment.reason}
                </>
              )}
            </Tooltip>
          </Polyline>
        ))}

        {stops.map(({ hub, alert }) => (
          <CircleMarker
            key={hub.id}
            center={[hub.lat, hub.lon]}
            radius={alert ? 8 : 6}
            pathOptions={{
              color: alert ? ALERT_COLOR : '#e2e8f0',
              fillColor: alert ? ALERT_COLOR : '#0f172a',
              fillOpacity: 1,
              weight: 2
            }}
          >
            <Tooltip>
              {hub.display_name}
              {alert ? ' (disrupted)' : ''}
            </Tooltip>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}