const LATENCY_PROBE_INTERVAL_MS = 5000;
const LATENCY_SCAN_INTERVAL_MS = 1000;
const latencyStates = new WeakMap();

function formatLatencyMicros(value) {
  if (value < 1000) {
    return `${value} µs`;
  }
  if (value < 1000000) {
    const millis = value / 1000;
    return `${millis < 10 ? millis.toFixed(1) : Math.round(millis)} ms`;
  }
  return `${(value / 1000000).toFixed(1)} s`;
}

function latencyStateFor(session) {
  let state = latencyStates.get(session);
  if (state) {
    return state;
  }
  const badge = document.createElement('span');
  badge.className = 'terminal-latency-badge';
  badge.hidden = true;
  badge.setAttribute('aria-label', 'Authenticated session latency');
  session.tabWrap.insertBefore(badge, session.tabWrap.lastChild);
  state = { badge, inFlight: false, lastStarted: 0 };
  latencyStates.set(session, state);
  return state;
}

async function probeSessionLatency(session, state) {
  const connectionID = session.connectionID;
  const generation = session.generation;
  if (!connectionID || state.inFlight) {
    return;
  }

  state.inFlight = true;
  state.lastStarted = Date.now();
  try {
    const result = await getInvoke()('connection_latency', { connectionId: connectionID });
    if (session.connectionID !== connectionID || session.generation !== generation) {
      return;
    }
    const rttMicros = Number(result?.rtt_micros);
    if (!Number.isSafeInteger(rttMicros) || rttMicros < 1) {
      throw new Error('invalid latency result');
    }
    state.badge.textContent = `${formatLatencyMicros(rttMicros)} RTT`;
    state.badge.title = 'Round-trip time measured by Local Core over this authenticated secure session.';
    state.badge.hidden = false;
  } catch (_) {
    if (session.connectionID === connectionID && session.generation === generation) {
      state.badge.textContent = 'RTT unavailable';
      state.badge.title = 'Local Core could not measure this authenticated session.';
      state.badge.hidden = false;
    }
  } finally {
    state.inFlight = false;
  }
}

function scanConnectedSessionLatency() {
  const now = Date.now();
  for (const session of sessions.values()) {
    const state = latencyStateFor(session);
    if (!session.connectionID) {
      state.badge.hidden = true;
      continue;
    }
    if (!state.inFlight && now - state.lastStarted >= LATENCY_PROBE_INTERVAL_MS) {
      void probeSessionLatency(session, state);
    }
  }
}

setInterval(scanConnectedSessionLatency, LATENCY_SCAN_INTERVAL_MS);
scanConnectedSessionLatency();
