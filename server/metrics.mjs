/**
 * Process metrics, in Prometheus text format.
 *
 * WHY THIS EXISTS
 *
 * Logs tell you what happened to one request. They are a poor way to answer
 * "is the gateway healthy right now": counting lines to find the error rate
 * only works if you are already shipping them somewhere that can count, and it
 * cannot tell you about the things that never produce a line at all — how full
 * the upload slots are, how many documents are sitting unanchored.
 *
 * The numbers here are the ones that would have made the failures this service
 * has already been fixed for visible before a user reported them: uploads shed
 * because the in-flight cap was reached, upstream retries, and the pending
 * queue growing because nothing is anchoring it.
 *
 * Counters only ever increase and gauges are read at scrape time, which is what
 * lets a scrape be stateless — no reset, no windowing, no coordination between
 * replicas.
 */

/** Escape a label value per the Prometheus exposition format. */
function escapeLabel(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

function renderLabels(labels) {
  const entries = Object.entries(labels).filter(([, value]) => value !== undefined);
  if (entries.length === 0) return "";
  return `{${entries.map(([key, value]) => `${key}="${escapeLabel(value)}"`).join(",")}}`;
}

export function createMetrics({ now = () => Date.now() } = {}) {
  const startedAt = now();

  /** name -> Map<serialisedLabels, count> */
  const counters = new Map();
  const gauges = new Map();

  function bump(name, labels, by) {
    let series = counters.get(name);
    if (!series) counters.set(name, (series = new Map()));
    const key = renderLabels(labels);
    series.set(key, (series.get(key) || 0) + by);
  }

  return {
    /** Count an event. Labels must be low-cardinality: never a cid or a hash. */
    increment(name, labels = {}, by = 1) {
      bump(name, labels, by);
    },

    /** Register a value read at scrape time, so it is never stale. */
    gauge(name, read, help = "") {
      gauges.set(name, { read, help });
    },

    /**
     * Render the current values.
     *
     * HELP and TYPE lines are emitted because without them a scraper shows the
     * series as untyped and rate() on a counter silently does the wrong thing.
     */
    render(help = {}) {
      const lines = [];

      for (const [name, series] of counters) {
        if (help[name]) lines.push(`# HELP ${name} ${help[name]}`);
        lines.push(`# TYPE ${name} counter`);
        for (const [labels, value] of series) lines.push(`${name}${labels} ${value}`);
      }

      for (const [name, { read, help: gaugeHelp }] of gauges) {
        let value;
        try {
          value = read();
        } catch {
          // A broken gauge must not break the whole scrape, or one bad number
          // takes away every other number at the moment you need them.
          continue;
        }
        if (typeof value !== "number" || !Number.isFinite(value)) continue;
        if (gaugeHelp) lines.push(`# HELP ${name} ${gaugeHelp}`);
        lines.push(`# TYPE ${name} gauge`);
        lines.push(`${name} ${value}`);
      }

      lines.push("# TYPE oreochain_process_uptime_seconds gauge");
      lines.push(`oreochain_process_uptime_seconds ${((now() - startedAt) / 1000).toFixed(3)}`);

      return lines.join("\n") + "\n";
    },

    /** The same numbers as an object, for /health and for tests. */
    snapshot() {
      const out = {};
      for (const [name, series] of counters) {
        out[name] = {};
        for (const [labels, value] of series) out[name][labels || "_"] = value;
      }
      return out;
    },
  };
}

export const _internals = { renderLabels, escapeLabel };
