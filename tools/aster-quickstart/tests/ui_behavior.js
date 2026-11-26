"use strict";

const fs = require("fs");
const vm = require("vm");

const appSource = fs.readFileSync(process.argv[2], "utf8");
const eventId = "a".repeat(64);

function element(id) {
  const classes = new Set();
  const attributes = new Map();
  return {
    id,
    hidden: id.endsWith("-fallback") || id === "offline-panel" || id === "delivery-result",
    disabled: false,
    textContent: "",
    value: id === "detail-level" ? "guided" : id === "event-text" ? "Hello from publisher" : "",
    listeners: {},
    classList: {
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    focus() {},
    setAttribute(name, value) { attributes.set(name, String(value)); },
    removeAttribute(name) { attributes.delete(name); },
    getAttribute(name) { return attributes.has(name) ? attributes.get(name) : null; },
  };
}

function commit(text) {
  return {event_id: eventId, text, status: "committed", durable: true, node: "atlas"};
}

function receipt(text) {
  return {event_id: eventId, text, status: "received", observed: true, node: "beacon"};
}

function baseState(actions = ["start_publisher", "start_receiver", "cleanup"]) {
  return {
    revision: 1,
    initialized: true,
    cleanup: null,
    operation: null,
    nodes: {
      publisher: {state: "stopped", identity_fingerprint: "1".repeat(64)},
      receiver: {state: "stopped", identity_fingerprint: "2".repeat(64)},
    },
    authentication: {state: "unauthenticated"},
    failed_stage: null,
    available_actions: actions,
    message: null,
    commit: null,
    receipt: null,
    first_delivery: null,
    experiment: null,
    error: null,
    records: [{
      sequence: 1,
      timestamp: "2026-01-01T00:00:00+00:00",
      action: "ready",
      node: "publisher",
      outcome: "running",
      message: "running",
      explanation: "The node is ready for the next action.",
      debug: {state: "running"},
      rendered: {
        compact: "[ready] publisher running: running",
        guided: "[ready] publisher running: running\n  The node is ready for the next action.",
        debug: "[ready] publisher running: running\n  The node is ready for the next action.\n  debug: state=running",
      },
    }],
  };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

async function run(mode) {
  const ids = [
    "status", "session-signal", "workspace-step", "publisher-step", "receiver-step", "auth-step", "event-step",
    "workspace-progress-state", "publisher-progress-state", "receiver-progress-state",
    "auth-progress-state", "event-progress-state",
    "publisher-state", "publisher-fingerprint", "publisher-start", "publisher-stop",
    "publisher-terminal", "publisher-output", "publisher-fallback", "publisher-attach-command",
    "publisher-copy-command", "publisher-copy-feedback",
    "receiver-state", "receiver-fingerprint", "receiver-start", "receiver-stop",
    "receiver-terminal", "receiver-output", "receiver-fallback", "receiver-attach-command",
    "receiver-copy-command", "receiver-copy-feedback",
    "authenticate", "auth-state", "event-form", "event-text", "send-event", "validation-message",
    "delivery-result", "commit-result", "receipt-result", "detail-level", "offline-panel",
    "offline-experiment", "technical-evidence", "evidence", "cleanup",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, element(id)]));
  let state = baseState();
  let stateListener = null;
  let postSeen = false;
  let postPath = null;
  let confirmCalls = 0;
  let getCount = 0;
  let copiedText = null;
  let receiptAfterLaggingSse = null;
  let selectedText = null;
  let cleanupResolve = null;
  const frameSnapshots = [];

  class EventSourceStub {
    addEventListener(name, callback) { if (name === "state") stateListener = callback; }
  }

  async function fetchStub(url, options) {
    if (!options || options.method !== "POST") {
      getCount += 1;
      return {ok: true, async json() { return state; }};
    }
    postSeen = true;
    postPath = url;
    if (url.startsWith("/api/nodes/publisher/start")) {
      const responseState = baseState(["stop_publisher", "start_receiver", "cleanup"]);
      responseState.revision = 2;
      responseState.nodes.publisher.state = "running";
      if (mode === "stale-post") {
        state = baseState(["stop_publisher", "stop_receiver", "authenticate", "cleanup"]);
        state.revision = 3;
        state.nodes.publisher.state = "running";
        state.nodes.receiver.state = "running";
        stateListener({data: JSON.stringify(state)});
      } else {
        state = responseState;
      }
      return {ok: true, async json() { return responseState; }};
    }
    if (url.startsWith("/api/terminal/publisher")) {
      return {ok: true, async json() {
        return {state, terminal: {opened: false, attach_command: "/usr/bin/python3 -m aster_quickstart.attach --role publisher"}};
      }};
    }
    if (url.startsWith("/api/cleanup")) {
      if (mode === "cleanup-pending") {
        await new Promise((resolve) => { cleanupResolve = resolve; });
      }
      state = {...state, initialized: false, cleanup: "cleaned", available_actions: []};
      return {ok: true, async json() { return state; }};
    }
    if (url.startsWith("/api/events") && ["fast-post", "fast-post-sse"].includes(mode)) {
      state = baseState(["publish_event", "offline_experiment", "stop_publisher", "stop_receiver", "cleanup"]);
      state.revision = 3;
      state.nodes.publisher.state = "running";
      state.nodes.receiver.state = "running";
      state.authentication = {state: "authenticated", verification: "verified"};
      state.commit = commit("Hello from publisher");
      state.receipt = receipt("Hello from publisher");
      state.first_delivery = {message: "Hello from publisher", commit: state.commit, receipt: state.receipt};
      if (mode === "fast-post-sse") {
        setTimeout(() => {
          stateListener({data: JSON.stringify(state)});
          receiptAfterLaggingSse = elements["receipt-result"].textContent;
        }, 10);
      }
      return {ok: true, async json() { return state; }};
    }
    return {ok: true, async json() { return state; }};
  }

  const context = {
    console,
    encodeURIComponent,
    EventSource: EventSourceStub,
    fetch: fetchStub,
    TextEncoder,
    navigator: {
      clipboard: mode === "terminal-no-clipboard" ? undefined : {
        async writeText(value) { copiedText = value; },
      },
    },
    URLSearchParams,
    window: {
      location: {search: "?token=test-token"},
      confirm() { confirmCalls += 1; return mode !== "cleanup-cancel"; },
    },
    requestAnimationFrame(callback) {
      frameSnapshots.push({
        commit: elements["commit-result"].textContent,
        receipt: elements["receipt-result"].textContent,
      });
      setImmediate(() => callback(Date.now()));
    },
    setTimeout,
    document: {
      getElementById(id) { return elements[id]; },
      createRange() {
        return {
          text: "",
          selectNodeContents(node) { this.text = node.textContent; },
        };
      },
    },
  };
  context.window.getSelection = () => ({
    removeAllRanges() { selectedText = null; },
    addRange(range) { selectedText = range.text; },
  });
  vm.runInNewContext(appSource, context, {filename: process.argv[2]});
  await settle();
  getCount = 0;

  if (mode === "lifecycle") {
    const initialDisabled = {
      publisherStart: elements["publisher-start"].disabled,
      publisherStop: elements["publisher-stop"].disabled,
      receiverStart: elements["receiver-start"].disabled,
      authenticate: elements.authenticate.disabled,
      send: elements["send-event"].disabled,
    };
    await elements["publisher-start"].listeners.click({preventDefault() {}});
    await settle();
    return {
      initialDisabled,
      postPath,
      afterPublisher: {
        publisherState: elements["publisher-state"].textContent,
        receiverStartDisabled: elements["receiver-start"].disabled,
      },
    };
  }

  if (mode === "stale-post") {
    await elements["publisher-start"].listeners.click({preventDefault() {}});
    await settle();
    return {
      publisherState: elements["publisher-state"].textContent,
      receiverState: elements["receiver-state"].textContent,
      authState: elements["auth-state"].textContent,
      status: elements.status.textContent,
    };
  }

  if (mode === "resync-required") {
    state = baseState(["stop_publisher", "start_receiver", "cleanup"]);
    state.revision = 2;
    state.nodes.publisher.state = "running";
    stateListener({data: JSON.stringify({
      revision: 99,
      stream: {mode: "resync_required", reason: "payload_budget"},
    })});
    await settle();
    return {
      fetches: getCount,
      publisherState: elements["publisher-state"].textContent,
    };
  }

  if (mode === "consecutive-resync-required") {
    state = baseState(["stop_publisher", "start_receiver", "cleanup"]);
    state.revision = 2;
    state.nodes.publisher.state = "running";
    for (const revision of [99, 100]) {
      stateListener({data: JSON.stringify({
        revision,
        stream: {mode: "resync_required", reason: "payload_budget"},
      })});
    }
    await settle();
    return {
      fetches: getCount,
      publisherState: elements["publisher-state"].textContent,
    };
  }

  if (mode === "progress") {
    state = baseState([]);
    state.operation = "publishing";
    state.nodes.publisher.state = "running";
    state.nodes.receiver.state = "running";
    state.authentication = {state: "authenticated", verification: "verified"};
    state.message = "Hello";
    state.commit = commit("Hello");
    stateListener({data: JSON.stringify(state)});
    await settle();
    const before = {
      commit: elements["commit-result"].textContent,
      receipt: elements["receipt-result"].textContent,
      offline: elements["offline-experiment"].disabled,
    };
    state = {...state, revision: 3, operation: null, receipt: receipt("Hello"), first_delivery: {
      message: "Hello", commit: commit("Hello"), receipt: receipt("Hello"),
    }, available_actions: ["publish_event", "offline_experiment", "stop_publisher", "stop_receiver", "cleanup"]};
    stateListener({data: JSON.stringify(state)});
    await settle();
    return {
      commit: before.commit,
      receiptBefore: before.receipt,
      offlineBefore: before.offline,
      receiptAfter: elements["receipt-result"].textContent,
      offlineAfter: elements["offline-experiment"].disabled,
    };
  }

  if (["fast-post", "fast-post-sse"].includes(mode)) {
    state = baseState(["publish_event", "stop_publisher", "stop_receiver", "cleanup"]);
    state.nodes.publisher.state = "running";
    state.nodes.receiver.state = "running";
    state.authentication = {state: "authenticated", verification: "verified"};
    stateListener({data: JSON.stringify(state)});
    await settle();
    await elements["event-form"].listeners.submit({preventDefault() {}});
    await settle();
    return {
      frameSnapshots,
      receiptAfterLaggingSse,
      finalCommit: elements["commit-result"].textContent,
      finalReceipt: elements["receipt-result"].textContent,
    };
  }

  if (mode === "detail") {
    elements["detail-level"].value = "compact";
    elements["detail-level"].listeners.change();
    const compact = elements["publisher-output"].textContent;
    elements["detail-level"].value = "guided";
    elements["detail-level"].listeners.change();
    const guided = elements["publisher-output"].textContent;
    elements["detail-level"].value = "debug";
    elements["detail-level"].listeners.change();
    return {compact, guided, debug: elements["publisher-output"].textContent, fetchesAfterDetailChanges: getCount};
  }

  if (mode === "terminal" || mode === "terminal-no-clipboard") {
    await elements["publisher-terminal"].listeners.click({preventDefault() {}});
    await settle();
    await elements["publisher-copy-command"].listeners.click({preventDefault() {}});
    await settle();
    return {
      fallback: elements["publisher-attach-command"].textContent,
      fallbackHidden: elements["publisher-fallback"].hidden,
      copiedText,
      copyLabel: elements["publisher-copy-command"].textContent,
      copyFeedback: elements["publisher-copy-feedback"].textContent,
      selectedText,
      postPath,
    };
  }

  if (mode === "progress-accessibility") {
    const initial = {
      workspace: elements["workspace-progress-state"].textContent,
      publisher: elements["publisher-progress-state"].textContent,
      publisherCurrent: elements["publisher-step"].getAttribute("aria-current"),
    };
    state = baseState([]);
    state.revision = 2;
    state.operation = "authenticating";
    state.nodes.publisher.state = "running";
    state.nodes.receiver.state = "running";
    state.authentication = {state: "authenticating"};
    state.pair_transition = {state: "restarting_for_authentication"};
    stateListener({data: JSON.stringify(state)});
    await settle();
    const authenticating = {
      publisherPill: elements["publisher-state"].textContent,
      receiverPill: elements["receiver-state"].textContent,
      authText: elements["auth-progress-state"].textContent,
    };
    state = {...state, revision: 3, operation: null, pair_transition: null,
      authentication: {state: "authenticated", verification: "verified"},
      commit: commit("Hello"), receipt: receipt("Hello"),
      first_delivery: {message: "Hello", commit: commit("Hello"), receipt: receipt("Hello")},
      available_actions: ["publish_event", "offline_experiment", "stop_publisher", "stop_receiver", "cleanup"]};
    stateListener({data: JSON.stringify(state)});
    await settle();
    return {initial, authenticating, complete: {
      eventText: elements["event-progress-state"].textContent,
      eventCurrent: elements["event-step"].getAttribute("aria-current"),
    }};
  }

  if (mode === "cleanup-observer-controls") {
    state = baseState([]);
    state.revision = 2;
    state.operation = "cleaning";
    stateListener({data: JSON.stringify(state)});
    await settle();
    const cleaning = {
      terminal: elements["publisher-terminal"].disabled,
      copy: elements["publisher-copy-command"].disabled,
    };
    state = {...state, revision: 3, operation: null, cleanup: "failed",
      failed_stage: "cleanup", available_actions: ["cleanup"],
      error: {code: "cleanup_failed", message: "The quickstart cleanup failed."}};
    stateListener({data: JSON.stringify(state)});
    await settle();
    return {cleaning, failed: {
      terminal: elements["publisher-terminal"].disabled,
      copy: elements["publisher-copy-command"].disabled,
      cleanup: elements.cleanup.disabled,
    }};
  }

  if (mode === "cleanup-pending") {
    const pending = elements.cleanup.listeners.click({preventDefault() {}});
    await settle();
    const disabled = {
      terminal: elements["publisher-terminal"].disabled,
      copy: elements["publisher-copy-command"].disabled,
    };
    cleanupResolve();
    await pending;
    return disabled;
  }

  if (mode === "signal-states") {
    const ready = {
      good: elements["session-signal"].classList.contains("is-ready"),
      failed: elements["session-signal"].classList.contains("is-failed"),
    };
    state = baseState(["cleanup"]);
    state.revision = 2;
    state.failed_stage = "publisher";
    state.error = {code: "operation_failed", message: "The quickstart operation failed."};
    state.nodes.publisher.state = "failed";
    stateListener({data: JSON.stringify(state)});
    await settle();
    const failed = {
      good: elements["session-signal"].classList.contains("is-ready"),
      failed: elements["session-signal"].classList.contains("is-failed"),
    };
    state = {...state, revision: 3, initialized: false, cleanup: "cleaned",
      failed_stage: null, error: null, available_actions: []};
    stateListener({data: JSON.stringify(state)});
    await settle();
    return {ready, failed, cleaned: {
      inactive: elements["session-signal"].classList.contains("is-inactive"),
      good: elements["session-signal"].classList.contains("is-ready"),
    }};
  }

  if (mode === "publisher-failure" || mode === "authentication-failure") {
    state = baseState(["start_publisher", "start_receiver", "cleanup"]);
    state.revision = 2;
    state.error = {code: "operation_failed", message: "The quickstart operation failed."};
    if (mode === "publisher-failure") {
      state.failed_stage = "publisher";
      state.nodes.publisher.state = "failed";
    } else {
      state.failed_stage = "authentication";
      state.nodes.publisher.state = "failed";
      state.nodes.receiver.state = "failed";
    }
    stateListener({data: JSON.stringify(state)});
    await settle();
    const progress = {
      workspace: elements["workspace-progress-state"].textContent,
      publisher: elements["publisher-progress-state"].textContent,
      receiver: elements["receiver-progress-state"].textContent,
      authentication: elements["auth-progress-state"].textContent,
      event: elements["event-progress-state"].textContent,
    };
    const currentStages = ["workspace", "publisher", "receiver", "auth", "event"]
      .filter((name) => elements[name + "-step"].getAttribute("aria-current") === "step");
    return {
      progress,
      currentStages,
      publisherPill: elements["publisher-state"].textContent,
      nodePills: {
        publisher: elements["publisher-state"].textContent,
        receiver: elements["receiver-state"].textContent,
      },
    };
  }

  if (mode === "cleanup-cancel" || mode === "cleanup-accept") {
    await elements.cleanup.listeners.click({preventDefault() {}});
    await settle();
    return {confirmCalls, postSeen, postPath, status: elements.status.textContent};
  }

  throw new Error("unknown mode");
}

(async () => {
  process.stdout.write(JSON.stringify(await run(process.argv[3])));
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
