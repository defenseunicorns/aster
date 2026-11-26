(() => {
  "use strict";

  const token = new URLSearchParams(window.location.search).get("token") || "";
  const commitPresentationMs = 75;
  const byId = (id) => document.getElementById(id);
  const elements = {
    status: byId("status"),
    signal: byId("session-signal"),
    steps: {
      workspace: {item: byId("workspace-step"), state: byId("workspace-progress-state")},
      publisher: {item: byId("publisher-step"), state: byId("publisher-progress-state")},
      receiver: {item: byId("receiver-step"), state: byId("receiver-progress-state")},
      authentication: {item: byId("auth-step"), state: byId("auth-progress-state")},
      event: {item: byId("event-step"), state: byId("event-progress-state")},
    },
    nodes: {
      publisher: {
        state: byId("publisher-state"), fingerprint: byId("publisher-fingerprint"),
        start: byId("publisher-start"), stop: byId("publisher-stop"),
        terminal: byId("publisher-terminal"), output: byId("publisher-output"),
        fallback: byId("publisher-fallback"), attach: byId("publisher-attach-command"),
        copy: byId("publisher-copy-command"), copyFeedback: byId("publisher-copy-feedback"),
      },
      receiver: {
        state: byId("receiver-state"), fingerprint: byId("receiver-fingerprint"),
        start: byId("receiver-start"), stop: byId("receiver-stop"),
        terminal: byId("receiver-terminal"), output: byId("receiver-output"),
        fallback: byId("receiver-fallback"), attach: byId("receiver-attach-command"),
        copy: byId("receiver-copy-command"), copyFeedback: byId("receiver-copy-feedback"),
      },
    },
    authenticate: byId("authenticate"),
    authState: byId("auth-state"),
    form: byId("event-form"),
    text: byId("event-text"),
    send: byId("send-event"),
    validation: byId("validation-message"),
    delivery: byId("delivery-result"),
    commit: byId("commit-result"),
    receipt: byId("receipt-result"),
    detail: byId("detail-level"),
    offlinePanel: byId("offline-panel"),
    offline: byId("offline-experiment"),
    evidence: byId("evidence"),
    cleanup: byId("cleanup"),
    transcript: byId("execution-transcript"),
  };
  let currentState = null;
  let currentRevision = -1;
  let commitPresentationActive = false;
  let deferredReceiptState = null;
  const transcriptRows = new Map();
  const transcriptGroups = new Map();
  const transcriptGroupOrder = [
    ["setup", "Workspace"],
    ["publisher", "Publisher"],
    ["receiver", "Receiver"],
    ["authentication", "Authentication"],
    ["event", "Event"],
    ["experiment", "Optional experiment"],
    ["cleanup", "Cleanup"],
  ];

  function apiPath(path) {
    return path + "?token=" + encodeURIComponent(token);
  }

  function hasAction(state, action) {
    return Array.isArray(state.available_actions) && state.available_actions.includes(action);
  }

  function setProgress(step, status) {
    step.state.textContent = status;
    step.item.classList.toggle("complete", status === "Complete");
    step.item.classList.toggle("current", status === "Current");
    step.item.classList.toggle("failed", status === "Failed");
    if (status === "Current") step.item.setAttribute("aria-current", "step");
    else step.item.removeAttribute("aria-current");
  }

  function renderProgress(state) {
    const order = ["workspace", "publisher", "receiver", "authentication", "event"];
    const cleaned = state.cleanup === "cleaned";
    const publisher = state.nodes.publisher.state;
    const receiver = state.nodes.receiver.state;
    const authenticated = state.authentication && state.authentication.state === "authenticated";
    const statuses = {
      workspace: state.initialized || cleaned ? "Complete" : "Pending",
      publisher: publisher === "running" ? "Complete" : "Pending",
      receiver: receiver === "running" ? "Complete" : "Pending",
      authentication: authenticated ? "Complete" : "Pending",
      event: state.receipt ? "Complete" : "Pending",
    };
    const failedIndex = order.indexOf(state.failed_stage);
    if (failedIndex >= 0) {
      order.forEach((name, index) => {
        statuses[name] = index < failedIndex ? "Complete" : index === failedIndex ? "Failed" : "Pending";
      });
    } else if (!state.failed_stage && !cleaned) {
      if (statuses.workspace === "Pending") statuses.workspace = "Current";
      else if (statuses.publisher === "Pending") statuses.publisher = "Current";
      else if (statuses.receiver === "Pending") statuses.receiver = "Current";
      else if (statuses.authentication === "Pending") statuses.authentication = "Current";
      else if (statuses.event === "Pending") statuses.event = "Current";
    }
    for (const name of Object.keys(statuses)) setProgress(elements.steps[name], statuses[name]);
  }

  function shortFingerprint(value) {
    return typeof value === "string" && value.length >= 16 ? value.slice(0, 8) + "…" + value.slice(-8) : "unavailable";
  }

  function factText(fact, waiting) {
    return fact ? [fact.status, fact.event_id].filter(Boolean).join(" · ") : waiting;
  }

  function renderRecord(record, detail) {
    if (record.rendered && typeof record.rendered[detail] === "string") {
      return record.rendered[detail];
    }
    return "";
  }

  function renderOutputs() {
    if (!currentState) return;
    const records = Array.isArray(currentState.records) ? currentState.records : [];
    const detail = elements.detail.value;
    for (const role of ["publisher", "receiver"]) {
      elements.nodes[role].output.textContent = records
        .filter((record) => record.node === null || record.node === role)
        .map((record) => renderRecord(record, detail))
        .join("\n");
    }
  }

  function transcriptGroupName(step) {
    return transcriptGroupOrder.some(([key]) => key === step) ? step : "setup";
  }

  function transcriptIsFailing(entry) {
    return transcriptStatus(entry) === "failed";
  }

  function transcriptIsActive(entry) {
    return transcriptStatus(entry) === "running";
  }

  function transcriptStatus(entry) {
    if (["running", "succeeded", "failed", "stopped"].includes(entry.status)) {
      return entry.status;
    }
    const outcome = typeof entry.outcome === "string" ? entry.outcome.toLowerCase() : "";
    if (outcome === "running") return "running";
    if (["stopped", "cancelled"].includes(outcome)) return "stopped";
    if (/(fail|error|timeout|overflow)/.test(outcome)) return "failed";
    if (entry.returncode !== null && entry.returncode !== undefined && entry.returncode !== 0) {
      return "failed";
    }
    return "succeeded";
  }

  function appendTranscriptText(parent, tag, className, value) {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = value;
    parent.appendChild(element);
    return element;
  }

  function selectTranscriptEvidence(pre, feedback) {
    if (document.createRange && window.getSelection) {
      const range = document.createRange();
      range.selectNodeContents(pre);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      pre.focus();
      feedback.textContent = "Copy failed — text selected.";
    } else {
      feedback.textContent = "Copy unavailable";
    }
  }

  function selectObserverCommand(role) {
    const node = elements.nodes[role];
    const label = role === "publisher" ? "Publisher" : "Receiver";
    if (document.createRange && window.getSelection) {
      const range = document.createRange();
      range.selectNodeContents(node.attach);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      node.attach.focus();
      node.copyFeedback.textContent =
        label + " observer command selected. Use your copy shortcut to copy it.";
    } else {
      node.copyFeedback.textContent = label + " observer command could not be copied.";
    }
  }

  async function copyObserverCommand(role) {
    const node = elements.nodes[role];
    const command = node.attach.textContent;
    if (!command) return;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      try {
        await navigator.clipboard.writeText(command);
        node.copy.textContent = "Copied";
        node.copyFeedback.textContent =
          (role === "publisher" ? "Publisher" : "Receiver") + " observer command copied.";
        return;
      } catch (_) {
        // Clipboard permission may be unavailable; select the exact command instead.
      }
    }
    selectObserverCommand(role);
  }

  async function copyTranscriptEvidence(button) {
    const text = button.__transcriptCopyText;
    const feedback = button.__transcriptCopyFeedback;
    const pre = button.__transcriptCopyPre;
    if (typeof text !== "string") return;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      try {
        await navigator.clipboard.writeText(text);
        feedback.textContent = "Copied";
        return;
      } catch (_) {
        // Browser clipboard permission is unavailable; leave a safe text selection instead.
      }
    }
    selectTranscriptEvidence(pre, feedback);
  }

  function createTranscriptValue(label, field) {
    const section = document.createElement("section");
    section.className = "transcript-value";
    section.dataset.transcriptField = field;
    const header = document.createElement("div");
    header.className = "transcript-value-heading";
    appendTranscriptText(header, "strong", "transcript-value-label", label);
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "transcript-copy";
    copy.textContent = "Copy " + label.toLowerCase();
    copy.setAttribute("aria-label", "Copy " + label.toLowerCase());
    const feedback = appendTranscriptText(header, "span", "transcript-copy-feedback", "");
    feedback.setAttribute("aria-live", "polite");
    const pre = document.createElement("pre");
    pre.tabIndex = 0;
    copy.__transcriptCopyFeedback = feedback;
    copy.__transcriptCopyPre = pre;
    copy.addEventListener("click", () => copyTranscriptEvidence(copy));
    header.appendChild(copy);
    section.appendChild(header);
    section.appendChild(pre);
    return {section, pre, copy};
  }

  function createTranscriptRow(entry) {
    const details = document.createElement("details");
    details.className = "transcript-row";
    details.id = "transcript-entry-" + entry.id;
    const summary = document.createElement("summary");
    const title = appendTranscriptText(summary, "span", "transcript-row-title", "");
    const badges = document.createElement("span");
    badges.className = "transcript-badges";
    summary.appendChild(badges);
    const body = document.createElement("div");
    body.className = "transcript-row-body";
    const detail = appendTranscriptText(body, "p", "transcript-detail", "");
    const command = entry.kind === "command" ? createTranscriptValue("Command", "command") : null;
    const stdin = entry.kind === "command" ? createTranscriptValue("Standard input", "stdin") : null;
    const stdout = entry.kind === "command" ? createTranscriptValue("Standard output", "stdout") : null;
    const stderr = entry.kind === "command" ? createTranscriptValue("Standard error", "stderr") : null;
    const cwd = appendTranscriptText(body, "p", "transcript-cwd", "");
    for (const value of [command, stdin, stdout, stderr].filter(Boolean)) {
      body.appendChild(value.section);
    }
    details.appendChild(summary);
    details.appendChild(body);
    const row = {
      details, title, badges, detail, cwd, command, stdin, stdout, stderr,
      userOpen: null, autoOpen: false, active: false, failing: false,
    };
    summary.addEventListener("click", () => { row.userOpen = !details.open; });
    scheduleTranscriptDisclosureCollapse(row);
    return row;
  }

  function setTranscriptValue(value, text) {
    if (!value) return;
    const visible = typeof text === "string";
    value.section.hidden = !visible;
    if (!visible) return;
    value.pre.textContent = text;
    value.copy.__transcriptCopyText = text;
  }

  function renderTranscriptBadges(row, entry) {
    row.badges.textContent = "";
    const badges = [entry.kind === "internal" ? "Internal operation" : "Command", entry.outcome];
    if (typeof entry.duration_ms === "number") badges.push(entry.duration_ms + " ms");
    if (entry.returncode !== null && entry.returncode !== undefined) badges.push("exit " + entry.returncode);
    if (entry.replayable === false) badges.push("Not replayable");
    for (const stream of [entry.stdin, entry.stdout, entry.stderr]) {
      if (typeof stream === "string" && stream.includes("<truncated:")) badges.push("Truncated");
    }
    for (const [index, badge] of badges.filter((value) => typeof value === "string" && value).entries()) {
      appendTranscriptText(
        row.badges,
        "span",
        "transcript-badge" + (index === 0 ? " transcript-kind-badge" : index === 1 ? " transcript-status-badge" : ""),
        badge,
      );
    }
  }

  function ensureTranscriptGroups() {
    if (transcriptGroups.size || !elements.transcript) return;
    for (const [key, label] of transcriptGroupOrder) {
      const details = document.createElement("details");
      details.className = "transcript-group";
      details.dataset.transcriptStep = key;
      details.hidden = true;
      const summary = document.createElement("summary");
      appendTranscriptText(summary, "h3", "transcript-group-title", label);
      details.appendChild(summary);
      const rows = document.createElement("div");
      rows.className = "transcript-group-rows";
      details.appendChild(rows);
      elements.transcript.appendChild(details);
      const group = {
        details, rows, count: 0, hasActive: false, hasFailure: false,
        userOpen: null, autoOpen: false, active: false, failing: false,
      };
      summary.addEventListener("click", () => { group.userOpen = !details.open; });
      scheduleTranscriptDisclosureCollapse(group);
      transcriptGroups.set(key, group);
    }
  }

  function scheduleTranscriptDisclosureCollapse(item) {
    item.details.addEventListener("focusout", () => {
      setTimeout(() => updateTranscriptDisclosure(item, item.active, item.failing));
    });
  }

  function updateTranscriptDisclosure(item, active, failing) {
    item.active = active;
    item.failing = failing;
    const focused = item.details.contains(document.activeElement);
    if (failing) {
      item.autoOpen = true;
      item.details.open = true;
    } else if (active) {
      item.autoOpen = true;
      item.details.open = item.userOpen !== false;
    } else if (item.userOpen !== null) {
      item.autoOpen = false;
      item.details.open = item.userOpen;
    } else if (item.autoOpen && !focused) {
      item.autoOpen = false;
      item.details.open = false;
    }
  }

  function renderTranscript(state) {
    if (!elements.transcript) return;
    ensureTranscriptGroups();
    const entries = Array.isArray(state.transcript) ? state.transcript : [];
    const retained = new Set();
    for (const group of transcriptGroups.values()) {
      group.count = 0;
      group.hasActive = false;
      group.hasFailure = false;
    }
    for (const entry of entries) {
      if (!entry || !Number.isInteger(entry.id)) continue;
      retained.add(entry.id);
      const group = transcriptGroups.get(transcriptGroupName(entry.step));
      if (!group) continue;
      let row = transcriptRows.get(entry.id);
      if (!row) {
        row = createTranscriptRow(entry);
        transcriptRows.set(entry.id, row);
        group.rows.appendChild(row.details);
      }
      group.count += 1;
      const active = transcriptIsActive(entry);
      const failing = transcriptIsFailing(entry);
      group.hasActive = group.hasActive || active;
      group.hasFailure = group.hasFailure || failing;
      row.title.textContent = entry.kind === "command" ? (entry.command || "Command") : (entry.title || "Internal operation");
      row.detail.textContent = entry.detail || "";
      row.detail.hidden = !entry.detail;
      row.cwd.textContent = entry.cwd ? "Working directory: " + entry.cwd : "";
      row.cwd.hidden = !entry.cwd;
      setTranscriptValue(row.command, entry.command);
      setTranscriptValue(row.stdin, entry.stdin);
      setTranscriptValue(row.stdout, entry.stdout);
      setTranscriptValue(row.stderr, entry.stderr);
      row.details.classList.toggle("is-active", active);
      row.details.classList.toggle("is-failing", failing);
      updateTranscriptDisclosure(row, active, failing);
      renderTranscriptBadges(row, entry);
    }
    for (const [id, row] of transcriptRows) {
      if (retained.has(id)) continue;
      row.details.remove();
      transcriptRows.delete(id);
    }
    for (const group of transcriptGroups.values()) {
      group.details.hidden = group.count === 0;
      updateTranscriptDisclosure(group, group.hasActive, group.hasFailure);
    }
  }

  function renderAuthoritative(state) {
    if (commitPresentationActive && state && state.receipt &&
        Number.isInteger(state.revision) && state.revision >= currentRevision) {
      if (!deferredReceiptState || state.revision >= deferredReceiptState.revision) {
        deferredReceiptState = state;
      }
      return false;
    }
    return render(state);
  }

  async function presentCommitBeforeReceipt(finalState) {
    commitPresentationActive = true;
    deferredReceiptState = finalState;
    await new Promise((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(resolve));
    });
    await new Promise((resolve) => setTimeout(resolve, commitPresentationMs));
    const newestState = deferredReceiptState;
    commitPresentationActive = false;
    deferredReceiptState = null;
    render(newestState);
  }

  function statusText(state) {
    if (state.cleanup === "cleaned") return "Cleanup complete. You can close this page.";
    if (state.error && state.error.message) return state.error.message;
    const operation = {
      starting: "Starting a node…",
      stopping: "Stopping a node…",
      authenticating: "Restarting and authenticating both nodes…",
      publishing: state.commit ? "Committed at publisher; waiting for receiver…" : "Publishing the Event…",
      offline_experiment: "Running the optional transport experiment…",
      cleaning: "Cleaning up the disposable workspace…",
    }[state.operation];
    if (operation) return operation;
    if (state.receipt) return "Event committed and received.";
    if (state.authentication && state.authentication.state === "authenticated") return "Nodes authenticated. Send an Event.";
    const running = ["publisher", "receiver"].filter((role) => state.nodes[role].state === "running").length;
    if (running === 2) return "Both nodes are running. Authenticate them.";
    if (running === 1) return "One node is running. Start the other node.";
    return "Workspace ready. Start both nodes.";
  }

  function renderSignal(state) {
    const failed = state.cleanup === "failed" || Boolean(state.failed_stage) || Boolean(state.error);
    const inactive = state.cleanup === "cleaned";
    const working = !failed && !inactive && Boolean(state.operation);
    elements.signal.classList.toggle("is-ready", !failed && !inactive && !working);
    elements.signal.classList.toggle("is-working", working);
    elements.signal.classList.toggle("is-failed", failed);
    elements.signal.classList.toggle("is-inactive", inactive);
  }

  function render(state) {
    if (!state || !Number.isInteger(state.revision) || state.revision < currentRevision) return false;
    currentRevision = state.revision;
    currentState = state;
    elements.status.textContent = statusText(state);
    renderSignal(state);
    const cleanupStarted = state.operation === "cleaning" || state.cleanup !== null;
    for (const role of ["publisher", "receiver"]) {
      const node = state.nodes[role];
      const pairRestarting = state.pair_transition && state.pair_transition.state === "restarting_for_authentication";
      elements.nodes[role].state.textContent = pairRestarting ? "restarting · pair authentication" : node.state;
      elements.nodes[role].fingerprint.textContent = shortFingerprint(node.identity_fingerprint);
      elements.nodes[role].start.disabled = !hasAction(state, "start_" + role);
      elements.nodes[role].stop.disabled = !hasAction(state, "stop_" + role);
      elements.nodes[role].terminal.disabled = cleanupStarted;
      elements.nodes[role].copy.disabled = cleanupStarted;
    }
    const authentication = state.authentication ? state.authentication.state : "unauthenticated";
    elements.authState.textContent = authentication;
    elements.authenticate.disabled = !hasAction(state, "authenticate");
    elements.send.disabled = !hasAction(state, "publish_event");
    elements.text.disabled = !hasAction(state, "publish_event");
    elements.offline.disabled = !hasAction(state, "offline_experiment");
    elements.cleanup.disabled = !hasAction(state, "cleanup");

    renderProgress(state);
    renderTranscript(state);

    elements.delivery.hidden = !state.commit && !state.receipt;
    elements.commit.textContent = factText(state.commit, "Waiting for commit…");
    elements.receipt.textContent = factText(state.receipt, "Waiting for receiver…");
    elements.offlinePanel.hidden = !state.first_delivery;
    elements.evidence.textContent = JSON.stringify({
      revision: state.revision,
      nodes: state.nodes,
      authentication: state.authentication,
      pair_transition: state.pair_transition,
      failed_stage: state.failed_stage,
      commit: state.commit,
      receipt: state.receipt,
      experiment: state.experiment,
    }, null, 2);
    renderOutputs();
    return true;
  }

  async function request(path, body) {
    const response = await fetch(apiPath(path), {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) {
      const error = new Error(payload.error && payload.error.message ? payload.error.message : "The quickstart operation failed.");
      error.code = payload.error && payload.error.code ? payload.error.code : "operation_failed";
      throw error;
    }
    return payload;
  }

  async function refresh() {
    const response = await fetch(apiPath("/api/state"), {cache: "no-store"});
    if (!response.ok) throw new Error("The browser session is unavailable.");
    renderAuthoritative(await response.json());
  }

  function disableActions(disableObservers = false) {
    for (const role of ["publisher", "receiver"]) {
      elements.nodes[role].start.disabled = true;
      elements.nodes[role].stop.disabled = true;
      if (disableObservers) {
        elements.nodes[role].terminal.disabled = true;
        elements.nodes[role].copy.disabled = true;
      }
    }
    elements.authenticate.disabled = true;
    elements.send.disabled = true;
    elements.offline.disabled = true;
    elements.cleanup.disabled = true;
  }

  async function mutate(path, body) {
    disableActions(path === "/api/cleanup");
    try {
      const state = await request(path, body);
      const unseenCommit = state && state.commit && state.receipt &&
        state.revision >= currentRevision &&
        (!currentState || !currentState.commit ||
          currentState.commit.event_id !== state.commit.event_id);
      if (unseenCommit) {
        render({...state, operation: "publishing", receipt: null, first_delivery: null});
        await presentCommitBeforeReceipt(state);
      } else {
        renderAuthoritative(state);
      }
      return state;
    } catch (error) {
      try {
        await refresh();
        if (error.code === "invalid_event") elements.validation.textContent = error.message;
        else elements.status.textContent = error.message;
      } catch (_) {
        elements.status.textContent = error.message;
      }
      return null;
    }
  }

  function validEventText(text) {
    return text.length > 0 && new TextEncoder().encode(text).length <= 4096;
  }

  for (const role of ["publisher", "receiver"]) {
    elements.nodes[role].start.addEventListener("click", () => mutate("/api/nodes/" + role + "/start", {}));
    elements.nodes[role].stop.addEventListener("click", () => mutate("/api/nodes/" + role + "/stop", {}));
    elements.nodes[role].terminal.addEventListener("click", async () => {
      try {
        const payload = await request("/api/terminal/" + role, {detail: elements.detail.value});
        renderAuthoritative(payload.state);
        elements.nodes[role].fallback.hidden = payload.terminal.opened;
        elements.nodes[role].attach.textContent = payload.terminal.attach_command;
      } catch (error) {
        elements.status.textContent = error.message;
      }
    });
    elements.nodes[role].copy.addEventListener("click", () => copyObserverCommand(role));
  }
  elements.authenticate.addEventListener("click", () => mutate("/api/authenticate", {}));
  elements.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!validEventText(elements.text.value)) {
      elements.validation.textContent = "Enter an Event between 1 and 4096 UTF-8 bytes.";
      return;
    }
    elements.validation.textContent = "";
    await mutate("/api/events", {text: elements.text.value});
  });
  elements.offline.addEventListener("click", () => mutate("/api/experiments/offline", {text: elements.text.value}));
  elements.detail.addEventListener("change", renderOutputs);
  elements.cleanup.addEventListener("click", async () => {
    if (!window.confirm("Stop both nodes and remove all disposable quickstart data?")) return;
    await mutate("/api/cleanup", {confirm: true});
  });

  let resyncRefresh = null;

  function refreshAfterResync() {
    if (resyncRefresh !== null) return;
    resyncRefresh = refresh()
      .catch((error) => { elements.status.textContent = error.message; })
      .finally(() => { resyncRefresh = null; });
  }

  const events = new EventSource(apiPath("/api/events"));
  events.addEventListener("state", (event) => {
    const nextState = JSON.parse(event.data);
    if (nextState.stream && nextState.stream.mode === "resync_required") {
      refreshAfterResync();
      return;
    }
    renderAuthoritative(nextState);
  });
  events.onerror = () => refresh().catch(() => {});
  refresh().catch((error) => { elements.status.textContent = error.message; });
})();
