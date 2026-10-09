document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const POLL_MS = 4000;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "ico");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(SVG_NS, "use");
    use.setAttribute("href", `#i-${name}`);
    svg.appendChild(use);
    return svg;
  }

  function formatTime(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  /* ---------------------------------------------------------------- API */
  const TOKEN_KEY = "threatguard.token";

  function getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY) || "";
    } catch {
      return "";
    }
  }

  function setToken(value) {
    try {
      localStorage.setItem(TOKEN_KEY, value);
    } catch {
      /* storage unavailable */
    }
  }

  async function api(path, options = {}, retried = false) {
    const headers = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) headers["X-API-Key"] = token;

    const res = await fetch(path, { ...options, headers });
    if (res.status === 401 && !retried) {
      const entered = window.prompt("Enter your ThreatGuard access key");
      if (entered) {
        setToken(entered.trim());
        return api(path, options, true);
      }
    }
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  const post = (path, data) =>
    api(path, { method: "POST", body: JSON.stringify(data || {}) });

  /* -------------------------------------------------------------- views */
  const views = {
    home: $("homeView"),
    scan: $("scanView"),
    inbox: $("inboxView"),
    dashboard: $("dashboardView"),
  };
  const navLinks = document.querySelectorAll(".nav-links a");

  function showView(name, targetId) {
    Object.entries(views).forEach(([key, node]) =>
      node.classList.toggle("hidden", key !== name),
    );
    navLinks.forEach((link) =>
      link.classList.toggle(
        "active",
        link.dataset.view === name && !link.dataset.target,
      ),
    );

    const target = targetId ? $(targetId) : null;
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
    if (name === "inbox" || name === "dashboard") refresh();
  }

  document.addEventListener("click", (e) => {
    const trigger = e.target.closest("[data-view]");
    if (!trigger) return;
    e.preventDefault();
    showView(trigger.dataset.view, trigger.dataset.target);
  });

  document.querySelectorAll(".card-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const open = btn.getAttribute("aria-expanded") !== "true";
      btn.setAttribute("aria-expanded", String(open));
      $(btn.getAttribute("aria-controls")).hidden = !open;
      btn.textContent = open ? "Show less" : "Learn more";
    });
  });

  /* ---------------------------------------------------------- highlight */
  function highlight(text, level, ranges) {
    const frag = document.createDocumentFragment();
    let pos = 0;

    ranges.forEach((range) => {
      if (range.start > pos) {
        frag.appendChild(document.createTextNode(text.slice(pos, range.start)));
      }
      const mark = el(
        "mark",
        range.type === "link" ? "link" : "",
        text.slice(range.start, range.end),
      );
      if (range.type === "link" && level === "high") {
        mark.classList.add("blocked");
        mark.title = "Link blocked by ThreatGuard";
      }
      frag.appendChild(mark);
      pos = range.end;
    });

    if (pos < text.length) {
      frag.appendChild(document.createTextNode(text.slice(pos)));
    }
    return frag;
  }

  /* --------------------------------------------------- demo sample pool */
  const POOL = [
    {
      sender: "SecureBank Alerts",
      channel: "SMS",
      tag: "phish",
      body: "URGENT: Your bank account has been suspended. Verify your password immediately at http://secure-bank-login.example.com or your account will be closed.",
    },
    {
      sender: "Lucas",
      channel: "SMS",
      tag: "safe",
      body: "Hey, are we still meeting for lunch at 12:30 tomorrow? I'll save us a table.",
    },
    {
      sender: "Prize Center",
      channel: "SMS",
      body: "Congratulations winner! Claim your $500 gift card prize now: bit.ly/claim-prize and reply with your OTP to confirm.",
    },
    {
      sender: "Parcel Express",
      channel: "Email",
      body: "Your package is on hold. Confirm your address within 24 hours: http://track-parcel.example.net/confirm",
    },
    {
      sender: "Records Office",
      channel: "Email",
      body: "Please verify your account details when you get a chance so we can update our records.",
    },
    {
      sender: "Mom",
      channel: "SMS",
      body: "Don't forget to bring the charger when you come home this weekend. Love you!",
    },
    {
      sender: "IT Helpdesk",
      channel: "Email",
      body: "Action required: your mailbox is full. Log in now at http://192.168.44.12/mail-reset to keep receiving email.",
    },
    {
      sender: "Team Calendar",
      channel: "Email",
      body: "Reminder: the project meeting moved to 3 PM on Thursday in Room B. See you there.",
    },
  ];

  let bag = [];
  function nextSample() {
    if (bag.length === 0) {
      bag = POOL.slice();
      for (let i = bag.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [bag[i], bag[j]] = [bag[j], bag[i]];
      }
    }
    return bag.pop();
  }

  /* ----------------------------------------------------------- display */
  const LEVEL = {
    high: {
      badge: "Blocked",
      title: "High Risk",
      dashClass: "badge-phishing",
      statusClass: "status-blocked",
      scoreClass: "score-high",
    },
    medium: {
      badge: "Flagged",
      title: "Medium Risk",
      dashClass: "badge-smishing",
      statusClass: "status-flagged",
      scoreClass: "score-medium",
    },
    low: {
      badge: "Safe",
      title: "Low Risk",
      dashClass: "badge-safe",
      statusClass: "status-allowed",
      scoreClass: "score-low",
    },
  };

  const ADVICE = {
    high: "I blocked this message and disabled its link. Do not reply or share any codes. Delete it, and report it through the real company's official app or website.",
    medium:
      "I flagged this message. Do not click anything. Check with the sender using a phone number or website you already trust.",
    low: "I found no suspicious phrases or links, so this message was delivered normally.",
  };

  const AVATAR_COLORS = ["#e48a2c", "#4aa3f5", "#8a6cf0", "#e0527f", "#2fb8a0", "#d9a21b"];

  function avatar(name) {
    let hash = 0;
    for (const ch of name) hash = (hash * 31 + ch.charCodeAt(0)) % 997;
    const node = el("div", "avatar", name.charAt(0).toUpperCase());
    node.style.background = AVATAR_COLORS[hash % AVATAR_COLORS.length];
    return node;
  }

  function buildResult(msg) {
    const frag = document.createDocumentFragment();

    const header = el("div", "result-header");
    header.append(
      el("span", `pill pill-${msg.level}`, LEVEL[msg.level].title),
      el("span", "score-text", `Threat Score: ${msg.score}/100`),
    );

    const meter = el("div", "meter");
    const fill = el("span");
    fill.style.width = `${msg.score}%`;
    meter.appendChild(fill);
    frag.append(header, meter);

    if (msg.level !== "low") {
      const list = el("ul", "signal-list");
      msg.hits.forEach((hit) => {
        const item = el("li");
        item.append(el("span", "kw", hit.label), el("span", "why", hit.why));
        list.appendChild(item);
      });
      frag.appendChild(list);
    }

    const assistant = el("div", "assistant");
    const bot = el("div", "bot");
    bot.appendChild(icon("shield-check"));
    assistant.append(bot, el("div", "say", ADVICE[msg.level]));
    frag.appendChild(assistant);

    return frag;
  }

  /* ------------------------------------------------------------- state */
  const state = {
    allowed: false,
    messages: [],
    selectedId: null,
    signature: "",
  };

  const inboxList = $("inboxList");
  const inboxCount = $("inboxCount");
  const detail = $("detail");

  function inboxMessages() {
    return state.messages.filter((m) => !m.archived && m.channel !== "Manual");
  }

  function renderInbox() {
    const list = inboxMessages();
    inboxList.replaceChildren();
    const count = list.length;
    inboxCount.textContent = `${count} message${count === 1 ? "" : "s"}`;

    if (count === 0) {
      inboxList.appendChild(
        el(
          "div",
          "empty-state",
          "Your inbox is empty. Share a message to ThreatGuard and it appears here.",
        ),
      );
      return;
    }

    list.forEach((msg) => {
      const item = el(
        "button",
        "inbox-item" + (msg.id === state.selectedId ? " selected" : ""),
      );
      item.type = "button";

      const top = el("div", "item-top");
      top.append(
        el("span", "sender", msg.sender),
        el("span", "chan", msg.channel),
        el("span", "time", formatTime(msg.time)),
      );
      const main = el("div", "item-main");
      main.append(top, el("div", "preview", msg.body));

      item.append(
        avatar(msg.sender),
        main,
        el("span", `pill pill-${msg.level}`, LEVEL[msg.level].badge),
      );
      item.addEventListener("click", () => {
        state.selectedId = msg.id;
        renderInbox();
        renderDetail();
      });
      inboxList.appendChild(item);
    });
  }

  function renderDetail() {
    detail.replaceChildren();
    const msg = inboxMessages().find((m) => m.id === state.selectedId);

    if (!msg) {
      delete detail.dataset.level;
      const empty = el("div", "detail-empty");
      const inner = el("div");
      inner.append(
        icon("shield-check"),
        el("p", "", "Detection results appear here as soon as a message arrives."),
      );
      empty.appendChild(inner);
      detail.appendChild(empty);
      return;
    }

    detail.dataset.level = msg.level;

    const who = el("div");
    who.append(
      el("h3", "", msg.sender),
      el("span", "", `${msg.channel} · ${formatTime(msg.time)}`),
    );
    const head = el("div", "detail-head");
    head.append(avatar(msg.sender), who);

    const bubble = el("p", "bubble");
    bubble.appendChild(highlight(msg.body, msg.level, msg.ranges));

    detail.append(head, bubble, buildResult(msg));
  }

  const tableBody = $("logTableBody");

  function renderLog() {
    tableBody.replaceChildren();

    if (state.messages.length === 0) {
      const row = el("tr");
      const td = el(
        "td",
        "empty",
        "No messages scanned yet. Share a message to ThreatGuard, or use the scanner on the Scan page.",
      );
      td.colSpan = 6;
      row.appendChild(td);
      tableBody.appendChild(row);
      return;
    }

    state.messages.forEach((msg) => {
      const info = LEVEL[msg.level];
      const flat = msg.body.replace(/\s+/g, " ").trim();
      const excerpt = flat.length > 48 ? `"${flat.slice(0, 45)}..."` : `"${flat}"`;
      const badge = el("span", `type-badge ${info.dashClass}`, msg.threat_type);

      const cells = [
        { text: formatTime(msg.time) },
        { text: msg.sender },
        { text: excerpt, cls: "excerpt" },
        { node: badge },
        { text: `${msg.score}%`, cls: info.scoreClass },
        { text: msg.status, cls: info.statusClass },
      ];

      const row = el("tr");
      cells.forEach((cell) => {
        const td = el("td", cell.cls);
        if (cell.node) td.appendChild(cell.node);
        else td.textContent = cell.text;
        row.appendChild(td);
      });
      tableBody.appendChild(row);
    });
  }

  function renderStats(stats) {
    $("totalScans").textContent = stats.total;
    $("highRiskScans").textContent = stats.high;
    $("cleanScans").textContent = stats.clean;
  }

  /* ------------------------------------------------------------ access */
  const permissionCard = $("permissionCard");
  const inboxGrid = $("inboxGrid");
  const permDenied = $("permDenied");
  const inboxSub = $("inboxSub");

  const SUB_ASK = "ThreatGuard needs your permission before it can scan messages sent to it.";
  const SUB_ALLOWED = "On. Every message you share or forward is scanned the moment it arrives.";
  const SUB_DENIED = "Off. ThreatGuard is not accepting messages.";

  function applyAccess(allowed) {
    state.allowed = allowed;
    permissionCard.classList.toggle("hidden", allowed);
    inboxGrid.classList.toggle("hidden", !allowed);
    permDenied.classList.add("hidden");
    inboxSub.textContent = allowed ? SUB_ALLOWED : SUB_ASK;
  }

  async function setAccess(allowed) {
    try {
      await post("/api/access", { allowed });
      applyAccess(allowed);
      state.selectedId = null;
      await refresh(true);
    } catch {
      window.alert("Could not reach the ThreatGuard server.");
    }
  }

  /* ----------------------------------------------------------- refresh */
  let refreshing = false;

  async function refresh(force = false) {
    if (refreshing) return;
    refreshing = true;
    try {
      const [{ messages }, stats, info] = await Promise.all([
        api("/api/messages?limit=50"),
        api("/api/stats"),
        api("/api/state"),
      ]);

      if (info.access !== state.allowed) applyAccess(info.access);

      const signature = JSON.stringify([messages.map((m) => [m.id, m.archived]), stats]);
      if (!force && signature === state.signature) return;
      state.signature = signature;

      const previousTop = inboxMessages()[0]?.id;
      state.messages = messages;
      const list = inboxMessages();

      if (!list.some((m) => m.id === state.selectedId)) state.selectedId = null;
      if (list[0] && list[0].id !== previousTop) state.selectedId = list[0].id;

      renderStats(stats);
      renderLog();
      renderInbox();
      renderDetail();
    } catch {
      /* offline or unauthorised: keep what is on screen */
    } finally {
      refreshing = false;
    }
  }

  async function simulateMessage() {
    if (!state.allowed) return;
    const sample = nextSample();
    try {
      await post("/api/messages", {
        sender: sample.sender,
        channel: sample.channel,
        body: sample.body,
      });
      await refresh();
    } catch {
      /* ignore */
    }
  }

  $("allow-btn").addEventListener("click", () => setAccess(true));
  $("deny-btn").addEventListener("click", () => {
    permDenied.classList.remove("hidden");
    inboxSub.textContent = SUB_DENIED;
  });
  $("revoke-btn").addEventListener("click", () => setAccess(false));
  $("receive-btn").addEventListener("click", simulateMessage);
  $("clear-btn").addEventListener("click", async () => {
    try {
      await post("/api/inbox/clear");
      state.selectedId = null;
      await refresh(true);
    } catch {
      /* ignore */
    }
  });

  /* -------------------------------------------------------------- scan */
  const scanForm = $("scan");
  const scanSender = $("scanSender");
  const scanText = $("scanText");
  const scanResult = $("scanResult");

  function showScanResult(msg) {
    scanResult.replaceChildren();
    scanResult.dataset.level = msg.level;

    const bubble = el("p", "bubble");
    bubble.appendChild(highlight(msg.body, msg.level, msg.ranges));
    scanResult.append(bubble, buildResult(msg));
    scanResult.classList.remove("hidden");
  }

  async function runScan() {
    const body = scanText.value.trim();
    if (!body) {
      scanText.focus();
      return;
    }
    try {
      const msg = await post("/api/scan", { sender: scanSender.value.trim(), body });
      showScanResult(msg);
      refresh();
    } catch {
      window.alert("Could not reach the ThreatGuard server.");
    }
  }

  $("pasteBtn").addEventListener("click", async () => {
    try {
      const copied = (await navigator.clipboard.readText()).trim();
      if (!copied) {
        window.alert("Nothing copied yet. Copy the message first, then tap Paste & scan.");
        return;
      }
      scanText.value = copied.slice(0, 5000);
      runScan();
    } catch {
      scanText.focus();
      window.alert("Clipboard access was blocked. Long-press the message box and tap Paste instead.");
    }
  });

  scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    runScan();
  });

  scanForm.addEventListener("reset", () => {
    scanResult.classList.add("hidden");
    scanResult.replaceChildren();
  });

  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sample = POOL.find((item) => item.tag === btn.dataset.sample);
      scanSender.value = sample.sender;
      scanText.value = sample.body;
      scanText.focus();
    });
  });

  /* ----------------------------------------------- share target (phone) */
  function handleSharedText() {
    const params = new URLSearchParams(window.location.search);
    const text = [params.get("title"), params.get("text"), params.get("url")]
      .filter(Boolean)
      .join(" ")
      .trim();
    if (!text) return;

    window.history.replaceState({}, "", "/");
    showView("scan");
    scanText.value = text;
    runScan();
  }

  /* ------------------------------------------------------ install button */
  const installButtons = document.querySelectorAll("[data-install]");
  const installDialog = $("installDialog");
  const installLead = $("installLead");
  let deferredInstall = null;

  const isInstalled = () =>
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone === true;

  function hideInstallButtons() {
    installButtons.forEach((btn) => btn.classList.add("hidden"));
  }

  if (isInstalled()) hideInstallButtons();

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstall = e;
  });

  window.addEventListener("appinstalled", () => {
    deferredInstall = null;
    hideInstallButtons();
  });

  installButtons.forEach((btn) =>
    btn.addEventListener("click", async () => {
      if (deferredInstall) {
        deferredInstall.prompt();
        try {
          await deferredInstall.userChoice;
        } catch {
          /* ignore */
        }
        deferredInstall = null;
        return;
      }
      installLead.textContent = window.isSecureContext
        ? "Your browser did not offer a one-tap install, so use the steps below."
        : "Installing needs a secure (https) address. Open the https link you were given, then try again.";
      if (typeof installDialog.showModal === "function") installDialog.showModal();
      else window.alert("Open your browser menu and choose Install app or Add to Home screen.");
    }),
  );

  /* -------------------------------------------------------------- init */
  renderInbox();
  renderDetail();
  refresh(true).then(handleSharedText);
  setInterval(() => {
    if (!document.hidden) refresh();
  }, POLL_MS);

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
});
