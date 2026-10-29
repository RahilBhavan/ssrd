
(() => {
  const LIVE_SERVER = __LIVE_SERVER__;
  let DATA = JSON.parse(document.getElementById("ssrd-data").textContent);
  let currentSeries = "ingest";
  let kitFilter = "all";
  let selectedCardIdx = 0;

  const fmtInt = (n) => (n == null ? "—" : Number(n).toLocaleString("en-US"));
  const fmtPct = (x, d = 1) => (x == null ? "pending" : (x * 100).toFixed(d) + "%");
  const el = (tag, attrs = {}, ...kids) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "style") node.setAttribute("style", v);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (v != null) node.setAttribute(k, String(v));
    }
    for (const kid of kids) {
      if (kid == null) continue;
      node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    }
    return node;
  };

  const pill = (text, cls) => el("span", { class: "pill " + (cls || "unreviewed") }, text);

  const sigBadge = (s) => {
    const str = typeof s === "string" ? s : `${s.family}:${s.signal}`;
    const fam = str.split(":")[0] || "D";
    return el("span", { class: `sig-tag fam-${fam}` }, str);
  };

  function showTip(ev, text) {
    const tip = document.getElementById("tooltip");
    tip.textContent = text;
    tip.style.display = "block";
    tip.style.left = Math.min(window.innerWidth - 260, ev.clientX + 12) + "px";
    tip.style.top = Math.max(8, ev.clientY - 28) + "px";
  }
  function hideTip() {
    document.getElementById("tooltip").style.display = "none";
  }

  function renderBanner() {
    const b = document.getElementById("mode-banner");
    b.replaceChildren();
    if (DATA.mode === "public") {
      b.className = "banner public";
      b.append(
        el("span", {}, "PUBLIC REDACTED SHOWCASE · Aggregate pipeline telemetry + synthetic .test review walkthrough. Reference and flagged domains are withheld."),
        pill("aggregate view", "unreviewed")
      );
    } else {
      b.className = "banner private";
      b.append(
        el("span", {}, "PRIVATE LOCAL BRIEFING · Contains defanged domains and sanitized plain text from data/ssrd.sqlite. Keep private; never publish."),
        pill(LIVE_SERVER ? "127.0.0.1 read-only" : "0600 private file", "likely")
      );
    }
    document.getElementById("gen-stamp").textContent = `Snapshot: ${DATA.generated_at_utc}`;
    const generated = Date.parse(DATA.generated_at_utc);
    const age = Number.isFinite(generated) ? Math.max(0, Math.floor((Date.now() - generated) / 60000)) : null;
    document.getElementById("freshness").textContent = `Snapshot: ${DATA.generated_at_utc || "time unavailable"}. ` +
      (age == null ? "Freshness unknown." : age > 120 ? `Stale snapshot (${Math.floor(age / 60)} hours old). Counts may have changed.` : `Generated ${age} minutes ago.`) +
      ` Metrics window: ${DATA.window.first_utc || DATA.window.start || "see chart dates"} to ${DATA.window.last_utc || DATA.window.end || DATA.generated_at_utc}; ${DATA.window.hours ?? "unknown"} hours. ` +
      (LIVE_SERVER ? "Refresh retrieves a new snapshot." : "This static page updates when its publisher rebuilds it; reload to check for a newer snapshot.");
    if (LIVE_SERVER) {
      const btn = document.getElementById("refresh-btn");
      btn.style.display = "inline-block";
      btn.onclick = async () => {
        btn.textContent = "Refreshing…";
        try {
          const r = await fetch("/api/snapshot");
          if (!r.ok) throw new Error("Snapshot unavailable");
          DATA = await r.json();
          selectedCardIdx = 0;
          renderAll();
        } catch (_) {
          document.getElementById("freshness").textContent = "Refresh failed. The previous snapshot remains visible. Try again shortly.";
        } finally {
          btn.textContent = "Refresh snapshot";
        }
      };
    }
  }

  function renderKPIs() {
    const f = DATA.funnel;
    const ev = DATA.evaluation;
    const ttf = ev.time_to_flag || {};
    const prec = ev.precision || {};
    const populationMeasured = prec.population_precision_available ?? (prec.representative && prec.minimum_sample_met);


    const items = [
      {
        label: "CT Names Inspected",
        badge: pill("recorded", "unreviewed"),
        val: fmtInt(f.ct_names ?? null),
        sub: `${fmtInt(f.ct_bytes_mb)} MB names tiles (${DATA.window.hours || 0}h window)`,
      },
      {
        label: "Classifier Candidates",
        badge: pill(f.pass_rate_pct != null ? `${f.pass_rate_pct.toFixed(2)}% pass` : "filter", "confirmed"),
        val: fmtInt(f.candidates_db),
        sub: `n-gram ≥ 0.93 · ${fmtInt(f.visits_pending)} visits queued`,
      },
      {
        label: "Passive Visits Done",
        badge: pill("recorded", "unreviewed"),
        val: fmtInt(f.visits_done),
        sub: `${fmtInt(f.pages_live_content)} live HTML content pages`,
      },
      {
        label: "Scam-Kit Library",
        badge: pill("recorded", "unreviewed"),
        val: `${fmtInt(f.kits_multi_active)} kits`,
        sub: `+ ${fmtInt(f.kits_single_ref)} single-site refs (${fmtInt((f.seeds_by_source.cbr || 0) + (f.seeds_by_source.kcda || 0))} seeds)`,
      },
      {
        label: "Live Kit Alerts",
        badge: pill(prec.n_labeled_alerts ? "reviewed" : "unreviewed", prec.n_labeled_alerts ? "likely" : "unreviewed"),
        val: fmtInt(f.alerts_active),
        sub: `${fmtInt(f.alerts_total)} cumulative · KCDA: ${f.alerts_kcda}, CBR: ${f.alerts_cbr}`,
      },
      {
        label: "Live alert precision",
        badge: pill(populationMeasured && prec.precision != null ? "measured" : "pending", "pending"),
        val: populationMeasured && prec.precision != null ? fmtPct(prec.precision, 0) : "Pending",
        sub: populationMeasured && prec.precision != null
          ? `Reviewed subset · 95% CI ${fmtPct(prec.ci95[0], 0)}–${fmtPct(prec.ci95[1], 0)} (n=${prec.n_labeled_alerts})`
          : "Awaiting representative human-reviewed sample",
      },
      {
        label: "Median Time to Flag",
        badge: pill(ttf.n ? "likely" : "pending", ttf.n ? "likely" : "pending"),
        val: ttf.median_min != null ? `${ttf.median_min}m` : "—",
        sub: ttf.n ? `p90 ${ttf.p90_min}m (n=${ttf.n} live; +20m delay)` : "Awaiting live CT timestamps",
      },
    ];

    const root = document.getElementById("kpis");
    root.replaceChildren(
      ...items.map((it) =>
        el("div", { class: "kpi" },
          el("div", { class: "label" }, el("span", {}, it.label), it.badge),
          el("div", { class: "val" }, it.val),
          el("div", { class: "sub" }, it.sub)
        )
      )
    );
  }

  function renderFunnel() {
    const f = DATA.funnel;
    const stages = [
      { name: "CT Registrable Names", count: f.ct_names ?? null, color: "#45474C" },
      { name: "Name-Filter Candidates", count: f.candidates_db, color: "#45474C" },
      { name: "Completed Passive Visits", count: f.visits_done, color: "#45474C" },
      { name: "Live Content Captures", count: f.pages_live_content, color: "#45474C" },
      { name: "Cumulative Kit Alerts", count: f.alerts_total, color: "#76787D" },
      { name: "Active Alerts (Current Rule)", count: f.alerts_active, color: "#45474C" },
    ];
    const maxLog = Math.max(1, ...stages.map((s) => Math.log10(Math.max(1, s.count || 0) + 1)));
    const root = document.getElementById("funnel-view");
    root.replaceChildren(
      ...stages.map((s) => {
        const w = s.count > 0 ? Math.max(4, (Math.log10(s.count + 1) / maxLog) * 100) : 0;
        return el("div", { class: "funnel-row" },
          el("span", {}, s.name),
          el("div", { class: "funnel-bar-bg", style: "visibility:hidden", title: `${s.name}: ${fmtInt(s.count)} (log-scaled width)` },
            el("div", { class: "funnel-bar-fill", style: `width:${w.toFixed(1)}%;background:${s.color}` })
          ),
          el("span", { class: "funnel-num" }, fmtInt(s.count))
        );
      })
    );

    const outcomes = f.visits_by_outcome || {};
    const palette = {
      content: "#45474C",
      blank: "#45474C",
      error: "#45474C",
      parked: "#45474C",
      blocked: "#45474C",
      skipped: "#45474C",
      refiltered: "#45474C",
      expired: "#45474C",
      seized: "#76787D",
    };
    const entries = Object.entries(outcomes).sort((a, b) => b[1] - a[1]);
    const totalOut = entries.reduce((acc, [, v]) => acc + v, 0) || 1;
    const bar = document.getElementById("outcome-bar");
    const leg = document.getElementById("outcome-legend");
    bar.replaceChildren(
      ...entries.map(([k, v]) => {
        const pct = (v / totalOut) * 100;
        return el("div", {
          style: `width:${pct.toFixed(2)}%;background:${palette[k] || "#45474C"}`,
          onmousemove: (e) => showTip(e, `${k}: ${fmtInt(v)} (${pct.toFixed(1)}%)`),
          onmouseleave: hideTip,
        });
      })
    );
    leg.replaceChildren(
      ...entries.map(([k, v]) =>
        el("span", {},
          el("i", { class: "dot", style: `background:${palette[k] || "#45474C"}` }),
          `${k}: ${fmtInt(v)} (${((v / totalOut) * 100).toFixed(1)}%)`
        )
      )
    );
  }

  function renderTimeseries() {
    const box = document.getElementById("ts-chart");
    box.replaceChildren();
    let rows = [];
    let primaryKey = "names";
    let secondaryKey = "filter_pass";
    let primaryColor = "#45474C";
    let secondaryColor = "#76787D";
    let labelA = "CT names";
    let labelB = "Filter passes";

    if (currentSeries === "ingest") {
      rows = DATA.timeseries.ingest_6h || [];
    } else if (currentSeries === "fetch") {
      rows = DATA.timeseries.fetch_6h || [];
      primaryKey = "visits";
      secondaryKey = "content";
      primaryColor = "#45474C";
      secondaryColor = "#76787D";
      labelA = "Visits";
      labelB = "Content pages";
    } else {
      rows = DATA.timeseries.alerts_daily || [];
      primaryKey = "total";
      secondaryKey = "kcda";
      primaryColor = "#76787D";
      secondaryColor = "#45474C";
      labelA = "Total alerts";
      labelB = "KCDA alerts";
    }

    if (!rows.length) {
      box.appendChild(el("div", { style: "padding:32px;color:var(--ssrd-dim);text-align:center" }, "No time-series buckets recorded yet."));
      return;
    }

    const W = 560, H = 250, padL = 64, padR = 14, padT = 16, padB = 34;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const maxVal = Math.max(1, ...rows.map((r) => Math.max(r[primaryKey] || 0, r[secondaryKey] || 0)));
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.style.minWidth = `${W}px`;

    for (let i = 0; i <= 4; i++) {
      const y = padT + (plotH * i) / 4;
      const val = Math.round(maxVal * (1 - i / 4));
      const line = document.createElementNS(ns, "line");
      line.setAttribute("x1", padL);
      line.setAttribute("x2", W - padR);
      line.setAttribute("y1", y);
      line.setAttribute("y2", y);
      line.setAttribute("stroke", "var(--ssrd-border)");
      line.setAttribute("stroke-dasharray", "3,3");
      svg.appendChild(line);

      const txt = document.createElementNS(ns, "text");
      txt.setAttribute("x", padL - 6);
      txt.setAttribute("y", y + 4);
      txt.setAttribute("text-anchor", "end");
      txt.setAttribute("fill", "var(--ssrd-faint)");
      txt.setAttribute("font-size", "14");
      txt.setAttribute("font-family", "var(--font-figure)");
      txt.textContent = val >= 10000 ? (val / 1000).toFixed(0) + "k" : String(val);
      svg.appendChild(txt);
    }

    const barW = Math.max(2, plotW / rows.length - 2);
    rows.forEach((r, idx) => {
      const x = padL + (idx / rows.length) * plotW;
      const v1 = r[primaryKey] || 0;
      const v2 = r[secondaryKey] || 0;
      const h1 = (v1 / maxVal) * plotH;
      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", x);
      rect.setAttribute("y", padT + plotH - h1);
      rect.setAttribute("width", barW);
      rect.setAttribute("height", h1);
      rect.setAttribute("fill", primaryColor);
      
      rect.setAttribute("rx", "1.5");
      const tLabel = r.t || r.day || "";
      rect.addEventListener("mousemove", (e) => showTip(e, `${tLabel} · ${labelA}: ${fmtInt(v1)} · ${labelB}: ${fmtInt(v2)}`));
      rect.addEventListener("mouseleave", hideTip);
      svg.appendChild(rect);

      if (v2 > 0) {
        const h2 = (v2 / maxVal) * plotH;
        const r2 = document.createElementNS(ns, "rect");
        r2.setAttribute("x", x + barW * 0.25);
        r2.setAttribute("y", padT + plotH - h2);
        r2.setAttribute("width", barW * 0.5);
        r2.setAttribute("height", h2);
        r2.setAttribute("fill", secondaryColor);
        r2.addEventListener("mousemove", (e) => showTip(e, `${tLabel} · ${labelB}: ${fmtInt(v2)}`));
        r2.addEventListener("mouseleave", hideTip);
        svg.appendChild(r2);
      }
    });

    const step = Math.max(1, Math.ceil(rows.length / 4));
    for (let i = 0; i < rows.length; i += step) {
      const x = padL + (i / rows.length) * plotW + barW / 2;
      const lbl = (rows[i].t || rows[i].day || "").slice(5, 16);
      const t = document.createElementNS(ns, "text");
      t.setAttribute("x", x);
      t.setAttribute("y", H - 10);
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("fill", "var(--ssrd-faint)");
      t.setAttribute("font-size", "14");
      t.setAttribute("font-family", "var(--font-figure)");
      t.textContent = lbl;
      svg.appendChild(t);
    }

    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `${labelA} and ${labelB} by UTC bucket; exact values follow in the data table.`);
    box.appendChild(svg);
    const table = el("table", {}, el("thead", {}, el("tr", {}, ...["UTC bucket", labelA, labelB].map(x => el("th", {scope:"col"}, x)))),
      el("tbody", {}, ...rows.map(r => el("tr", {}, el("td", {}, r.t || r.day || ""), el("td", {class:"mono"}, fmtInt(r[primaryKey] ?? 0)), el("td", {class:"mono"}, fmtInt(r[secondaryKey] ?? 0))))));
    box.appendChild(el("details", {class:"chart-data"}, el("summary", {}, "Read exact chart values"), table));
    box.appendChild(
      el("div", { class: "legend", style: "margin-top:6px" },
        el("span", {}, el("i", { class: "dot", style: `background:${primaryColor}` }), `${labelA} (wide bars)`),
        el("span", {}, el("i", { class: "dot", style: `background:${secondaryColor}` }), `${labelB} (narrow bars)`)
      )
    );
  }

