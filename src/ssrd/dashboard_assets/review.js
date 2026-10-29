  function ciWidget(lo, hi, pt) {
    if (pt == null) return el("span", { class: "mono", style: "color:var(--ssrd-faint)" }, "—");
    const box = el("span", { class: "ci-bar", title: `95% CI: ${fmtPct(lo)} – ${fmtPct(hi)}` },
      el("span", { class: "ci-range", style: `left:${(lo * 100).toFixed(1)}%;width:${Math.max(2, (hi - lo) * 100).toFixed(1)}%` }),
      el("span", { class: "ci-point", style: `left:${(pt * 100).toFixed(1)}%` })
    );
    return el("span", {}, box, el("span", { class: "mono", style: "margin-left:7px;font-size:14px" }, `[${fmtPct(lo, 0)}, ${fmtPct(hi, 0)}]`));
  }

  function renderEvaluation() {
    const ev = DATA.evaluation;
    const p = ev.precision || {};
    const pk = ev.precision_kcda || {};
    const pc = ev.precision_cbr || {};
    const bt = ev.backtest || ev.recorded_backtest;
    const mb = ev.model_benchmark || {};
    const fwd = ev.cbr_forward || {};
    const kp = ev.kappa;

    const rows = [
      {
        name: "Precision (reviewed subset; may be biased)",
        val: p.n_labeled_alerts ? `${fmtPct(p.precision, 1)} (${p.scam_kit}/${p.n_labeled_alerts})` : "Pending frozen sample labels",
        ci: p.n_labeled_alerts ? ciWidget(p.ci95[0], p.ci95[1], p.precision) : el("span", { style: "color:var(--ssrd-dim)" }, "Awaiting a complete frozen sample"),
        conf: pill(p.n_labeled_alerts ? "confirmed" : "pending", p.n_labeled_alerts ? "confirmed" : "pending"),
      },
      {
        name: "KCDA vs. CBR Alert Split",
        val: `KCDA: ${DATA.funnel.alerts_kcda} active · CBR: ${DATA.funnel.alerts_cbr} active`,
        ci: el("span", { class: "mono", style: "font-size:14px;color:var(--ssrd-dim)" },
          `labeled KCDA n=${pk.n_labeled_alerts || 0}, CBR n=${pc.n_labeled_alerts || 0}`),
        conf: pill(p.n_labeled_alerts ? "likely" : "unreviewed", p.n_labeled_alerts ? "likely" : "unreviewed"),
      },
      {
        name: "Hold-Out Backtest (20% multi-domain kits)",
        val: bt ? `${fmtPct(bt.catch_rate, 0)} (${bt.caught_correct_kit}/${bt.held_out})` : "Pending backtest",
        ci: bt && bt.ci95 ? ciWidget(bt.ci95[0], bt.ci95[1], bt.catch_rate) : el("span", {}, "—"),
        conf: pill("recorded", "unreviewed"),
      },
      {
        name: "CT Name Classifier (CBR ≥ 2026-07-01)",
        val: mb.ngram_recall == null ? "Benchmark not available" : `Recall ${(mb.ngram_recall * 100).toFixed(0)}% @ ${mb.ngram_pass_rate_pct}% pass rate`,
        ci: el("span", { style: "color:var(--ssrd-dim);font-size:14px" }, mb.keyword_recall == null ? "No verified benchmark in this snapshot" : `vs. keyword ${(mb.keyword_recall * 100).toFixed(0)}% @ ${mb.keyword_pass_rate_pct}%`),
        conf: pill("recorded", "unreviewed"),
      },
      {
        name: "CBR Forward Check (External Ground Truth)",
        val: `${fmtInt(fwd.candidates_later_listed)} CT candidates later listed by CBR`,
        ci: el("span", { class: "mono", style: "font-size:14px" }, `${fmtInt(fwd.of_which_alerted)} alerted by SSRD`),
        conf: pill("recorded", "unreviewed"),
      },
    ];
    if (kp && kp.n > 0) {
      rows.push({
        name: "Inter-Rater Agreement (Cohen's κ)",
        val: `κ = ${kp.kappa} (agreement ${(kp.observed_agreement * 100).toFixed(1)}%)`,
        ci: el("span", { class: "mono" }, `n=${kp.n} blind double-labeled`),
        conf: pill("recorded", "unreviewed"),
      });
    }

    const tbody = document.querySelector("#eval-table tbody");
    tbody.replaceChildren(
      ...rows.map((r) => el("tr", {}, el("td", {}, r.name), el("td", { class: "mono" }, r.val), el("td", {}, r.ci), el("td", {}, r.conf)))
    );

    const assist = ev.assist_triage || {};
    const assistParts = Object.entries(assist).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}: ${v}`).join(" · ");
    const lc = ev.lead_confidence || {};
    document.getElementById("label-summary").textContent =
      `Active lead confidence: ${lc.confirmed || 0} confirmed, ${lc.likely || 0} likely, ${lc.speculative || 0} speculative (unreviewed). ` +
      `Assistant triage hints (claude-assist, never counted as labels): ${assistParts || "none"}.`;
  }

  function renderTTF() {
    const ttf = DATA.evaluation.time_to_flag || {};
    const stats = document.getElementById("ttf-stats");
    stats.replaceChildren(
      el("span", {}, "Live-visit alerts: ", el("strong", { class: "mono" }, fmtInt(ttf.n || 0))),
      el("span", {}, "Median: ", el("strong", { class: "mono" }, ttf.median_min != null ? `${ttf.median_min} min` : "—")),
      el("span", {}, "p90: ", el("strong", { class: "mono" }, ttf.p90_min != null ? `${ttf.p90_min} min` : "—")),
      el("span", {}, "Retroactive (later kit rebuild): ", el("strong", { class: "mono" }, fmtInt(ttf.retroactive_alerts || 0)))
    );

    const buckets = ttf.buckets || [];
    const box = document.getElementById("ttf-chart");
    box.replaceChildren();
    if (!buckets.length || !ttf.n) { box.appendChild(el("p", {class:"empty"}, "No eligible latency observations. Median and p90 remain pending.")); return; }
    const maxC = Math.max(1, ...buckets.map((b) => b.count));
    const W = 520, H = 200, padL = 44, padR = 14, padT = 18, padB = 38;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.style.minWidth = `${W}px`;

    const bw = plotW / buckets.length - 8;
    buckets.forEach((b, i) => {
      const x = padL + i * (plotW / buckets.length) + 4;
      const h = (b.count / maxC) * plotH;
      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", x);
      rect.setAttribute("y", padT + plotH - h);
      rect.setAttribute("width", Math.max(8, bw));
      rect.setAttribute("height", h);
      rect.setAttribute("rx", "3");
      rect.setAttribute("fill", "#45474C");
      
      rect.addEventListener("mousemove", (e) => showTip(e, `${b.label}: ${fmtInt(b.count)} alerts`));
      rect.addEventListener("mouseleave", hideTip);
      svg.appendChild(rect);

      const valTxt = document.createElementNS(ns, "text");
      valTxt.setAttribute("x", x + Math.max(8, bw) / 2);
      valTxt.setAttribute("y", padT + plotH - h - 5);
      valTxt.setAttribute("text-anchor", "middle");
      valTxt.setAttribute("fill", "var(--ssrd-dim)");
      valTxt.setAttribute("font-size", "14");
      valTxt.setAttribute("font-family", "var(--font-figure)");
      valTxt.textContent = String(b.count);
      svg.appendChild(valTxt);

      const lbl = document.createElementNS(ns, "text");
      lbl.setAttribute("x", x + Math.max(8, bw) / 2);
      lbl.setAttribute("y", H - 12);
      lbl.setAttribute("text-anchor", "middle");
      lbl.setAttribute("fill", "var(--ssrd-faint)");
      lbl.setAttribute("font-size", "14");
      lbl.setAttribute("font-family", "var(--font-figure)");
      lbl.textContent = b.label;
      svg.appendChild(lbl);
    });
    svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "CT-to-alert latency distribution; exact counts follow.");
    box.appendChild(svg);
    box.appendChild(el("div", {class:"legend"}, ...buckets.map(b => el("span", {}, `${b.label}: ${fmtInt(b.count)} alerts`))));
  }

  let kitLimit = 8;

  function renderKits() {
    const q = (document.getElementById("kit-search").value || "").toLowerCase().trim();
    const multi = (DATA.kits.multi || []).filter((k) => {
      if (kitFilter === "kcda" && k.group !== "kcda") return false;
      if (kitFilter === "cbr" && k.group !== "cbr") return false;
      if (kitFilter === "alerting" && !k.live_alerts) return false;
      if (!q) return true;
      return (
        k.name.toLowerCase().includes(q) ||
        k.summary.toLowerCase().includes(q) ||
        (k.signals || []).some((s) => s.toLowerCase().includes(q))
      );
    });

    const sr = DATA.kits.single_ref_summary || {};
    document.getElementById("kit-sub").textContent =
      `${Math.min(kitLimit, multi.length)} of ${multi.length} matching multi-domain kits shown · plus ${fmtInt(sr.count || 0)} single-site references (${sr.live_alerts || 0} active alerts)`;

    const tbody = document.querySelector("#kit-table tbody");
    tbody.replaceChildren(
      ...multi.slice(0, kitLimit).map((k) =>
        el("tr", {},
          el("td", { class: "mono", style: "font-weight:600;white-space:nowrap" },
            k.name,
            k.status !== "active" ? el("span", { style: "color:var(--ssrd-faint);font-weight:400" }, " [excl]") : null
          ),
          el("td", {}, pill(k.group.toUpperCase(), k.group)),
          el("td", { class: "mono" }, `${k.pages}p / ${k.domains}d`),
          el("td", { class: "mono" }, k.live_alerts ? pill(String(k.live_alerts), "alert") : "0"),
          el("td", {}, ...(k.signals || []).slice(0, 4).map(sigBadge)),
          el("td", { style: "color:var(--ssrd-dim);font-size:14px" }, k.summary)
        )
      )
    );

    const more = document.getElementById("kit-more");
    more.hidden = multi.length <= 8;
    more.textContent = kitLimit >= multi.length ? "Show first 8 kits" : `Show all ${multi.length} matching kits`;
    more.setAttribute("aria-expanded", String(kitLimit >= multi.length));

    if (!multi.length) tbody.appendChild(el("tr", {}, el("td", {colspan:"6",class:"empty"}, "No kits match these filters. Clear the search or choose All.")));
    const sm = DATA.kits.signal_matrix || {};
    const combos = sm.by_family_combo || [];
    const maxCombo = Math.max(1, ...combos.map((c) => c.alerts));
    document.getElementById("combo-bars").replaceChildren(
      ...combos.map((c) =>
        el("div", { class: "funnel-row", style: "grid-template-columns:160px 1fr 60px;margin-bottom:6px" },
          el("span", { class: "mono", style: "font-size:14px" }, c.combo),
          el("div", { class: "funnel-bar-bg", style: "height:14px" },
            el("div", { class: "funnel-bar-fill", style: `width:${((c.alerts / maxCombo) * 100).toFixed(1)}%;background:var(--ssrd-accent)` })
          ),
          el("span", { class: "funnel-num" }, fmtInt(c.alerts))
        )
      )
    );

    const sigs = (sm.by_signal || []).slice(0, 8);
    const maxSig = Math.max(1, ...sigs.map((s) => s.alerts));
    document.getElementById("signal-bars").replaceChildren(
      ...sigs.map((s) =>
        el("div", { class: "funnel-row", style: "grid-template-columns:160px 1fr 60px;margin-bottom:6px" },
          sigBadge(`${s.family}:${s.signal}`),
          el("div", { class: "funnel-bar-bg", style: "height:12px" },
            el("div", { class: "funnel-bar-fill", style: `width:${((s.alerts / maxSig) * 100).toFixed(1)}%;background:var(--ssrd-blue)` })
          ),
          el("span", { class: "funnel-num" }, fmtInt(s.alerts))
        )
      )
    );
  }

  function renderWalkthrough() {
    const w = DATA.walkthrough || { cards: [] };
    document.getElementById("walk-sub").textContent = w.note || "";
    const q = (document.getElementById("card-search").value || "").toLowerCase().trim();
    const cards = (w.cards || []).filter((c) => {
      if (!q) return true;
      return (
        c.domain.toLowerCase().includes(q) ||
        c.kit.toLowerCase().includes(q) ||
        (c.signals || []).some((s) => `${s.family}:${s.signal}`.toLowerCase().includes(q)) ||
        (c.sanitized_text || "").toLowerCase().includes(q)
      );
    });

    const listEl = document.getElementById("alert-list");
    const detailEl = document.getElementById("alert-detail");
    listEl.replaceChildren();
    detailEl.replaceChildren();

    if (!cards.length) {
      listEl.appendChild(el("div", { style: "padding:18px;color:var(--ssrd-dim)" }, "No matching cards."));
      return;
    }
    if (selectedCardIdx >= cards.length) selectedCardIdx = 0;

    cards.forEach((c, idx) => {
      const item = el("button", {
        type: "button", "aria-pressed": idx === selectedCardIdx,
        class: "alert-item" + (idx === selectedCardIdx ? " selected" : ""),
        onclick: () => {
          selectedCardIdx = idx;
          renderWalkthrough();
          document.querySelector(".alert-item.selected")?.focus();
        },
      },
        el("div", { style: "display:flex;justify-content:space-between;gap:6px;align-items:center" },
          el("strong", { class: "mono", style: "font-size:14px" }, c.domain),
          pill(c.confidence, c.confidence === "confirmed" ? "confirmed" : (c.confidence === "likely" ? "likely" : "unreviewed"))
        ),
        el("div", { style: "font-size:14px;color:var(--ssrd-dim);margin-top:3px" },
          `matches ${c.kit} · score=${c.score}` + (c.assist_hint ? ` · hint: ${c.assist_hint.label}` : "")
        )
      );
      listEl.appendChild(item);
    });

    const cur = cards[selectedCardIdx];
    const hintText = cur.assist_hint
      ? `Assistant hint (uncounted): ${cur.assist_hint.label}${cur.assist_hint.note ? " — " + cur.assist_hint.note : ""}`
      : "No assistant prelabel rule matched.";

    const pre = el("pre", { class: "sanitized" }, cur.sanitized_text || "(sanitized text unavailable)");
    detailEl.append(
      el("div", { style: "display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:8px" },
        el("div", {},
          el("span", { class: "mono", style: "font-size:15px;font-weight:700" }, cur.domain),
          el("span", { style: "margin-left:10px;color:var(--ssrd-dim)" }, `matches ${cur.kit} (nearest: ${cur.nearest_member})`)
        ),
        el("div", { style: "display:flex;gap:6px;align-items:center" },
          pill(cur.group.toUpperCase(), cur.group),
          pill(cur.alert ? `alert score=${cur.score}` : `near-miss score=${cur.score}`, cur.alert ? "alert" : "unreviewed")
        )
      ),
      el("div", { style: "font-size:14px;color:var(--ssrd-dim);margin-bottom:8px" },
        `class=${cur.page_class} · lang=${cur.lang || "—"} · cyrillic=${cur.cyrillic_ratio ?? 0} · invest_terms=${cur.invest_terms ?? 0}` +
        (cur.ct_to_alert_min != null ? ` · CT→alert: ${cur.ct_to_alert_min} min` : "") +
        (cur.human_labels && cur.human_labels.length ? ` · human labels: ${cur.human_labels.join(", ")}` : " · human labels: unreviewed")
      ),
      el("div", { style: "margin-bottom:8px" }, ...(cur.signals || []).map(sigBadge)),
      el("div", { style: "font-size:14px;color:var(--ssrd-amber);margin-bottom:6px" }, hintText),
      el("div", { style: "font-size:14px;color:var(--ssrd-faint);text-transform:uppercase;letter-spacing:0.04em" },
        "Sanitized Plain-Text Capture (Scripts Stripped, Links Defanged — Never Rendered as HTML)"
      ),
      pre
    );

    if (LIVE_SERVER && cur.page_id > 0 && !w.is_synthetic) {
      fetch(`/api/page/${cur.page_id}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (d && d.sanitized_text) pre.textContent = d.sanitized_text;
        })
        .catch(() => {});
    }
  }

  function renderFooterAndLimitations() {
    document.getElementById("limitations").replaceChildren(
      ...(DATA.limitations || []).map((t) => el("li", {}, t))
    );
    const logs = (DATA.funnel.ct_logs || []).map((l) => `${l.label}: @${fmtInt(l.next_index)}`).join(" · ");
    document.getElementById("ct-state-line").textContent = logs ? `CT tile cursors · ${logs}` : "CT cursors: offline snapshot";
  }

  function renderAll() {
    renderBanner();
    renderKPIs();
    renderFunnel();
    renderTimeseries();
    renderEvaluation();
    renderTTF();
    renderKits();
    renderWalkthrough();
    renderFooterAndLimitations();
  }

  document.getElementById("theme-btn").addEventListener("click", () => {
    const html = document.documentElement;
    html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
  });

  document.querySelectorAll("#ts-tabs button").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll("#ts-tabs button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      b.parentElement.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      currentSeries = b.dataset.series;
      renderTimeseries();
    });
  });

  document.querySelectorAll("[data-kfilter]").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll("[data-kfilter]").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      b.parentElement.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      kitFilter = b.dataset.kfilter;
      kitLimit = 8;
      renderKits();
    });
  });

  document.getElementById("kit-search").addEventListener("input", () => { kitLimit = 8; renderKits(); });
  document.getElementById("kit-more").addEventListener("click", () => {
    kitLimit = kitLimit === 8 ? Infinity : 8;
    renderKits();
  });
  document.getElementById("card-search").addEventListener("input", () => {
    selectedCardIdx = 0;
    renderWalkthrough();
  });

  document.querySelectorAll("[data-series],[data-kfilter]").forEach(b => b.setAttribute("aria-pressed", String(b.classList.contains("active"))));
  renderAll();
})();
