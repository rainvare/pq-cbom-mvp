/* Demo interactiva: replica pq_cbom/risk_model.py en el navegador sobre el
   CBOM de ejemplo generado por el propio escáner. */
(function () {
  "use strict";

  var CBOM = window.SAMPLE_CBOM || { entries: [] };
  var KB = window.KNOWLEDGE || { algorithms: [] };
  var entries = CBOM.entries || [];

  var STATUS_WEIGHT = { vulnerable: 10, at_risk: 5, unknown: 2, secure: 0 };
  var MAX_OCC = 10;
  var STATUS_ORDER = ["vulnerable", "at_risk", "unknown", "secure"];
  var STATUS_LABEL = { vulnerable: "Vulnerable", at_risk: "En riesgo", unknown: "Desconocido", secure: "Seguro" };

  // ---- agregaciones base ----
  function countsByStatus() {
    var c = {};
    entries.forEach(function (e) {
      var s = e.classification.pq_status;
      c[s] = (c[s] || 0) + 1;
    });
    return c;
  }

  function hndlEntries() {
    return entries.filter(function (e) {
      return e.classification.pq_status === "vulnerable" && e.classification.category === "asymmetric";
    });
  }

  function riskIndex(counts, hndlCount, moscaAtRisk) {
    var penalty = 0;
    Object.keys(STATUS_WEIGHT).forEach(function (s) {
      var w = STATUS_WEIGHT[s], c = counts[s] || 0;
      if (c && w) penalty += w * Math.min(c, MAX_OCC);
    });
    penalty += 8 * Math.min(hndlCount, 5);
    var idx = Math.min(100, Math.round(penalty));
    if (moscaAtRisk && hndlCount > 0) idx = Math.max(idx, 70);
    return idx;
  }

  function riskBand(idx) {
    if (idx >= 70) return "critical";
    if (idx >= 45) return "high";
    if (idx >= 20) return "medium";
    if (idx > 0) return "low";
    return "none";
  }

  function mosca(x, y, z) {
    var collapse = x + y - z;
    return { x: x, y: y, z: z, collapse: collapse, atRisk: collapse > 0 };
  }

  // ---- render KPIs ----
  function renderKpis(counts, hndlCount, idx, band) {
    var total = entries.length;
    var secure = counts.secure || 0;
    var readiness = total === 0 ? 100 : Math.round((100 * secure) / total);
    var kpis = [
      { v: total, l: "Activos cripto inventariados", cls: "" },
      { v: readiness + "%", l: "Preparación cuántica", cls: readiness >= 60 ? "good" : "bad" },
      { v: idx + "/100", l: "Índice de riesgo (" + band + ")", cls: idx >= 45 ? "bad" : idx >= 20 ? "warn" : "good" },
      { v: hndlCount, l: "Exposición HNDL (asimétrico roto)", cls: hndlCount ? "bad" : "good" }
    ];
    document.getElementById("kpis").innerHTML = kpis.map(function (k) {
      return '<div class="kpi ' + k.cls + '"><div class="v">' + k.v + '</div><div class="l">' + k.l + "</div></div>";
    }).join("");
    return readiness;
  }

  // ---- render donut + barras ----
  function renderReadiness(readiness, counts) {
    var deg = Math.round((readiness / 100) * 360);
    var donut = document.getElementById("donut");
    var color = readiness >= 60 ? "var(--secure)" : readiness >= 30 ? "var(--at-risk)" : "var(--vuln)";
    donut.style.background = "conic-gradient(" + color + " " + deg + "deg, var(--bg-soft) " + deg + "deg)";
    document.getElementById("donutPct").textContent = readiness + "%";

    var total = entries.length || 1;
    var html = "";
    STATUS_ORDER.forEach(function (s) {
      var c = counts[s] || 0;
      var pct = Math.round((100 * c) / total);
      html += '<div class="bar-row"><span class="name">' + STATUS_LABEL[s] +
        '</span><span class="track"><span class="fill ' + s + '" style="width:' + pct + '%"></span></span>' +
        '<span class="cnt">' + c + "</span></div>";
    });
    document.getElementById("statusBars").innerHTML = html;
  }

  // ---- render Mosca ----
  function renderMosca(m) {
    document.getElementById("moscaEq").textContent =
      "X + Y − Z  =  " + m.x + " + " + m.y + " − " + m.z + "  =  " + m.collapse + " años";
    var v = document.getElementById("moscaVerdict");
    if (m.atRisk) {
      v.className = "verdict risk";
      v.innerHTML = "<b>EN RIESGO</b> — X+Y supera Z en <b>" + m.collapse +
        " año(s)</b>. Datos protegidos hoy con criptografía clásica podrían descifrarse antes de completar la migración.";
    } else {
      v.className = "verdict safe";
      v.innerHTML = "<b>Margen de " + (-m.collapse) +
        " año(s)</b> — la migración cabe antes del Q-day estimado, pero el margen se reduce cada año que se pospone.";
    }
  }

  // ---- top risks (HNDL) ----
  function renderTopRisks() {
    var rows = hndlEntries().slice(0, 8).map(function (e) {
      var c = e.classification;
      return "<tr><td><b>" + c.rule_id + "</b></td>" +
        '<td><span class="pill ' + c.pq_status + '">' + STATUS_LABEL[c.pq_status] + "</span></td>" +
        '<td class="loc">' + e.crypto_asset.location + "</td>" +
        "<td>" + (c.replacement || "–") + "</td></tr>";
    }).join("");
    document.getElementById("topRisks").innerHTML = rows || '<tr><td colspan="4">Sin exposición HNDL 🎉</td></tr>';
  }

  // ---- roadmap ----
  function renderRoadmap() {
    var bands = {};
    entries.forEach(function (e) {
      if (e.classification.pq_status === "secure") return;
      var b = e.priority.band;
      if (!bands[b]) bands[b] = { count: 0, action: e.priority.recommended_action, algos: {} };
      bands[b].count++;
      bands[b].algos[e.classification.rule_id] = true;
    });
    var order = ["critical", "high", "medium", "low"];
    var html = order.filter(function (b) { return bands[b]; }).map(function (b) {
      var s = bands[b];
      return "<tr><td><span class='pill " + b + "'>" + b + "</span></td>" +
        "<td>" + s.count + "</td><td>" + s.action + "</td>" +
        "<td class='loc'>" + Object.keys(s.algos).sort().join(", ") + "</td></tr>";
    }).join("");
    document.getElementById("roadmap").innerHTML = html || '<tr><td colspan="4">Todo seguro</td></tr>';
  }

  // ---- knowledge base table ----
  function renderKb(filter) {
    var q = (filter || "").toLowerCase();
    var rows = (KB.algorithms || []).filter(function (a) {
      if (!q) return true;
      var hay = [a.id, a.name, a.family, a.pq_status, a.math_problem, a.quantum_attack, a.nist_status]
        .concat(a.aliases || []).join(" ").toLowerCase();
      return hay.indexOf(q) !== -1;
    }).map(function (a) {
      return "<tr><td><b>" + a.id + "</b></td><td>" + a.family + "</td>" +
        '<td><span class="pill ' + a.pq_status + '">' + (STATUS_LABEL[a.pq_status] || a.pq_status) + "</span></td>" +
        "<td>" + (a.quantum_attack || "–") + "</td><td>" + (a.nist_status || "–") + "</td>" +
        "<td>" + (a.replacement || "–") + "</td></tr>";
    }).join("");
    document.getElementById("kbTable").innerHTML = rows || '<tr><td colspan="6">Sin coincidencias</td></tr>';
  }

  // ---- recompute all (on slider change) ----
  function recompute() {
    var x = +document.getElementById("x").value;
    var y = +document.getElementById("y").value;
    var z = +document.getElementById("z").value;
    document.getElementById("xv").textContent = x;
    document.getElementById("yv").textContent = y;
    document.getElementById("zv").textContent = z;

    var counts = countsByStatus();
    var hndl = hndlEntries().length;
    var m = mosca(x, y, z);
    var idx = riskIndex(counts, hndl, m.atRisk);
    var band = riskBand(idx);

    var readiness = renderKpis(counts, hndl, idx, band);
    renderReadiness(readiness, counts);
    renderMosca(m);
  }

  // ---- tabs ----
  function initTabs() {
    var tabs = document.querySelectorAll(".tab");
    tabs.forEach(function (t) {
      t.addEventListener("click", function () {
        var name = t.getAttribute("data-tab");
        tabs.forEach(function (x) { x.classList.remove("active"); });
        t.classList.add("active");
        document.querySelectorAll(".tab-body").forEach(function (b) {
          b.classList.toggle("active", b.getAttribute("data-tab") === name);
        });
      });
    });
  }

  // ---- init ----
  ["x", "y", "z"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", recompute);
  });
  document.getElementById("kbSearch").addEventListener("input", function (e) { renderKb(e.target.value); });

  recompute();
  renderTopRisks();
  renderRoadmap();
  renderKb("");
  initTabs();
})();
