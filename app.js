document.addEventListener("DOMContentLoaded", () => {
  // Form & Button Elements
  const iocForm = document.getElementById("ioc-form");
  const iocInput = document.getElementById("ioc-input");
  const sampleButtons = document.querySelectorAll(".sample-btn[data-ioc]");
  const logForm = document.getElementById("log-form");
  const logFileInput = document.getElementById("log-file");
  const loadSampleLogBtn = document.getElementById("load-sample-log");
  const exportCsvBtn = document.getElementById("export-csv-btn");

  // KPI Metric Elements
  const riskScoreEl = document.getElementById("risk-score");
  const riskLabelEl = document.getElementById("risk-label");
  const totalEventsEl = document.getElementById("total-events");
  const failedLoginsEl = document.getElementById("failed-logins");
  const maliciousIpsEl = document.getElementById("malicious-ips");

  // Threat Intel Breakdown Elements
  const intelIspEl = document.getElementById("intel-isp");
  const intelCountryEl = document.getElementById("intel-country");
  const intelAbuseEl = document.getElementById("intel-abuse");
  const intelVtEl = document.getElementById("intel-vt");
  const intelMitreEl = document.getElementById("intel-mitre");

  // Table & Chart Elements
  const eventsTbody = document.getElementById("events-tbody");
  const chartCanvas = document.getElementById("traffic-chart");
  let trafficChart = null;
  let currentEvents = [];

  // Initialize Chart.js Timeline
  function initChart(labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"], dataPoints = [0, 0, 0, 0, 0, 0]) {
    if (trafficChart) {
      trafficChart.destroy();
    }

    trafficChart = new Chart(chartCanvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Failed Logins / Anomalies",
            data: dataPoints,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.15)",
            borderWidth: 2,
            tension: 0.3,
            fill: true,
            pointRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { precision: 0 },
          },
        },
      },
    });
  }

  // Render initial empty chart
  initChart();

  // Helper: Update KPI Cards
  function updateMetrics(metrics) {
    riskScoreEl.textContent = `${metrics.risk_score} / 100`;
    riskLabelEl.textContent = metrics.risk_label;
    totalEventsEl.textContent = metrics.total_events;
    failedLoginsEl.textContent = metrics.failed_logins;
    maliciousIpsEl.textContent = metrics.malicious_ips;

    // Color-code risk label
    riskLabelEl.className = "status-tag";
    if (metrics.risk_score >= 70) {
      riskLabelEl.style.backgroundColor = "#dc2626";
      riskLabelEl.style.color = "#ffffff";
    } else if (metrics.risk_score >= 30) {
      riskLabelEl.style.backgroundColor = "#f59e0b";
      riskLabelEl.style.color = "#000000";
    } else {
      riskLabelEl.style.backgroundColor = "#16a34a";
      riskLabelEl.style.color = "#ffffff";
    }
  }

  // Helper: Update Threat Intel Breakdown
  function updateIntelBreakdown(intel) {
    intelIspEl.textContent = intel.isp || "—";
    intelCountryEl.textContent = intel.country || "—";
    intelAbuseEl.textContent = intel.abuse_confidence || "—";
    intelVtEl.textContent = intel.vt_detections || "—";
    intelMitreEl.textContent = intel.mitre_attack || "—";
  }

  // Helper: Render Events Table Safely (Prevents XSS via textContent)
  function renderEventsTable(events) {
    currentEvents = events;
    eventsTbody.innerHTML = "";

    if (!events || events.length === 0) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 5;
      cell.className = "empty-state";
      cell.textContent = "No suspicious events detected for this input.";
      row.appendChild(cell);
      eventsTbody.appendChild(row);
      return;
    }

    events.forEach((ev) => {
      const row = document.createElement("tr");

      const fields = [ev.timestamp, ev.source_ip, ev.event_type, ev.target, ev.severity];
      fields.forEach((text, index) => {
        const td = document.createElement("td");
        td.textContent = text;
        if (index === 4) {
          td.style.fontWeight = "bold";
          if (text === "High" || text === "Critical") td.style.color = "#ef4444";
          else if (text === "Medium") td.style.color = "#f59e0b";
          else td.style.color = "#22c55e";
        }
        row.appendChild(td);
      });

      eventsTbody.appendChild(row);
    });
  }

  // 1. Handle IP / URL Lookup Form Submit
  async function scanIndicator(iocValue) {
    riskLabelEl.textContent = "Scanning...";
    try {
      const response = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: iocValue }),
      });

      if (!response.ok) throw new Error("Lookup request failed");
      const data = await response.json();

      updateMetrics(data.metrics);
      updateIntelBreakdown(data.intel);
      renderEventsTable(data.events);
      initChart(data.timeline.labels, data.timeline.counts);
    } catch (error) {
      console.error(error);
      riskLabelEl.textContent = "Error Scanning IOC";
    }
  }

  iocForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const val = iocInput.value.trim();
    if (val) scanIndicator(val);
  });

  // Handle Sample IP Buttons (8.8.8.8 & 185.220.101.4)
  sampleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sampleIoc = btn.getAttribute("data-ioc");
      iocInput.value = sampleIoc;
      scanIndicator(sampleIoc);
    });
  });

  // 2. Handle Server Log File Upload
  logForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = logFileInput.files[0];
    if (!file) {
      alert("Please select a .log, .txt, or .csv file first.");
      return;
    }

    const formData = new FormData();
    formData.append("logfile", file);
    riskLabelEl.textContent = "Analyzing Log...";

    try {
      const response = await fetch("/api/analyze-log", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) throw new Error("Log analysis failed");
      const data = await response.json();

      updateMetrics(data.metrics);
      updateIntelBreakdown(data.intel);
      renderEventsTable(data.events);
      initChart(data.timeline.labels, data.timeline.counts);
    } catch (error) {
      console.error(error);
      riskLabelEl.textContent = "Log Parse Error";
    }
  });

  // Handle "Load Sample SSH Brute-Force Log" Button
  loadSampleLogBtn.addEventListener("click", async () => {
    riskLabelEl.textContent = "Loading Sample...";
    try {
      const response = await fetch("/api/sample-log");
      if (!response.ok) throw new Error("Failed to load sample log");
      const data = await response.json();

      updateMetrics(data.metrics);
      updateIntelBreakdown(data.intel);
      renderEventsTable(data.events);
      initChart(data.timeline.labels, data.timeline.counts);
    } catch (error) {
      console.error(error);
      riskLabelEl.textContent = "Sample Load Error";
    }
  });

  // 3. Export Flagged Events Table to CSV
  exportCsvBtn.addEventListener("click", () => {
    if (!currentEvents.length) {
      alert("No events available to export.");
      return;
    }

    const headers = ["Timestamp", "Source IP", "Event Type", "Target User / Endpoint", "Severity"];
    const csvRows = [
      headers.join(","),
      ...currentEvents.map((ev) =>
        [ev.timestamp, ev.source_ip, ev.event_type, ev.target, ev.severity]
          .map((field) => `"${String(field).replace(/"/g, '""')}"`)
          .join(",")
      ),
    ];

    const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threatlens-report-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  });
});
