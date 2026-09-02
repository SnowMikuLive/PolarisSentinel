(async function () {
    const byId = (id) => document.getElementById(id);

    const info = await fetch("/api/demo/info").then(r => r.json()).catch(() => null);
    if (info) {
        byId("model-info").textContent =
            `rf_model.onnx | classes: ${info.classes.join(", ")} | ` +
            `alert \u2265 ${info.rfThreshold} | block \u2265 ${info.blockThreshold}`;
    }

    const counts = { flows: 0, benign: 0, alerts: 0, blocks: 0, DoS: 0, PortScan: 0, BruteForce: 0 };

    function render() {
        byId("c-flows").textContent = counts.flows;
        byId("c-benign").textContent = counts.benign;
        byId("c-alerts").textContent = counts.alerts;
        byId("c-blocks").textContent = counts.blocks;
        byId("c-dos").textContent = counts.DoS;
        byId("c-portscan").textContent = counts.PortScan;
        byId("c-bruteforce").textContent = counts.BruteForce;
    }

    function addRow(d) {
        const body = byId("det-body");
        const row = body.insertRow(0);
        row.className = d.tier === "block" ? "table-danger"
            : d.tier === "alert" ? "table-warning" : "";
        const badge = d.tier === "block" ? '<span class="badge bg-danger">BLOCK-ELIGIBLE</span>'
            : d.tier === "alert" ? '<span class="badge bg-warning text-dark">ALERT</span>'
            : '<span class="badge bg-secondary">LOW CONFIDENCE</span>';
        row.innerHTML =
            `<td>${d.time}</td><td>${d.sourceIp}</td><td>${d.destinationPort}</td>` +
            `<td>${d.attackType}</td><td>${(d.confidence * 100).toFixed(1)}%</td><td>${badge}</td>`;
        while (body.rows.length > 15) body.deleteRow(15);
    }

    const connection = new signalR.HubConnectionBuilder()
        .withUrl("/hubs/detections")
        .withAutomaticReconnect()
        .build();

    connection.on("detection", (d) => {
        counts.flows++;
        if (d.attackType === "Benign") {
            counts.benign++;
        } else {
            counts[d.attackType] = (counts[d.attackType] || 0) + 1;
            if (d.tier === "block") { counts.blocks++; counts.alerts++; }
            else if (d.tier === "alert") { counts.alerts++; }
            addRow(d);
        }
        render();
    });

    const state = byId("conn-state");
    connection.onreconnecting(() => { state.textContent = "reconnecting…"; state.className = "badge bg-warning text-dark"; });
    connection.onreconnected(() => { state.textContent = "live"; state.className = "badge bg-success"; });

    await connection.start();
    state.textContent = "live";
    state.className = "badge bg-success";
})();
