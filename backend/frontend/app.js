/* ==============================================================================
   Logic: app.js
   Purpose: Interactive Dashboard Controllers, API integration with Railway, fallback mock data.
   ============================================================================== */

// Se auto-detecta la URL si está alojado en el mismo servidor (como en Railway).
// Si lo corres separado, puedes reemplazarlo con la URL fija (ej. "https://f5.up.railway.app").
const BACKEND_API_URL = window.location.origin;

// --- 1. Base de datos de respaldo (Mock Data) por si el backend está offline ---
const MOCK_DEVICES_DATA = {
    "bigip-01.local": {
        hostname: "bigip-01.local",
        last_scan: "Hace 10 minutos (Hoy, 17:15:32)",
        health_score: 88,
        stats: { critical: 2, warning: 4, info: 6, cves: 3 },
        resourceHistory: {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            cpu: [34, 45, 55, 38, 42, 28, 30],
            ram: [68, 70, 72, 71, 74, 65, 66]
        },
        connectionsHistory: {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            active: [1200, 1450, 1900, 1550, 1700, 950, 1100]
        },
        heuristics: [
            {
                id: "H00123",
                severity: "critical",
                title: "Certificado SSL Expirado en Virtual Server 'vs_portal_prod'",
                category: "Local Traffic Manager",
                cve: null,
                description: "El certificado digital ssl_prod_cert asociado al perfil client-ssl en el Virtual Server '/Common/vs_portal_prod' expirará en menos de 5 días.",
                solution: "Renueve el certificado SSL a través de su autoridad certificadora (CA) e impórtelo al F5 BIG-IP."
            },
            {
                id: "H00456",
                severity: "critical",
                title: "Vulnerabilidad de Seguridad CVE-2023-46747: Ejecución Remota de Código",
                category: "Security & Vulnerability",
                cve: "CVE-2023-46747",
                description: "Se detectó que el firmware activo de BIG-IP (17.5.1.6) es vulnerable a un ataque de omisión de autenticación en la interfaz de configuración.",
                solution: "Aplique el Hotfix oficial proporcionado por F5 para la versión 17.5.1.6."
            }
        ]
    }
};

let activeFilter = "all";
let isBackendOnline = false;
let currentDevices = [];

// --- 2. Inicialización del Dashboard ---
document.addEventListener("DOMContentLoaded", () => {
    checkBackendConnection();
    // Mantener la página sincronizada en vivo de forma constante cada 30 segundos
    setInterval(() => {
        if (isBackendOnline) {
            loadRealDevices();
        }
    }, 30000);
});

// Comprobar si el backend en Railway está respondiendo
async function checkBackendConnection() {
    try {
        const response = await fetch(`${BACKEND_API_URL}/health`, { timeout: 4000 });
        if (response.ok) {
            console.log("Conectado exitosamente al backend en Railway:", BACKEND_API_URL);
            isBackendOnline = true;
            document.querySelector(".device-status-badge").innerHTML = `<span class="pulse-dot"></span><span>Nube Railway Conectada</span>`;
            loadRealDevices();
        } else {
            throw new Error("Backend offline");
        }
    } catch (error) {
        console.warn("No se pudo conectar al backend en Railway. Usando modo de demostración local con datos de prueba.");
        document.querySelector(".device-status-badge").innerHTML = `<span class="pulse-dot" style="background-color: #f59e0b; box-shadow: 0 0 8px #f59e0b;"></span><span style="color: #f59e0b;">Modo Demo (Backend Offline)</span>`;
        loadMockData();
    }
}

// Cargar dispositivos reales desde la base de datos de Railway
async function loadRealDevices() {
    try {
        const response = await fetch(`${BACKEND_API_URL}/api/devices`);
        const devices = await response.json();
        currentDevices = devices;
        
        const selector = document.getElementById("device-selector");
        selector.innerHTML = ""; // Limpiar selector
        
        if (devices.length === 0) {
            selector.innerHTML = `<option value="">Sin dispositivos</option>`;
            document.getElementById("alerts-list").innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-triangle-exclamation"></i> Conectado a Railway, pero aún no se han subido QKViews desde el F5.</div>`;
            return;
        }

        devices.forEach(dev => {
            const opt = document.createElement("option");
            opt.value = dev.hostname;
            let statusText = "Desconocido";
            if (dev.status === "processing") statusText = "Procesando...";
            else if (dev.status === "failed") statusText = "Fallo";
            else if (dev.status === "completed") statusText = "Listo";
            opt.innerText = `${dev.hostname} (${statusText})`;
            selector.appendChild(opt);
        });

        // Cargar datos del primer dispositivo
        loadRealDeviceData(devices[0].hostname);

        // Event listener para el selector
        selector.onchange = (e) => loadRealDeviceData(e.target.value);

        // Si hay algún dispositivo procesándose, programar sondeo automático en 8 segundos
        const hasProcessing = devices.some(dev => dev.status === "processing");
        if (hasProcessing) {
            console.log("Detectado dispositivo en procesamiento. Programando recarga en 8 segundos...");
            setTimeout(loadRealDevices, 8000);
        }

    } catch (err) {
        console.error("Error al cargar dispositivos reales:", err);
    }
}

// Cargar datos detallados y heurísticas desde la API de Railway
async function loadRealDeviceData(hostname) {
    try {
        const devMeta = currentDevices.find(d => d.hostname === hostname);
        if (!devMeta) return;

        // Actualizar datos del encabezado y contadores
        document.getElementById("lbl-hostname").innerText = devMeta.hostname;
        document.getElementById("lbl-last-scan").innerText = devMeta.last_scan;
        
        // --- Escenario 1: El dispositivo está procesando el QKView en iHealth ---
        if (devMeta.status === "processing") {
            document.getElementById("lbl-health-score").innerText = "--";
            document.getElementById("lbl-critical-count").innerText = "0";
            document.getElementById("lbl-warning-count").innerText = "0";
            document.getElementById("lbl-cve-count").innerText = "0";
            setProgressRing(0);
            
            document.getElementById("alerts-list").innerHTML = `
                <div class="loading-spinner" style="flex-direction: column; gap: 20px; padding: 45px 20px; width: 100%;">
                    <i class="fa-solid fa-arrows-spin fa-spin fa-3x" style="color: #3b82f6;"></i>
                    <div style="text-align: center;">
                        <p style="font-weight: 600; color: #fff; margin-bottom: 8px; font-size: 16px;">Analizando QKView en F5 iHealth...</p>
                        <p style="font-size: 13px; color: #9ca3af; max-width: 440px; margin: 0 auto; line-height: 1.5;">
                            El servidor de tránsito recibió el archivo correctamente y lo está enviando a la API oficial de iHealth para su análisis de seguridad. 
                            Este proceso suele tomar entre 2 y 5 minutos. La pantalla se actualizará sola cuando termine.
                        </p>
                    </div>
                </div>
            `;
            
            // Dibujar gráficas vacías durante la carga
            const emptyHistory = { labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], cpu: [0,0,0,0,0,0,0], ram: [0,0,0,0,0,0,0] };
            initResourceChart(emptyHistory);
            initConnectionsChart({ labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], active: [0,0,0,0,0,0,0] });
            return;
        }

        // --- Escenario 2: El análisis falló ---
        if (devMeta.status === "failed") {
            document.getElementById("lbl-health-score").innerText = "Error";
            document.getElementById("lbl-critical-count").innerText = "--";
            document.getElementById("lbl-warning-count").innerText = "--";
            document.getElementById("lbl-cve-count").innerText = "--";
            setProgressRing(0);
            
            const errMsg = devMeta.error_message || "Fallo en la comunicación o credenciales de la API de iHealth.";
            document.getElementById("alerts-list").innerHTML = `
                <div class="loading-spinner" style="flex-direction: column; gap: 20px; padding: 45px 20px; width: 100%;">
                    <i class="fa-solid fa-circle-xmark fa-3x" style="color: #ef4444;"></i>
                    <div style="text-align: center;">
                        <p style="font-weight: 600; color: #fff; margin-bottom: 8px; font-size: 16px;">Error al Procesar Diagnóstico</p>
                        <p style="font-size: 13px; color: #f87171; max-width: 440px; margin: 0 auto; background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; border: 1px solid rgba(239, 68, 68, 0.2); line-height: 1.5; font-family: monospace;">
                            ${errMsg}
                        </p>
                        <p style="font-size: 12px; color: #9ca3af; margin-top: 15px; max-width: 400px; margin-left: auto; margin-right: auto;">
                            Por favor, revise en el dashboard de Railway que las variables <code style="color: #f3f4f6; background: #374151; padding: 2px 4px; border-radius: 4px;">F5_IHEALTH_CLIENT_ID</code> y <code style="color: #f3f4f6; background: #374151; padding: 2px 4px; border-radius: 4px;">F5_IHEALTH_CLIENT_SECRET</code> sean correctas y que sus API credentials tengan permisos activos.
                        </p>
                    </div>
                </div>
            `;
            
            const emptyHistory = { labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], cpu: [0,0,0,0,0,0,0], ram: [0,0,0,0,0,0,0] };
            initResourceChart(emptyHistory);
            initConnectionsChart({ labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], active: [0,0,0,0,0,0,0] });
            return;
        }

        // --- Escenario 3: El análisis se completó exitosamente ---
        document.getElementById("lbl-health-score").innerText = devMeta.health_score;
        document.getElementById("lbl-critical-count").innerText = devMeta.stats.critical;
        document.getElementById("lbl-warning-count").innerText = devMeta.stats.warning;
        document.getElementById("lbl-cve-count").innerText = devMeta.stats.cves;
        setProgressRing(devMeta.health_score);

        // Llamar a la API para obtener el JSON completo de diagnósticos
        const response = await fetch(`${BACKEND_API_URL}/api/diagnostics/${hostname}`);
        const diagData = await response.json();
        
        // Parsear heurísticas
        const rawHits = diagData.diagnostic_results?.diagnostic_result || [];
        const hits = Array.isArray(rawHits) ? rawHits : (rawHits ? [rawHits] : []);

        // Adaptar formato de iHealth a la interfaz
        const heuristics = hits.map(hit => ({
            id: hit.id || "N/A",
            severity: (hit.severity || "info").toLowerCase(),
            title: hit.title || "Alerta sin título",
            category: hit.category || "General",
            cve: hit.cve || null,
            description: hit.description || "Sin descripción detallada.",
            solution: hit.solution || "Consulte la documentación de F5 para este ID."
        }));

        renderHeuristics(heuristics);

        // Generar historial de recursos simulados basados en el estado del equipo
        const simulatedHistory = {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            cpu: [20, 25, 30, 28, 32, 22, 25].map(v => Math.min(95, v + (devMeta.stats.critical * 8))),
            ram: [55, 57, 58, 60, 62, 55, 56].map(v => Math.min(98, v + (devMeta.stats.warning * 3)))
        };
        initResourceChart(simulatedHistory);

        const simulatedConnections = {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            active: [500, 600, 750, 680, 800, 450, 480].map(v => v * (devMeta.stats.info + 1))
        };
        initConnectionsChart(simulatedConnections);

    } catch (err) {
        console.error("Error al cargar diagnósticos del dispositivo:", err);
    }
}

// Carga en Modo Demostración (Offline)
function loadMockData() {
    const selector = document.getElementById("device-selector");
    selector.innerHTML = `<option value="bigip-01.local">bigip-01.local (Modo Demo)</option>`;
    
    const data = MOCK_DEVICES_DATA["bigip-01.local"];
    document.getElementById("lbl-hostname").innerText = data.hostname;
    document.getElementById("lbl-last-scan").innerText = data.last_scan;
    document.getElementById("lbl-health-score").innerText = data.health_score;
    document.getElementById("lbl-critical-count").innerText = data.stats.critical;
    document.getElementById("lbl-warning-count").innerText = data.stats.warning;
    document.getElementById("lbl-cve-count").innerText = data.stats.cves;
    setProgressRing(data.health_score);

    renderHeuristics(data.heuristics);
    initResourceChart(data.resourceHistory);
    initConnectionsChart(data.connectionsHistory);

    // Event listeners para filtros
    document.getElementById("btn-filter-all").onclick = () => renderHeuristics(data.heuristics);
    document.getElementById("btn-filter-critical").onclick = () => renderHeuristics(data.heuristics.filter(h=>h.severity==='critical'));
    document.getElementById("btn-filter-warning").onclick = () => renderHeuristics(data.heuristics.filter(h=>h.severity==='warning'));
    document.getElementById("btn-filter-info").onclick = () => renderHeuristics(data.heuristics.filter(h=>h.severity==='info'));
}

// --- 3. Renderizadores Comunes de Interfaz ---

function setProgressRing(score) {
    const circle = document.getElementById("score-ring");
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    
    if (score >= 90) circle.style.stroke = "#10b981";
    else if (score >= 75) circle.style.stroke = "#f59e0b";
    else circle.style.stroke = "#ef4444";
}

function renderHeuristics(heuristicsList) {
    const container = document.getElementById("alerts-list");
    container.innerHTML = "";

    if (heuristicsList.length === 0) {
        container.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Sin alertas para este filtro.</div>`;
        return;
    }

    heuristicsList.forEach(item => {
        const alertItem = document.createElement("div");
        alertItem.className = `alert-item`;
        let cveTag = item.cve ? `<span class="meta-cve"><i class="fa-solid fa-bug"></i> ${item.cve}</span>` : "";
        
        alertItem.innerHTML = `
            <div class="alert-item-header">
                <div class="alert-title-group">
                    <span class="severity-indicator severity-${item.severity}"></span>
                    <span class="alert-title">${item.title}</span>
                </div>
                <i class="fa-solid fa-chevron-down alert-chevron"></i>
            </div>
            <div class="alert-meta">
                <span><i class="fa-solid fa-folder"></i> ${item.category}</span>
                <span><i class="fa-solid fa-fingerprint"></i> ID: ${item.id}</span>
                ${cveTag}
            </div>
            <div class="alert-detail">
                <div class="alert-detail-title">Descripción del Problema</div>
                <p>${item.description}</p>
                <div class="solution-box">
                    <div class="alert-detail-title">Solución Recomendada</div>
                    <p>${item.solution}</p>
                </div>
            </div>
        `;

        alertItem.addEventListener("click", () => {
            alertItem.classList.toggle("expanded");
        });
        container.appendChild(alertItem);
    });
}

// --- 4. Inicialización de Gráficas (Chart.js) ---
function initResourceChart(historyData) {
    const ctx = document.getElementById("resourceChart").getContext("2d");
    if (resourceChartInstance) resourceChartInstance.destroy();
    resourceChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: historyData.labels,
            datasets: [
                { label: 'CPU (%)', data: historyData.cpu, borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', borderWidth: 2, fill: true, tension: 0.3 },
                { label: 'RAM (%)', data: historyData.ram, borderColor: '#a855f7', backgroundColor: 'rgba(168, 85, 247, 0.1)', borderWidth: 2, fill: true, tension: 0.3 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } } },
            scales: {
                x: { grid: { color: 'rgba(75, 85, 99, 0.15)' }, ticks: { color: '#9ca3af' } },
                y: { min: 0, max: 100, grid: { color: 'rgba(75, 85, 99, 0.15)' }, ticks: { color: '#9ca3af' } }
            }
        }
    });
}

function initConnectionsChart(historyData) {
    const ctx = document.getElementById("connectionsChart").getContext("2d");
    if (connectionsChartInstance) connectionsChartInstance.destroy();
    connectionsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: historyData.labels,
            datasets: [{ label: 'Conexiones Activas', data: historyData.active, backgroundColor: 'rgba(16, 185, 129, 0.6)', borderColor: '#10b981', borderWidth: 1, borderRadius: 4 }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#9ca3af' } },
                y: { grid: { color: 'rgba(75, 85, 99, 0.15)' }, ticks: { color: '#9ca3af' } }
            }
        }
    });
}

let resourceChartInstance = null;
let connectionsChartInstance = null;

// Simulación de escaneo manual / forzado
function simulateScan() {
    if (isBackendOnline) {
        alert("El F5 realiza las subidas de QKView de forma programada en producción. Este botón de prueba simula la interacción en modo local.");
    }
    
    const btn = document.getElementById("btn-force-scan");
    const container = document.getElementById("alerts-list");
    const originalHtml = btn.innerHTML;
    
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Subiendo QKView...`;
    
    container.innerHTML = `
        <div class="loading-spinner" style="flex-direction: column; gap: 20px;">
            <i class="fa-solid fa-spinner fa-spin fa-3x" style="color: #3b82f6;"></i>
            <div style="text-align: center;">
                <p style="font-weight: 600; color: #fff; margin-bottom: 6px;">[Tránsito] Subiendo QKView al iHealth API...</p>
                <p style="font-size: 12px; color: #9ca3af;">Simulando comunicación cifrada HTTPS y parseo.</p>
            </div>
        </div>
    `;

    setTimeout(() => {
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analizando Heurísticas...`;
        container.innerHTML = `
            <div class="loading-spinner" style="flex-direction: column; gap: 20px;">
                <i class="fa-solid fa-arrows-spin fa-spin fa-3x" style="color: #a855f7;"></i>
                <div style="text-align: center;">
                    <p style="font-weight: 600; color: #fff; margin-bottom: 6px;">[iHealth] Generando diagnóstico heurístico...</p>
                    <p style="font-size: 12px; color: #9ca3af;">Procesando coincidencias de Bugs y vulnerabilidades CVE.</p>
                </div>
            </div>
        `;
        
        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
            loadMockData();
        }, 1500);
    }, 1500);
}
