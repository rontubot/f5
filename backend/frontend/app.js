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
let currentHeuristics = [];
let cveSearchQuery = "";
let cveSeverityFilter = "all";
let selectedHeuristicId = null;
let currentLogType = "files";
let allLogItems = [];
let selectedLogItemId = null;
let selectedLogItemName = "";
let logSearchQuery = "";
let logTextSearchQuery = "";
let rawLogContent = "";

// --- 2. Inicialización del Dashboard ---
document.addEventListener("DOMContentLoaded", () => {
    checkBackendConnection();
    setupTabs();
    setupSettingsPage();
    setupCveFilters();
    setupLogExplorerEvents();
    setupDragAndDrop();
    // Mantener la página sincronizada en vivo de forma constante cada 30 segundos
    setInterval(() => {
        if (isBackendOnline && !rapidPollingInterval) {
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
        
        // Parsear y guardar metadatos de sistema
        const versionData = diagData.version || {};
        const sha1 = diagData.sha1 || "";
        renderSystemProfile(versionData, sha1);

        // Procesar heurísticas y guardarlas en variable global
        currentHeuristics = processDiagnosticsData(diagData);

        // Renderizar heurísticas en Vista General
        renderHeuristics(currentHeuristics);

        // Renderizar CVEs y actualizar KPIs
        const cveHeuristics = currentHeuristics.filter(h => h.cve !== null);
        updateCveKpis(cveHeuristics);
        renderCves();

        // Renderizar selector de hitos/heurísticas en pestaña Hitos
        renderHeuristicsSelector();

        // Limpiar logs y volver a cargarlos para el nuevo dispositivo
        allLogItems = [];
        selectedLogItemId = null;
        selectedLogItemName = "";
        rawLogContent = "";
        const logContainer = document.getElementById("log-viewer-container");
        if (logContainer) {
            logContainer.innerHTML = `
                <i class="fa-solid fa-file-lines fa-3x" style="margin-bottom: 15px; color: var(--border-color);"></i>
                <p>Seleccione un archivo de log o comando de la lista de la izquierda para ver su contenido aquí.</p>
            `;
            document.getElementById("log-viewer-title").innerText = "Visor de Logs";
        }
        
        // Si estamos actualmente en la pestaña de logs, forzar recarga
        const btnLogs = document.getElementById("btn-logs");
        if (btnLogs && btnLogs.classList.contains("active")) {
            loadDeviceLogItems();
        }

        // Actualizar curl en Settings
        const curlPre = document.getElementById("curl-code-command");
        if (curlPre) {
            curlPre.innerText = `curl -X POST -H "Authorization: Bearer BirraverdePCtoken" -F "qkview=@/ruta/al/archivo.qkview" ${BACKEND_API_URL}/api/upload`;
        }

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

    // Guardar en global
    currentHeuristics = data.heuristics.map(h => {
        return {
            id: h.id,
            severity: h.severity,
            importance: h.severity === 'critical' ? 'critical' : h.severity === 'warning' ? 'high' : 'info',
            title: h.title,
            category: h.category,
            cve: h.cve,
            description: h.description,
            solution: h.solution,
            output: h.id === 'H00456' ? [
                "Matching config: /Common/vs_portal_prod is vulnerable.",
                "Line 43: client-ssl profile associated.",
                "WARNING: CVE-2023-46747 vulnerability detected in BIG-IP firmware version 17.5.1.6!"
            ] : [],
            fixedInVersions: { version: [{ major: 17, minor: 5, maintenance: 1, point: 7, fix: "" }] }
        };
    });

    renderHeuristics(currentHeuristics);
    
    const cveHeuristics = currentHeuristics.filter(h => h.cve !== null);
    updateCveKpis(cveHeuristics);
    renderCves();
    
    renderHeuristicsSelector();
    renderSystemProfile({ product: "BIG-IP (Demo)", version: "17.5.1.6", edition: "Virtual Edition", built: "20231102" }, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    initResourceChart(data.resourceHistory);
    initConnectionsChart(data.connectionsHistory);

    // Event listeners para filtros de la vista general
    document.getElementById("btn-filter-all").onclick = () => renderHeuristics(currentHeuristics);
    document.getElementById("btn-filter-critical").onclick = () => renderHeuristics(currentHeuristics.filter(h=>h.severity==='critical'));
    document.getElementById("btn-filter-warning").onclick = () => renderHeuristics(currentHeuristics.filter(h=>h.severity==='warning'));
    document.getElementById("btn-filter-info").onclick = () => renderHeuristics(currentHeuristics.filter(h=>h.severity==='info'));
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

// --- 5. Lógica de Pestañas y Vistas ---
function setupTabs() {
    const tabs = [
        { btn: "btn-overview", page: "page-overview" },
        { btn: "btn-cves", page: "page-cves" },
        { btn: "btn-heuristics", page: "page-heuristics" },
        { btn: "btn-logs", page: "page-logs" },
        { btn: "btn-settings", page: "page-settings" }
    ];
    
    tabs.forEach(tab => {
        const btnEl = document.getElementById(tab.btn);
        if (btnEl) {
            btnEl.addEventListener("click", (e) => {
                e.preventDefault();
                // Ocultar todas las páginas y desactivar enlaces
                tabs.forEach(t => {
                    const el = document.getElementById(t.btn);
                    if (el) el.classList.remove("active");
                    const pg = document.getElementById(t.page);
                    if (pg) pg.classList.add("hidden");
                });
                
                // Activar actual
                btnEl.classList.add("active");
                const pageEl = document.getElementById(tab.page);
                if (pageEl) pageEl.classList.remove("hidden");
                
                // Cargar ítems de log si se selecciona esa pestaña
                if (tab.page === "page-logs") {
                    loadDeviceLogItems();
                }
                
                // Redimensionar gráficos para evitar problemas de ancho al volver
                if (tab.page === "page-overview") {
                    window.dispatchEvent(new Event('resize'));
                }
            });
        }
    });
}

// --- 6. Lógica de CVEs y Filtros ---
function setupCveFilters() {
    const searchInput = document.getElementById("cve-search-input");
    const severityFilter = document.getElementById("cve-severity-filter");
    
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            cveSearchQuery = e.target.value.toLowerCase();
            renderCves();
        });
    }
    
    if (severityFilter) {
        severityFilter.addEventListener("change", (e) => {
            cveSeverityFilter = e.target.value;
            renderCves();
        });
    }
}

function processDiagnosticsData(diagData) {
    const rawHits = diagData.diagnostics?.diagnostic || [];
    const hits = Array.isArray(rawHits) ? rawHits : (rawHits ? [rawHits] : []);
    const matchedHits = hits.filter(hit => hit.run_data?.match === true);
    
    return matchedHits.map(hit => {
        const results = hit.results || {};
        const importance = (hit.run_data?.h_importance || "info").toLowerCase();
        
        let uiSeverity = "info";
        if (importance === "high" || importance === "critical") {
            uiSeverity = "critical";
        } else if (importance === "medium") {
            uiSeverity = "warning";
        }
        
        const cvesList = results.h_cve_ids || [];
        const cveString = cvesList.length > 0 ? cvesList.join(", ") : null;
        
        const solutionLinks = results.solution || [];
        const linkUrl = solutionLinks.length > 0 ? solutionLinks[0].value : "";
        let solutionText = results.h_action || "";
        if (linkUrl) {
            solutionText += `\n\nReferencia oficial AskF5: ${linkUrl}`;
        }
        
        let category = "Tráfico Local (LTM)";
        const hitName = hit.name || "";
        if (hitName.startsWith("H")) {
            category = "Configuración GTM/DNS";
        } else if (cveString || results.h_header?.toLowerCase().includes("vulnerability") || results.h_header?.toLowerCase().includes("cve")) {
            category = "Seguridad (CVE)";
        } else if (results.h_header?.toLowerCase().includes("profile") || results.h_header?.toLowerCase().includes("tcp")) {
            category = "Perfiles de Protocolo";
        } else {
            category = "Optimización de Sistema";
        }
        
        return {
            id: hit.name || results.h_name || "N/A",
            severity: uiSeverity,
            importance: importance,
            title: results.h_header || "Alerta sin título",
            category: category,
            cve: cveString,
            description: results.h_summary || "Sin descripción detallada.",
            solution: solutionText || "Consulte el artículo oficial de F5.",
            output: hit.output || [],
            fixedInVersions: hit.fixedInVersions || {}
        };
    });
}

function renderCves() {
    const cveContainer = document.getElementById("cve-alerts-list");
    if (!cveContainer) return;
    
    const cveHeuristics = currentHeuristics.filter(h => h.cve !== null);
    
    const filteredCves = cveHeuristics.filter(item => {
        const matchesSearch = item.cve.toLowerCase().includes(cveSearchQuery) || 
                              item.title.toLowerCase().includes(cveSearchQuery) || 
                              item.description.toLowerCase().includes(cveSearchQuery);
        
        let matchesSeverity = true;
        if (cveSeverityFilter !== "all") {
            if (cveSeverityFilter === "medium") {
                matchesSeverity = (item.severity === "warning" || item.severity === "info");
            } else {
                matchesSeverity = (item.severity === cveSeverityFilter);
            }
        }
        return matchesSearch && matchesSeverity;
    });
    
    cveContainer.innerHTML = "";
    
    if (filteredCves.length === 0) {
        cveContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Sin vulnerabilidades registradas para el criterio actual.</div>`;
        return;
    }
    
    filteredCves.forEach(item => {
        const alertItem = document.createElement("div");
        alertItem.className = `alert-item`;
        
        const fixedStr = formatFixedVersions(item.fixedInVersions);
        
        alertItem.innerHTML = `
            <div class="alert-item-header">
                <div class="alert-title-group">
                    <span class="severity-indicator severity-${item.severity}"></span>
                    <span class="alert-title"><strong class="meta-cve" style="margin-right: 8px;">${item.cve}</strong> - ${item.title}</span>
                </div>
                <i class="fa-solid fa-chevron-down alert-chevron"></i>
            </div>
            <div class="alert-meta">
                <span><i class="fa-solid fa-folder"></i> ${item.category}</span>
                <span><i class="fa-solid fa-fingerprint"></i> ID: ${item.id}</span>
                <span style="color: #3b82f6;"><i class="fa-solid fa-wrench"></i> Corregido en: ${fixedStr}</span>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-title">Descripción del Problema</div>
                <p>${item.description}</p>
                <div class="solution-box">
                    <div class="alert-detail-title">Remediación Propuesta</div>
                    <p>${item.solution}</p>
                </div>
            </div>
        `;
        
        alertItem.addEventListener("click", () => {
            alertItem.classList.toggle("expanded");
        });
        cveContainer.appendChild(alertItem);
    });
}

function updateCveKpis(cveHeuristics) {
    const total = cveHeuristics.length;
    let critical = 0;
    let high = 0;
    let mediumLow = 0;
    
    cveHeuristics.forEach(h => {
        if (h.importance === "critical") critical++;
        else if (h.importance === "high") high++;
        else mediumLow++;
    });
    
    const totalEl = document.getElementById("lbl-cve-total");
    const criticalEl = document.getElementById("lbl-cve-critical");
    const highEl = document.getElementById("lbl-cve-high");
    const mediumEl = document.getElementById("lbl-cve-medium");
    
    if (totalEl) totalEl.innerText = total;
    if (criticalEl) criticalEl.innerText = critical;
    if (highEl) highEl.innerText = high;
    if (mediumEl) mediumEl.innerText = mediumLow;
}

// --- 7. Lógica de Explorador de Hitos ---
function renderSystemProfile(versionData, sha1) {
    const prodEl = document.getElementById("prof-product");
    const verEl = document.getElementById("prof-version");
    const editEl = document.getElementById("prof-edition");
    const builtEl = document.getElementById("prof-built");
    const shaEl = document.getElementById("prof-sha");
    
    if (prodEl) prodEl.innerText = versionData.product || "BIG-IP";
    if (verEl) verEl.innerText = versionData.version || "-";
    if (editEl) editEl.innerText = versionData.edition || "-";
    if (builtEl) builtEl.innerText = versionData.built || "-";
    if (shaEl) shaEl.innerText = sha1 || "-";
}

function renderHeuristicsSelector() {
    const listContainer = document.getElementById("heuristics-selector-list");
    if (!listContainer) return;
    
    listContainer.innerHTML = "";
    
    if (currentHeuristics.length === 0) {
        listContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Sin alertas registradas.</div>`;
        return;
    }
    
    currentHeuristics.forEach(item => {
        const selectItem = document.createElement("div");
        selectItem.className = `selector-alert-item`;
        if (selectedHeuristicId === item.id) {
            selectItem.classList.add("selected");
        }
        
        let severityBadgeClass = "badge-info";
        let severityText = "Info";
        if (item.severity === "critical") {
            severityBadgeClass = "badge-critical";
            severityText = "Crítico";
        } else if (item.severity === "warning") {
            severityBadgeClass = "badge-warning";
            severityText = "Advertencia";
        }
        
        selectItem.innerHTML = `
            <div class="selector-alert-item-title" title="${item.title}">${item.title}</div>
            <span class="badge ${severityBadgeClass}">${severityText}</span>
        `;
        
        selectItem.addEventListener("click", () => {
            document.querySelectorAll(".selector-alert-item").forEach(el => el.classList.remove("selected"));
            selectItem.classList.add("selected");
            selectedHeuristicId = item.id;
            renderHeuristicEvidence(item);
        });
        listContainer.appendChild(selectItem);
    });
    
    // Auto-seleccionar el primero si no hay ninguno seleccionado previamente o si cambió el dispositivo
    const exists = currentHeuristics.some(h => h.id === selectedHeuristicId);
    if (currentHeuristics.length > 0 && (!selectedHeuristicId || !exists)) {
        const firstItem = currentHeuristics[0];
        const firstEl = listContainer.querySelector(".selector-alert-item");
        if (firstEl) {
            firstEl.classList.add("selected");
            selectedHeuristicId = firstItem.id;
            renderHeuristicEvidence(firstItem);
        }
    } else if (selectedHeuristicId) {
        const activeItem = currentHeuristics.find(h => h.id === selectedHeuristicId);
        if (activeItem) renderHeuristicEvidence(activeItem);
    }
}

function renderHeuristicEvidence(item) {
    const evidenceContainer = document.getElementById("evidence-container");
    if (!evidenceContainer) return;
    
    let cveBlock = item.cve ? `<span class="meta-cve" style="margin-top: 4px;"><i class="fa-solid fa-bug"></i> ${item.cve}</span>` : "";
    
    // Formatear logs/evidencia
    let logOutputBlock = "";
    if (item.output && item.output.length > 0) {
        const rawLogs = item.output.map(line => line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")).join("\n");
        logOutputBlock = `
            <div class="alert-detail-title" style="margin-top: 24px;"><i class="fa-solid fa-terminal"></i> Evidencia Coincidente (Líneas de Log / Comandos)</div>
            <pre class="log-output">${rawLogs}</pre>
        `;
    } else {
        logOutputBlock = `
            <div class="alert-detail-title" style="margin-top: 24px;"><i class="fa-solid fa-terminal"></i> Evidencia Coincidente</div>
            <div style="background-color: hsl(222, 25%, 3%); padding: 16px; border-radius: 8px; font-size: 12.5px; color: var(--text-muted); border: 1px solid var(--border-color); margin-top: 10px; width: 100%;">
                <i class="fa-solid fa-info-circle"></i> Esta heurística se detectó mediante análisis estático de configuración y no produjo líneas de salida de logs específicas en el QKView.
            </div>
        `;
    }
    
    evidenceContainer.innerHTML = `
        <div style="width: 100%; display: flex; flex-direction: column; align-items: flex-start; text-align: left; animation: fadeIn 0.25s ease;">
            <div style="display: flex; align-items: center; gap: 10px; width: 100%; justify-content: space-between;">
                <h3 style="font-size: 16px; font-weight: 700; color: var(--text-primary);">${item.title}</h3>
                <span class="badge badge-${item.severity === 'critical' ? 'critical' : item.severity === 'warning' ? 'warning' : 'info'}">${item.severity}</span>
            </div>
            
            <div class="alert-meta" style="padding-left: 0; margin-top: 8px; flex-wrap: wrap;">
                <span><i class="fa-solid fa-folder"></i> ${item.category}</span>
                <span><i class="fa-solid fa-fingerprint"></i> ID: ${item.id}</span>
                ${cveBlock}
            </div>
            
            <div style="margin-top: 20px; width: 100%;">
                <div class="alert-detail-title">Descripción Detallada</div>
                <p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-top: 6px;">${item.description}</p>
            </div>
            
            <div class="solution-box" style="margin-top: 20px; width: 100%;">
                <div class="alert-detail-title">Solución Recomendada</div>
                <p style="font-size: 13.5px; color: hsl(145, 40%, 80%); line-height: 1.6; margin-top: 6px; white-space: pre-line;">${item.solution}</p>
            </div>
            
            <div style="width: 100%;">
                ${logOutputBlock}
            </div>
        </div>
    `;
}

// --- 8. Lógica de Ajustes y Copia de Elementos ---
function setupSettingsPage() {
    const btnToggle = document.getElementById("btn-toggle-token");
    const tokenInput = document.getElementById("transit-token-input");
    if (btnToggle && tokenInput) {
        btnToggle.addEventListener("click", () => {
            if (tokenInput.type === "password") {
                tokenInput.type = "text";
                btnToggle.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
            } else {
                tokenInput.type = "password";
                btnToggle.innerHTML = '<i class="fa-solid fa-eye"></i>';
            }
        });
    }
    
    const btnCopyToken = document.getElementById("btn-copy-token");
    if (btnCopyToken && tokenInput) {
        btnCopyToken.addEventListener("click", () => {
            navigator.clipboard.writeText(tokenInput.value).then(() => {
                const originalHtml = btnCopyToken.innerHTML;
                btnCopyToken.innerHTML = '<i class="fa-solid fa-check" style="color: #10b981;"></i>';
                setTimeout(() => {
                    btnCopyToken.innerHTML = originalHtml;
                }, 1500);
            });
        });
    }
    
    const btnCopyCurl = document.getElementById("btn-copy-curl");
    const curlPre = document.getElementById("curl-code-command");
    if (btnCopyCurl && curlPre) {
        btnCopyCurl.addEventListener("click", () => {
            navigator.clipboard.writeText(curlPre.innerText).then(() => {
                const originalHtml = btnCopyCurl.innerHTML;
                btnCopyCurl.innerHTML = '<i class="fa-solid fa-check" style="color: #10b981;"></i>';
                setTimeout(() => {
                    btnCopyCurl.innerHTML = originalHtml;
                }, 1500);
            });
        });
    }
}

// Auxiliar para formatear la lista de versiones con fix
function formatFixedVersions(fixedObj) {
    const versions = fixedObj?.version || [];
    if (!Array.isArray(versions) || versions.length === 0) return "No especificada";
    return versions.map(v => {
        let verStr = `${v.major}.${v.minor}.${v.maintenance}`;
        if (v.point !== undefined && v.point !== "") verStr += `.${v.point}`;
        if (v.fix) verStr += `-${v.fix}`;
        return verStr;
    }).join(", ");
}

// --- 9. Explorador de Logs e Evidencias de QKView ---
async function loadDeviceLogItems() {
    const hostname = document.getElementById("lbl-hostname").innerText;
    if (!hostname || hostname === "Cargando..." || hostname === "Error") return;
    
    const listContainer = document.getElementById("log-items-list");
    if (!listContainer) return;
    
    listContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-spinner fa-spin"></i> Cargando lista...</div>`;
    
    const btnDownload = document.getElementById("btn-download-log");
    if (btnDownload) btnDownload.disabled = true;
    
    try {
        const endpoint = currentLogType === "files" ? "files" : "commands";
        const response = await fetch(`${BACKEND_API_URL}/api/devices/${hostname}/${endpoint}`);
        if (!response.ok) throw new Error("Error en respuesta de API");
        
        allLogItems = await response.json();
        renderLogItems();
    } catch (err) {
        console.error("Error al cargar ítems de logs de F5:", err);
        listContainer.innerHTML = `
            <div style="color: var(--color-critical); text-align: center; padding: 20px 10px; font-size: 13px;">
                <i class="fa-solid fa-triangle-exclamation"></i> Error de conexión con el backend
            </div>
        `;
    }
}

function renderLogItems() {
    const listContainer = document.getElementById("log-items-list");
    if (!listContainer) return;
    
    listContainer.innerHTML = "";
    const query = logSearchQuery.trim().toLowerCase();
    const filtered = allLogItems.filter(item => item.name.toLowerCase().includes(query));
    
    if (filtered.length === 0) {
        listContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-info-circle"></i> Ningún archivo coincide.</div>`;
        return;
    }
    
    filtered.forEach(item => {
        const el = document.createElement("div");
        el.className = `selector-alert-item`;
        if (selectedLogItemId === item.id) {
            el.classList.add("selected");
        }
        
        el.innerHTML = `
            <div class="selector-alert-item-title" style="max-width: 100%;" title="${item.name}">${item.name}</div>
        `;
        
        el.addEventListener("click", () => {
            document.querySelectorAll("#log-items-list .selector-alert-item").forEach(x => x.classList.remove("selected"));
            el.classList.add("selected");
            selectedLogItemId = item.id;
            selectedLogItemName = item.name;
            loadLogItemContent(item);
        });
        
        listContainer.appendChild(el);
    });
}

async function loadLogItemContent(item) {
    const hostname = document.getElementById("lbl-hostname").innerText;
    const viewerContainer = document.getElementById("log-viewer-container");
    if (!viewerContainer) return;
    
    viewerContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-spinner fa-spin fa-2x"></i> Cargando contenido...</div>`;
    document.getElementById("log-viewer-title").innerText = item.name;
    
    // Renderizar metadatos del archivo si existen
    const metadataContainer = document.getElementById("log-viewer-metadata");
    if (metadataContainer) {
        if (currentLogType === "files") {
            const sizeFormatted = item.size ? (item.size / (1024 * 1024)).toFixed(2) + " MB" : "Desconocido";
            const perms = item.permissions || "Desconocido";
            const modified = item.lastModified || "Desconocido";
            metadataContainer.innerHTML = `
                <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Tamaño: ${sizeFormatted}</span>
                <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Permisos: ${perms}</span>
                <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Última Modificación: ${modified}</span>
            `;
            metadataContainer.classList.remove("hidden");
        } else {
            metadataContainer.innerHTML = "";
            metadataContainer.classList.add("hidden");
        }
    }
    
    const btnDownload = document.getElementById("btn-download-log");
    if (btnDownload) btnDownload.disabled = true;
    
    try {
        const endpoint = currentLogType === "files" ? "files" : "commands";
        const response = await fetch(`${BACKEND_API_URL}/api/devices/${hostname}/${endpoint}/${item.id}`);
        if (!response.ok) throw new Error("Error en respuesta de API");
        
        const data = await response.json();
        rawLogContent = data.content || "";
        
        if (btnDownload) btnDownload.disabled = false;
        renderLogContent();
    } catch (err) {
        console.error("Error al descargar contenido del log:", err);
        viewerContainer.innerHTML = `
            <div style="color: var(--color-critical); text-align: center; padding: 40px 20px;">
                <i class="fa-solid fa-circle-xmark fa-3x" style="margin-bottom: 10px;"></i>
                <p style="font-weight: 600;">Error al Descargar Contenido</p>
                <p style="font-size: 13px; margin-top: 5px;">El archivo puede ser binario o exceder el tamaño límite permitido por iHealth.</p>
            </div>
        `;
    }
}

function renderLogContent() {
    const viewerContainer = document.getElementById("log-viewer-container");
    if (!viewerContainer) return;
    
    if (!rawLogContent) {
        viewerContainer.innerHTML = `<div style="padding: 40px; color: var(--text-muted);"><i class="fa-solid fa-file-excel fa-2x" style="margin-bottom:10px;"></i> El archivo de log está vacío.</div>`;
        return;
    }
    
    let escaped = rawLogContent.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    // Aplicar resaltado si existe búsqueda interna
    if (logTextSearchQuery.trim()) {
        const escQuery = logTextSearchQuery.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`(${escQuery})`, 'gi');
        escaped = escaped.replace(regex, '<span class="highlight">$1</span>');
    }
    
    const lines = escaped.split("\n");
    const processedLines = lines.map(line => {
        if (line.includes("ERR") || line.includes("ERROR") || line.includes("crit") || line.includes("CRITICAL")) {
            return `<span style="color: var(--color-critical); font-weight: 500;">${line}</span>`;
        } else if (line.includes("WARN") || line.includes("WARNING")) {
            return `<span style="color: var(--color-warning); font-weight: 500;">${line}</span>`;
        } else if (line.includes("info") || line.includes("INFO")) {
            return `<span style="color: var(--text-secondary);">${line}</span>`;
        }
        return line;
    });
    
    viewerContainer.innerHTML = `
        <pre class="log-output" style="max-height: 500px; height: 500px; text-align: left; width: 100%; margin-top: 0; font-size: 12px; border: 1px solid var(--border-color);">${processedLines.join("\n")}</pre>
    `;
}

function setupLogExplorerEvents() {
    const btnFiles = document.getElementById("btn-logtype-files");
    const btnCmds = document.getElementById("btn-logtype-commands");
    
    if (btnFiles && btnCmds) {
        btnFiles.addEventListener("click", () => {
            if (currentLogType === "files") return;
            currentLogType = "files";
            btnFiles.classList.add("active");
            btnCmds.classList.remove("active");
            allLogItems = [];
            selectedLogItemId = null;
            selectedLogItemName = "";
            rawLogContent = "";
            document.getElementById("log-viewer-title").innerText = "Visor de Logs";
            const logContainer = document.getElementById("log-viewer-container");
            if (logContainer) {
                logContainer.innerHTML = `
                    <i class="fa-solid fa-file-lines fa-3x" style="margin-bottom: 15px; color: var(--border-color);"></i>
                    <p>Seleccione un archivo de log de la lista de la izquierda para ver su contenido aquí.</p>
                `;
            }
            loadDeviceLogItems();
        });
        
        btnCmds.addEventListener("click", () => {
            if (currentLogType === "commands") return;
            currentLogType = "commands";
            btnCmds.classList.add("active");
            btnFiles.classList.remove("active");
            allLogItems = [];
            selectedLogItemId = null;
            selectedLogItemName = "";
            rawLogContent = "";
            document.getElementById("log-viewer-title").innerText = "Visor de Comandos";
            const logContainer = document.getElementById("log-viewer-container");
            if (logContainer) {
                logContainer.innerHTML = `
                    <i class="fa-solid fa-terminal fa-3x" style="margin-bottom: 15px; color: var(--border-color);"></i>
                    <p>Seleccione un comando de la lista de la izquierda para ver su salida aquí.</p>
                `;
            }
            loadDeviceLogItems();
        });
    }
    
    const logSearch = document.getElementById("log-search-input");
    if (logSearch) {
        logSearch.addEventListener("input", (e) => {
            logSearchQuery = e.target.value;
            renderLogItems();
        });
    }
    
    const textSearch = document.getElementById("log-text-search");
    if (textSearch) {
        textSearch.addEventListener("input", (e) => {
            logTextSearchQuery = e.target.value;
            if (rawLogContent) {
                renderLogContent();
            }
        });
    }
    
    const btnDownload = document.getElementById("btn-download-log");
    if (btnDownload) {
        btnDownload.addEventListener("click", () => {
            if (!rawLogContent) return;
            const blob = new Blob([rawLogContent], { type: "text/plain;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            let cleanName = selectedLogItemName.replace(/[^a-zA-Z0-9.-]/g, "_");
            a.download = `${cleanName}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }
}

// --- 10. Sistema de Arrastre (Drag & Drop) y Sondeo Rápido ---
let rapidPollingInterval = null;

function setupDragAndDrop() {
    const zone = document.getElementById("drag-drop-zone");
    const fileInput = document.getElementById("qkview-file-input");
    
    if (!zone || !fileInput) return;
    
    // Clic en la tarjeta abre el buscador de archivos
    zone.addEventListener("click", (e) => {
        if (e.target.closest("#upload-progress-container")) return;
        fileInput.click();
    });
    
    // Selección mediante cuadro de diálogo tradicional
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            handleFileUpload(fileInput.files[0]);
        }
    });
    
    // Eventos de arrastre
    zone.addEventListener("dragover", (e) => {
        e.preventDefault();
        zone.classList.add("dragover");
    });
    
    zone.addEventListener("dragleave", () => {
        zone.classList.remove("dragover");
    });
    
    zone.addEventListener("drop", (e) => {
        e.preventDefault();
        zone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
}

function handleFileUpload(file) {
    if (!file) return;
    
    // Validar formato del archivo
    if (!file.name.endsWith(".qkview")) {
        alert("Formato de archivo inválido. Por favor, suba únicamente archivos con extensión '.qkview'.");
        return;
    }
    
    const progressContainer = document.getElementById("upload-progress-container");
    const filenameLabel = document.getElementById("upload-filename");
    const percentLabel = document.getElementById("upload-percent");
    const progressBar = document.getElementById("upload-progress-bar");
    const statusText = document.getElementById("upload-status-text");
    
    if (!progressContainer) return;
    
    // Mostrar interfaz de carga
    progressContainer.classList.remove("hidden");
    filenameLabel.innerText = file.name;
    percentLabel.innerText = "0%";
    progressBar.style.width = "0%";
    statusText.innerText = "Subiendo archivo al servidor de tránsito...";
    
    const formData = new FormData();
    formData.append("file", file);
    
    // Recuperar token desde ajustes
    const token = document.getElementById("transit-token-input")?.value || "BirraverdePCtoken";
    
    // Petición HTTP XMLHttpRequest para medir progreso
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BACKEND_API_URL}/api/upload`, true);
    xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    
    // Escuchar progreso de carga de bytes
    xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            percentLabel.innerText = `${percent}%`;
            progressBar.style.width = `${percent}%`;
            if (percent === 100) {
                statusText.innerText = "Carga completa. Procesando en Railway y subiendo a F5 iHealth...";
            }
        }
    });
    
    // Al finalizar la subida
    xhr.onload = () => {
        if (xhr.status === 200 || xhr.status === 202) {
            try {
                const response = JSON.parse(xhr.responseText);
                console.log("[iHealth] Archivo subido exitosamente:", response);
                
                let hostname = response.hostname || "unknown-f5";
                statusText.innerHTML = `<span style="color: #10b981;"><i class="fa-solid fa-circle-check"></i> Subido con éxito. Iniciando sondeo de estado...</span>`;
                
                // Iniciar consulta de estado continua de 5 segundos
                startRapidPolling(hostname);
            } catch (err) {
                console.error("Error procesando respuesta de subida:", err);
                statusText.innerText = "Archivo subido, pero no se pudo determinar el hostname.";
            }
        } else {
            console.error("[iHealth] Error en subida:", xhr.status, xhr.responseText);
            statusText.innerHTML = `<span style="color: #ef4444;"><i class="fa-solid fa-triangle-exclamation"></i> Falló la subida (Código ${xhr.status}). Verifique el Token en Ajustes.</span>`;
        }
    };
    
    xhr.onerror = () => {
        statusText.innerHTML = `<span style="color: #ef4444;"><i class="fa-solid fa-triangle-exclamation"></i> Error de conexión de red con el servidor.</span>`;
    };
    
    xhr.send(formData);
}

function startRapidPolling(hostname) {
    if (rapidPollingInterval) clearInterval(rapidPollingInterval);
    
    // Renderizar spinner de carga en el panel de alertas de Vista General
    renderProcessingState(hostname);
    
    // Forzar selección del nuevo dispositivo en el selector superior
    let selector = document.getElementById("device-selector");
    if (selector) {
        let optionExists = false;
        for (let i = 0; i < selector.options.length; i++) {
            if (selector.options[i].value === hostname) {
                optionExists = true;
                break;
            }
        }
        if (!optionExists) {
            const opt = document.createElement("option");
            opt.value = hostname;
            opt.innerText = `${hostname} (Procesando...)`;
            selector.appendChild(opt);
        }
        selector.value = hostname;
        
        // Actualizar valores de cabecera temporalmente
        document.getElementById("lbl-hostname").innerText = hostname;
        document.getElementById("lbl-last-scan").innerText = "Procesando...";
        document.getElementById("lbl-health-score").innerText = "0";
    }
    
    rapidPollingInterval = setInterval(async () => {
        try {
            const response = await fetch(`${BACKEND_API_URL}/api/devices`);
            if (!response.ok) return;
            const devices = await response.json();
            
            const dev = devices.find(d => d.hostname === hostname);
            if (dev) {
                if (dev.status === "completed") {
                    clearInterval(rapidPollingInterval);
                    rapidPollingInterval = null;
                    
                    // Ocultar barra de progreso tras 3 segundos
                    setTimeout(() => {
                        const progressContainer = document.getElementById("upload-progress-container");
                        if (progressContainer) progressContainer.classList.add("hidden");
                    }, 3000);
                    
                    console.log(`[iHealth] Sondeo exitoso. Dispositivo ${hostname} está listo.`);
                    
                    // Recargar dispositivos reales y cargar los datos correspondientes
                    await loadRealDevices();
                    if (selector) selector.value = hostname;
                    loadRealDeviceData(hostname);
                    
                } else if (dev.status === "failed") {
                    clearInterval(rapidPollingInterval);
                    rapidPollingInterval = null;
                    
                    const statusText = document.getElementById("upload-status-text");
                    if (statusText) {
                        statusText.innerHTML = `<span style="color: #ef4444;"><i class="fa-solid fa-triangle-exclamation"></i> Error en iHealth: ${dev.error_message || 'Fallo de análisis'}</span>`;
                    }
                    
                    const listContainer = document.getElementById("alerts-list");
                    if (listContainer) {
                        listContainer.innerHTML = `
                            <div class="loading-spinner" style="color: #ef4444; flex-direction: column; gap: 12px; padding: 50px 20px;">
                                <i class="fa-solid fa-circle-xmark fa-3x"></i>
                                <p style="font-weight: 600;">El análisis de QKView falló</p>
                                <p style="font-size: 12.5px; color: var(--text-muted);">${dev.error_message || 'Compruebe las credenciales de iHealth en Railway.'}</p>
                            </div>
                        `;
                    }
                } else {
                    // Mantener el spinner y actualizar selector por si acaso
                    renderProcessingState(hostname);
                }
            }
        } catch (err) {
            console.error("Error consultando estado en sondeo rápido:", err);
        }
    }, 5000);
}

function renderProcessingState(hostname) {
    const listContainer = document.getElementById("alerts-list");
    if (!listContainer) return;
    
    listContainer.innerHTML = `
        <div class="loading-spinner" style="flex-direction: column; gap: 20px; padding: 60px 20px; width: 100%;">
            <i class="fa-solid fa-arrows-spin fa-spin fa-3x" style="color: var(--accent-primary);"></i>
            <div style="text-align: center;">
                <p style="font-weight: 600; color: #fff; margin-bottom: 6px;">[iHealth] Analizando el QKView de '${hostname}'...</p>
                <p style="font-size: 12.5px; color: var(--text-muted);">La API de F5 está ejecutando diagnósticos heurísticos y analizando CVEs. Esto puede tomar unos minutos.</p>
            </div>
        </div>
    `;
}



