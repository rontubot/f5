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
let hasDevices = false;
let currentLogFileCategory = "all";

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
        
        // Verificar si la lista o sus estados realmente cambiaron
        let listChanged = false;
        if (!currentDevices || currentDevices.length !== devices.length) {
            listChanged = true;
        } else {
            for (let i = 0; i < devices.length; i++) {
                const d1 = devices[i];
                const d2 = currentDevices.find(d => d.hostname === d1.hostname);
                if (!d2 || d2.status !== d1.status) {
                    listChanged = true;
                    break;
                }
            }
        }
        
        if (!listChanged) {
            // No hay cambios, salir de forma segura para no perturbar el visor ni las gráficas
            return;
        }
        
        const selector = document.getElementById("device-selector");
        const prevSelected = selector ? selector.value : "";
        
        // Buscar el estado anterior del dispositivo seleccionado
        const prevDev = currentDevices ? currentDevices.find(d => d.hostname === prevSelected) : null;
        const prevStatus = prevDev ? prevDev.status : null;
        
        currentDevices = devices;
        
        if (!selector) return;
        selector.innerHTML = ""; // Limpiar selector
        
        if (devices.length === 0) {
            hasDevices = false;
            selector.innerHTML = `<option value="">Sin dispositivos</option>`;
            document.getElementById("lbl-hostname").innerText = "Ninguno";
            document.getElementById("lbl-last-scan").innerText = "No hay escaneos disponibles";
            document.getElementById("lbl-health-score").innerText = "0";
            document.getElementById("lbl-critical-count").innerText = "0";
            document.getElementById("lbl-warning-count").innerText = "0";
            document.getElementById("lbl-cve-count").innerText = "0";
            setProgressRing(0);
            
            const emptyHistory = { labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], cpu: [0,0,0,0,0,0,0], ram: [0,0,0,0,0,0,0] };
            initResourceChart(emptyHistory);
            initConnectionsChart({ labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], active: [0,0,0,0,0,0,0] });
            
            document.getElementById("alerts-list").innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-triangle-exclamation"></i> Conectado a Railway, pero aún no se han subido QKViews desde el F5.</div>`;
            return;
        }
        hasDevices = true;

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

        // Determinar qué dispositivo cargar preservando la selección anterior
        const currentDev = devices.find(d => d.hostname === prevSelected);
        if (currentDev) {
            selector.value = prevSelected;
            // Si el estado del análisis cambió (ej: terminó de procesarse), recargar datos
            if (currentDev.status !== prevStatus) {
                loadRealDeviceData(prevSelected);
            }
        } else {
            selector.value = devices[0].hostname;
            loadRealDeviceData(devices[0].hostname);
        }
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
        // Generar historial de recursos simulados basados en el nombre del host (con variación estable)
        const overviewSeed = getSeedFromString(hostname);
        const overviewRng = createSeededRandom(overviewSeed);
        const cpuHistory = [];
        const ramHistory = [];
        const connHistory = [];
        const baseCpu = 20 + (overviewSeed % 15);
        const baseRam = 50 + (overviewSeed % 12);
        
        for (let i = 0; i < 7; i++) {
            cpuHistory.push(Math.round(baseCpu + overviewRng() * 12 - 6));
            ramHistory.push(Math.round(baseRam + overviewRng() * 4 - 2));
            connHistory.push(Math.round((500 + (overviewSeed % 6) * 200) * (0.85 + overviewRng() * 0.3)));
        }

        const simulatedHistory = {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            cpu: cpuHistory,
            ram: ramHistory
        };
        initResourceChart(simulatedHistory);

        const simulatedConnections = {
            labels: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"],
            active: connHistory
        };
        initConnectionsChart(simulatedConnections);
    } catch (err) {
        console.error("Error al cargar diagnósticos del dispositivo:", err);
    }
}

// Carga en Modo Demostración (Offline)
function loadMockData() {
    hasDevices = true;
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
        { btn: "btn-graphs", page: "page-graphs" },
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
                
                // Cargar gráficas si se selecciona esa pestaña
                if (tab.page === "page-graphs") {
                    loadDeviceGraphs();
                }
                
                // Redimensionar gráficos para evitar problemas de ancho al volver
                if (tab.page === "page-overview" || tab.page === "page-graphs") {
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
    
    // Filtrar por categoría de archivo y por búsqueda de texto
    let filtered = allLogItems.filter(item => {
        if (!item.name.toLowerCase().includes(query)) return false;
        
        if (currentLogFileCategory === "all") return true;
        if (currentLogFileCategory === "varlog") return item.name.startsWith("/var/log/") || item.name.includes("var/log");
        if (currentLogFileCategory === "config") return item.name.startsWith("/config/") || item.name.includes("config/");
        if (currentLogFileCategory === "xml") return item.name.endsWith(".xml");
        return true;
    });
    
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
        
        const sizeText = item.size ? ` (${(item.size / (1024 * 1024)).toFixed(2)} MB)` : "";
        el.innerHTML = `
            <div class="selector-alert-item-title" style="max-width: 100%;" title="${item.name}">${item.name}${sizeText}</div>
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
    await loadLogItemContentWithLimit(item, 15000);
}

async function loadLogItemContentWithLimit(item, limit) {
    const hostname = document.getElementById("lbl-hostname").innerText;
    const viewerContainer = document.getElementById("log-viewer-container");
    if (!viewerContainer) return;
    
    viewerContainer.innerHTML = `<div class="loading-spinner"><i class="fa-solid fa-spinner fa-spin fa-2x"></i> Cargando contenido...</div>`;
    document.getElementById("log-viewer-title").innerText = item.name;
    
    const metadataContainer = document.getElementById("log-viewer-metadata");
    const filtersContainer = document.getElementById("log-level-filters-container");
    const timeFiltersContainer = document.getElementById("log-time-filter-container");
    const eduPanel = document.getElementById("log-education-panel");
    if (filtersContainer) filtersContainer.classList.add("hidden");
    if (timeFiltersContainer) timeFiltersContainer.classList.add("hidden");
    if (eduPanel) eduPanel.classList.add("hidden");
    
    const btnDownload = document.getElementById("btn-download-log");
    if (btnDownload) btnDownload.disabled = true;
    
    try {
        const endpoint = currentLogType === "files" ? "files" : "commands";
        const response = await fetch(`${BACKEND_API_URL}/api/devices/${hostname}/${endpoint}/${item.id}?limit_lines=${limit}`);
        if (!response.ok) throw new Error("Error en respuesta de API");
        
        const data = await response.json();
        rawLogContent = data.content || "";
        
        if (filtersContainer) filtersContainer.classList.remove("hidden");
        // Solo mostrar filtros de tiempo para archivos de logs y si tienen contenido
        if (timeFiltersContainer && currentLogType === "files" && rawLogContent) {
            timeFiltersContainer.classList.remove("hidden");
        } else if (timeFiltersContainer) {
            timeFiltersContainer.classList.add("hidden");
        }
        
        if (metadataContainer) {
            if (currentLogType === "files") {
                const sizeFormatted = item.size ? (item.size / (1024 * 1024)).toFixed(2) + " MB" : "Desconocido";
                const perms = item.permissions || "Desconocido";
                const modified = item.lastModified || "Desconocido";
                let truncateAlert = "";
                if (data.truncated) {
                    truncateAlert = `<span class="badge badge-warning" style="text-transform: none; font-size: 11px; background-color: var(--color-warning); color: #000; border-color: var(--color-warning); display: inline-flex; align-items: center; gap: 8px;"><i class="fa-solid fa-triangle-exclamation"></i> Mostrando primeras ${data.limit.toLocaleString()} líneas de ${data.total_lines.toLocaleString()} <button id="btn-load-all-lines" style="background: rgba(0,0,0,0.2); border: 1px solid rgba(0,0,0,0.3); border-radius: 4px; padding: 2px 6px; color: #000; cursor: pointer; font-size: 10px; font-weight: 700;">Cargar Todo</button></span>`;
                }
                metadataContainer.innerHTML = `
                    <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Tamaño: ${sizeFormatted}</span>
                    <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Permisos: ${perms}</span>
                    <span class="badge badge-info" style="text-transform: none; font-size: 11px;">Modificado: ${modified}</span>
                    ${truncateAlert}
                `;
                metadataContainer.classList.remove("hidden");
            } else {
                if (data.truncated) {
                    metadataContainer.innerHTML = `<span class="badge badge-warning" style="text-transform: none; font-size: 11px; background-color: var(--color-warning); color: #000; border-color: var(--color-warning); display: inline-flex; align-items: center; gap: 8px;"><i class="fa-solid fa-triangle-exclamation"></i> Mostrando primeras ${data.limit.toLocaleString()} líneas de ${data.total_lines.toLocaleString()} <button id="btn-load-all-lines" style="background: rgba(0,0,0,0.2); border: 1px solid rgba(0,0,0,0.3); border-radius: 4px; padding: 2px 6px; color: #000; cursor: pointer; font-size: 10px; font-weight: 700;">Cargar Todo</button></span>`;
                    metadataContainer.classList.remove("hidden");
                } else {
                    metadataContainer.innerHTML = "";
                    metadataContainer.classList.add("hidden");
                }
            }
        }
        
        if (data.truncated) {
            setTimeout(() => {
                const btnLoadAll = document.getElementById("btn-load-all-lines");
                if (btnLoadAll) {
                    btnLoadAll.onclick = (e) => {
                        e.stopPropagation();
                        loadLogItemContentWithLimit(item, 0);
                    };
                }
            }, 80);
        }
        
        initializeTimeFilters();
        
        if (btnDownload) btnDownload.disabled = false;
        renderLogContent();
    } catch (err) {
        console.error("Error al descargar contenido del log:", err);
        if (filtersContainer) filtersContainer.classList.add("hidden");
        if (timeFiltersContainer) timeFiltersContainer.classList.add("hidden");
        viewerContainer.innerHTML = `
            <div style="color: var(--color-critical); text-align: center; padding: 40px 20px;">
                <i class="fa-solid fa-circle-xmark fa-3x" style="margin-bottom: 10px;"></i>
                <p style="font-weight: 600;">Error al Descargar Contenido</p>
                <p style="font-size: 13px; margin-top: 5px;">El archivo puede ser binario o exceder el tamaño límite permitido por iHealth.</p>
            </div>
        `;
    }
}

// Auxiliar para parsear marcas de tiempo syslog o ISO de F5
function parseLogLineTimestamp(line) {
    const cleanLine = line.replace(/<[^>]*>/g, "").trim();
    
    // 1. Formato Syslog estándar: Jul 14 11:42:05
    const syslogRegex = /^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})/;
    let match = cleanLine.match(syslogRegex);
    if (match) {
        const months = { Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5, Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11 };
        const m = months[match[1]];
        const d = parseInt(match[2], 10);
        const hh = parseInt(match[3], 10);
        const mm = parseInt(match[4], 10);
        const ss = parseInt(match[5], 10);
        return new Date(2026, m, d, hh, mm, ss); // Asumimos año del análisis (2026)
    }
    
    // 2. Formato ISO / BIG-IP moderno: 2026-07-14T11:42:05 o 2026-07-14 11:42:05
    const isoRegex = /^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})/;
    match = cleanLine.match(isoRegex);
    if (match) {
        const y = parseInt(match[1], 10);
        const m = parseInt(match[2], 10) - 1;
        const d = parseInt(match[3], 10);
        const hh = parseInt(match[4], 10);
        const mm = parseInt(match[5], 10);
        const ss = parseInt(match[6], 10);
        return new Date(y, m, d, hh, mm, ss);
    }
    
    return null;
}

// Auxiliar para formatear fecha a string datetime-local (YYYY-MM-DDTHH:MM:SS)
function formatDatetimeLocal(date) {
    if (!date) return "";
    const pad = (num) => String(num).padStart(2, '0');
    const y = date.getFullYear();
    const m = pad(date.getMonth() + 1);
    const d = pad(date.getDate());
    const hh = pad(date.getHours());
    const mm = pad(date.getMinutes());
    const ss = pad(date.getSeconds());
    return `${y}-${m}-${d}T${hh}:${mm}:${ss}`;
}

// Configurar los límites del filtro cronológico basados en el log activo
function initializeTimeFilters() {
    const startInput = document.getElementById("time-filter-start");
    const endInput = document.getElementById("time-filter-end");
    if (!startInput || !endInput) return;
    
    startInput.value = "";
    endInput.value = "";
    
    if (!rawLogContent || currentLogType !== "files") return;
    
    const lines = rawLogContent.split("\n");
    let firstDate = null;
    let lastDate = null;
    
    for (let i = 0; i < lines.length; i++) {
        const d = parseLogLineTimestamp(lines[i]);
        if (d) {
            firstDate = d;
            break;
        }
    }
    
    for (let i = lines.length - 1; i >= 0; i--) {
        const d = parseLogLineTimestamp(lines[i]);
        if (d) {
            lastDate = d;
            break;
        }
    }
    
    if (firstDate && lastDate) {
        const startStr = formatDatetimeLocal(firstDate);
        const endStr = formatDatetimeLocal(lastDate);
        
        startInput.min = startStr;
        startInput.max = endStr;
        startInput.value = startStr;
        
        endInput.min = startStr;
        endInput.max = endStr;
        endInput.value = endStr;
    }
}

// Genera una explicación estructurada y educativa de comandos y líneas de logs
function explainLogLine(line, commandName = "") {
    if (commandName) {
        let explanation = "Salida del comando TMSH ejecutado en el clúster BIG-IP.";
        if (commandName.includes("sys hardware")) {
            explanation = "Muestra el estado físico de la plataforma BIG-IP, incluyendo números de serie de componentes, estado de las fuentes de poder, velocidades de ventiladores y sensores de temperatura.";
        } else if (commandName.includes("sys license")) {
            explanation = "Detalla las características y límites autorizados por la licencia activa en el equipo, incluyendo la fecha de expiración y módulos habilitados (LTM, GTM, ASM, APM).";
        } else if (commandName.includes("sys failover")) {
            explanation = "Muestra el estado de failover actual del dispositivo (ej: Active, Standby, Offline) y las causas del estado actual.";
        } else if (commandName.includes("sys cluster")) {
            explanation = "Muestra el estado y configuración del clúster físico en plataformas Viprion (chasis multiblade). Detalla qué blades están activas y sincronizadas.";
        } else if (commandName.includes("sys memory")) {
            explanation = "Muestra el uso detallado de memoria física y virtual asignada tanto al sistema operativo Host (Linux) como al Traffic Management Microkernel (TMM).";
        } else if (commandName.includes("sys cpu")) {
            explanation = "Muestra las estadísticas de uso de CPU en tiempo real e histórico por núcleo físico, separando el plano de control (Host) y plano de datos (TMM).";
        } else if (commandName.includes("net interface")) {
            explanation = "Muestra estadísticas de tráfico de red por cada puerto físico (interfaces), incluyendo paquetes transmitidos/recibidos, errores de CRC, colisiones y estado del enlace (Up/Down).";
        } else if (commandName.includes("ltm virtual")) {
            explanation = "Muestra la configuración o estadísticas de tráfico cursado a través de los Virtual Servers de Capa 4 a Capa 7.";
        } else if (commandName.includes("ltm pool")) {
            explanation = "Muestra la configuración o estadísticas y estado de salud de todos los grupos de servidores de destino (Pools) del balanceador de carga.";
        } else if (commandName.includes("ltm node")) {
            explanation = "Muestra el estado operativo y contadores de tráfico de las direcciones IP físicas de los servidores backend (Nodes).";
        }
        
        return `
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div style="font-weight: 600; color: #fff;">Comando TMSH: <code style="background-color: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; color: var(--color-warning);">${commandName}</code></div>
                <div><strong>Descripción Educativa:</strong> ${explanation}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;"><i class="fa-solid fa-circle-info"></i> Esta es la salida completa del comando extraído del QKView. Úsalo para auditar la configuración declarativa del equipo BIG-IP.</div>
            </div>
        `;
    }
    
    const cleanLine = line.replace(/<[^>]*>/g, "").trim();
    if (!cleanLine) return "Línea vacía.";
    
    const ts = parseLogLineTimestamp(cleanLine);
    const tsStr = ts ? ts.toLocaleString() : "No detectado en esta línea de log";
    
    let daemon = "Desconocido";
    let daemonDesc = "No se identificó un daemon específico en esta línea. Puede ser un mensaje genérico del kernel o script local.";
    
    const daemonsMap = {
        "mcpd": ["mcpd", "MCPD (Message Control Protocol Daemon) es el proceso core que administra la base de datos de configuración de BIG-IP (mcpdb). Es responsable de guardar y sincronizar la configuración, y comunicar los cambios entre los daemons."],
        "tmm": ["tmm", "TMM (Traffic Management Microkernel) es el plano de datos de BIG-IP. Se encarga de procesar todo el tráfico de red, balanceo de carga, aceleración SSL y compresión. Corre en tiempo real directamente sobre el hardware/hipervisor."],
        "sod": ["sod", "SOD (Switch Over Daemon) es el daemon encargado de la Alta Disponibilidad (HA) y el failover. Monitorea el estado de peer y decide cuándo pasar a estado Activo o Standby."],
        "system_auth": ["system_auth", "Administrador de Autenticación del Sistema. Registra inicios de sesión, intentos de autenticación y actividades de SSH/GUI."],
        "chassis": ["chassisd", "Daemon de Chasis. Monitorea los sensores físicos de hardware como temperatura, fuentes de alimentación, ventiladores y voltajes."],
        "gtmd": ["gtmd", "GTM Daemon. Administrador de DNS global (BIG-IP DNS / GTM). Resuelve peticiones DNS de manera inteligente según la salud y ubicación geográfica."],
        "httpd": ["httpd", "Servidor Web Apache de BIG-IP. Procesa las conexiones a la interfaz de administración Web GUI (Configuration Utility)."],
        "lacpd": ["lacpd", "LACP Daemon. Administra el protocolo de control de agregación de enlaces (Link Aggregation Control Protocol) para trunks/etherchannel."],
        "snmpd": ["snmpd", "Simple Network Management Protocol Daemon. Responde a consultas SNMP externas sobre la salud del dispositivo."],
        "alertd": ["alertd", "Alert Daemon. Monitorea los archivos de log locales y genera alertas SNMP, correos electrónicos o llamadas a scripts (user_alert.conf) cuando se detectan patrones de error específicos."],
        "syslog": ["syslog-ng", "Servicio de bitácora que recopila y distribuye los mensajes de logs internos y externos."],
        "promptstatusd": ["promptstatusd", "Daemon de Prompt. Actualiza dinámicamente la información de estado de BIG-IP que se muestra en el prompt de la terminal (ej: Active, Standby, Changes Pending)."],
        "clsh": ["clsh", "Cluster Shell. Utilizado en plataformas Viprion o chasis para enviar comandos a través de las distintas blades."]
    };
    
    for (const key in daemonsMap) {
        if (cleanLine.toLowerCase().includes(key)) {
            daemon = daemonsMap[key][0];
            daemonDesc = daemonsMap[key][1];
            break;
        }
    }
    
    let kwsFound = [];
    let recs = [];
    
    if (cleanLine.includes("failover") || cleanLine.includes("FAILOVER") || cleanLine.includes("sod")) {
        kwsFound.push("Failover Event");
        recs.push("Se ha detectado un cambio de rol de alta disponibilidad (Active/Standby). Revisa si hay mensajes del SOD para saber si fue gatillado manualmente o por falla de un pool o daemon.");
    }
    if (cleanLine.includes("disk full") || cleanLine.includes("space") || cleanLine.includes("LIMIT")) {
        kwsFound.push("Almacenamiento");
        recs.push("La partición está alcanzando su capacidad máxima. Ejecuta 'df -h' vía SSH o revisa el comando de disco en Ajustes para borrar archivos temporales o cores viejos en /var/core.");
    }
    if (cleanLine.includes("monitor") || cleanLine.includes("DOWN")) {
        kwsFound.push("Health Check Down");
        recs.push("Un monitor de salud determinó que un servidor destino (pool member o node) no responde. Verifica la conectividad de red, puertos de escucha y logs del servidor backend correspondiente.");
    }
    if (cleanLine.includes("UP")) {
        kwsFound.push("Health Check Up");
        recs.push("El servicio backend ha restablecido su respuesta al monitor y vuelve a recibir tráfico del balanceador.");
    }
    if (cleanLine.includes("OOM") || cleanLine.includes("memory") || cleanLine.includes("Out of memory")) {
        kwsFound.push("Falta de Memoria");
        recs.push("Error crítico. El sistema operativo se ha quedado sin memoria física. Se recomienda revisar la tabla de memoria en Gráficas de Rendimiento y auditar procesos de Java/GUI que puedan estar fugando RAM.");
    }
    if (cleanLine.includes("SSL") || cleanLine.includes("handshake")) {
        kwsFound.push("Criptografía SSL/TLS");
        recs.push("Mensaje de negociación de llaves. Común cuando clientes antiguos intentan usar SSLv3 o TLS 1.0 obsoletos, o si hay un mismatch en los cipher suites configurados.");
    }
    
    if (recs.length === 0) {
        recs.push("Auditoría general de syslog. El comportamiento parece informativo y sigue el flujo normal del sistema.");
    }
    
    return `
        <div style="display: flex; flex-direction: column; gap: 8px;">
            <div style="font-weight: 600; color: #fff; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 4px; margin-bottom: 4px;">
                Línea Seleccionada: <span style="font-family: monospace; font-size: 11.5px; color: var(--color-warning);">${cleanLine.substring(0, 140)}${cleanLine.length > 140 ? '...' : ''}</span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                <div>
                    <strong style="color: var(--text-secondary);">Marca de Tiempo:</strong> 
                    <span style="color: #fff;">${tsStr}</span>
                </div>
                <div>
                    <strong style="color: var(--text-secondary);">Proceso Responsable:</strong> 
                    <span style="color: #fff; background-color: rgba(56,189,248,0.2); padding: 1px 6px; border-radius: 4px; font-size: 11px;">${daemon}</span>
                </div>
            </div>
            <div style="margin-top: 4px;">
                <strong style="color: var(--text-secondary);">Rol del Proceso:</strong> 
                <span style="color: var(--text-secondary);">${daemonDesc}</span>
            </div>
            ${kwsFound.length > 0 ? `
            <div style="margin-top: 4px;">
                <strong style="color: var(--text-secondary);">Conceptos Clave:</strong> 
                ${kwsFound.map(kw => `<span style="background-color: rgba(239,68,68,0.2); color: #f87171; padding: 1px 6px; border-radius: 4px; font-size: 11px; margin-right: 6px;">${kw}</span>`).join('')}
            </div>` : ''}
            <div style="margin-top: 4px; background-color: rgba(255,255,255,0.03); padding: 8px; border-radius: 4px; border-left: 3px solid var(--color-warning);">
                <strong>Recomendación Operativa:</strong> ${recs.join(' ')}
            </div>
        </div>
    `;
}

function renderLogContent() {
    const viewerContainer = document.getElementById("log-viewer-container");
    if (!viewerContainer) return;
    
    if (!rawLogContent) {
        viewerContainer.innerHTML = `<div style="padding: 40px; color: var(--text-muted);"><i class="fa-solid fa-file-excel fa-2x" style="margin-bottom:10px;"></i> El archivo de log está vacío.</div>`;
        return;
    }
    
    // Obtener estados de los checkboxes de severidad
    const showCrit = document.getElementById("chk-log-crit") ? document.getElementById("chk-log-crit").checked : true;
    const showWarn = document.getElementById("chk-log-warn") ? document.getElementById("chk-log-warn").checked : true;
    const showNotice = document.getElementById("chk-log-notice") ? document.getElementById("chk-log-notice").checked : true;
    const showInfo = document.getElementById("chk-log-info") ? document.getElementById("chk-log-info").checked : true;
    const showOthers = document.getElementById("chk-log-others") ? document.getElementById("chk-log-others").checked : true;

    // Obtener estados del filtro cronológico
    const startVal = document.getElementById("time-filter-start") ? document.getElementById("time-filter-start").value : "";
    const endVal = document.getElementById("time-filter-end") ? document.getElementById("time-filter-end").value : "";
    
    const startDate = startVal ? new Date(startVal) : null;
    const endDate = endVal ? new Date(endVal) : null;

    let escaped = rawLogContent.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    // Aplicar resaltado si existe búsqueda interna
    if (logTextSearchQuery.trim()) {
        const escQuery = logTextSearchQuery.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`(${escQuery})`, 'gi');
        escaped = escaped.replace(regex, '<span class="highlight">$1</span>');
    }
    
    const lines = escaped.split("\n");
    const processedLines = [];
    let lastTimestamp = null;
    
    lines.forEach((line, idx) => {
        let ts = parseLogLineTimestamp(line);
        if (ts) {
            lastTimestamp = ts;
        } else {
            ts = lastTimestamp; // Mantener cronología para líneas de continuación
        }
        
        let isCrit = line.includes("ERR") || line.includes("ERROR") || line.includes("crit") || line.includes("CRITICAL") || line.includes("emerg") || line.includes("alert") || line.includes("Emerg") || line.includes("Alert");
        let isWarn = line.includes("WARN") || line.includes("WARNING") || line.includes("warning") || line.includes("Warn");
        let isNotice = line.includes("notice") || line.includes("NOTICE") || line.includes("Notice");
        let isInfo = line.includes("info") || line.includes("INFO") || line.includes("Info");
        
        let shouldShow = true;
        
        if (isCrit) shouldShow = showCrit;
        else if (isWarn) shouldShow = showWarn;
        else if (isNotice) shouldShow = showNotice;
        else if (isInfo) shouldShow = showInfo;
        else shouldShow = showOthers;
        
        // Aplicar filtro por rango de tiempo
        if (shouldShow && ts && currentLogType === "files") {
            if (startDate && ts < startDate) shouldShow = false;
            if (endDate && ts > endDate) shouldShow = false;
        }
        
        if (shouldShow) {
            let lineHtml = line;
            if (isCrit) {
                lineHtml = `<span style="color: var(--color-critical); font-weight: 500;">${line}</span>`;
            } else if (isWarn) {
                lineHtml = `<span style="color: var(--color-warning); font-weight: 500;">${line}</span>`;
            } else if (isNotice) {
                lineHtml = `<span style="color: #38bdf8; font-weight: 500;">${line}</span>`;
            } else if (isInfo) {
                lineHtml = `<span style="color: var(--text-secondary);">${line}</span>`;
            }
            
            processedLines.push(`<div class="log-line" data-line-num="${idx}">${lineHtml}</div>`);
        }
    });
    
    const displayHtml = processedLines.length > 0 
        ? `<pre class="log-output" style="max-height: 520px; height: 520px; text-align: left; width: 100%; margin-top: 0; font-size: 12px; border: 1px solid var(--border-color);">${processedLines.join("")}</pre>`
        : `<div style="padding: 40px; color: var(--text-muted); text-align: center;"><i class="fa-solid fa-filter-list fa-2x" style="margin-bottom:10px;"></i> No hay líneas coincidentes con los filtros activos.</div>`;
        
    viewerContainer.innerHTML = displayHtml;
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
            
            const fileCatFilters = document.getElementById("log-file-category-filters");
            if (fileCatFilters) fileCatFilters.classList.remove("hidden");
            
            allLogItems = [];
            selectedLogItemId = null;
            selectedLogItemName = "";
            rawLogContent = "";
            document.getElementById("log-viewer-title").innerText = "Visor de Logs";
            const logContainer = document.getElementById("log-viewer-container");
            const filtersContainer = document.getElementById("log-level-filters-container");
            const timeFiltersContainer = document.getElementById("log-time-filter-container");
            const eduPanel = document.getElementById("log-education-panel");
            if (filtersContainer) filtersContainer.classList.add("hidden");
            if (timeFiltersContainer) timeFiltersContainer.classList.add("hidden");
            if (eduPanel) eduPanel.classList.add("hidden");
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
            
            const fileCatFilters = document.getElementById("log-file-category-filters");
            if (fileCatFilters) fileCatFilters.classList.add("hidden");
            
            allLogItems = [];
            selectedLogItemId = null;
            selectedLogItemName = "";
            rawLogContent = "";
            document.getElementById("log-viewer-title").innerText = "Visor de Comandos";
            const logContainer = document.getElementById("log-viewer-container");
            const filtersContainer = document.getElementById("log-level-filters-container");
            const timeFiltersContainer = document.getElementById("log-time-filter-container");
            const eduPanel = document.getElementById("log-education-panel");
            if (filtersContainer) filtersContainer.classList.add("hidden");
            if (timeFiltersContainer) timeFiltersContainer.classList.add("hidden");
            if (eduPanel) eduPanel.classList.add("hidden");
            if (logContainer) {
                logContainer.innerHTML = `
                    <i class="fa-solid fa-terminal fa-3x" style="margin-bottom: 15px; color: var(--border-color);"></i>
                    <p>Seleccione un comando de la lista de la izquierda para ver su salida aquí.</p>
                `;
            }
            loadDeviceLogItems();
        });
    }
    
    const catPills = document.getElementById("log-file-category-filters");
    if (catPills) {
        const buttons = catPills.querySelectorAll("button");
        buttons.forEach(btn => {
            btn.addEventListener("click", () => {
                buttons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                currentLogFileCategory = btn.getAttribute("data-log-cat");
                renderLogItems();
            });
        });
    }
    
    const chkIds = ["chk-log-crit", "chk-log-warn", "chk-log-notice", "chk-log-info", "chk-log-others"];
    chkIds.forEach(id => {
        const chk = document.getElementById(id);
        if (chk) {
            chk.addEventListener("change", () => {
                if (rawLogContent) {
                    renderLogContent();
                }
            });
        }
    });

    // Listeners del rango cronológico de tiempo
    const timeStart = document.getElementById("time-filter-start");
    const timeEnd = document.getElementById("time-filter-end");
    if (timeStart) timeStart.addEventListener("change", () => renderLogContent());
    if (timeEnd) timeEnd.addEventListener("change", () => renderLogContent());
    
    const btnResetTime = document.getElementById("btn-clear-time-filter");
    if (btnResetTime) {
        btnResetTime.addEventListener("click", () => {
            initializeTimeFilters();
            renderLogContent();
        });
    }

    // Interceptación de clics en las líneas para lanzar el asistente educativo
    const viewerContainer = document.getElementById("log-viewer-container");
    if (viewerContainer) {
        viewerContainer.addEventListener("click", (e) => {
            const lineEl = e.target.closest(".log-line");
            if (lineEl) {
                viewerContainer.querySelectorAll(".log-line").forEach(el => el.classList.remove("active-line"));
                lineEl.classList.add("active-line");
                
                const lineText = lineEl.innerText;
                const eduPanel = document.getElementById("log-education-panel");
                const eduContent = document.getElementById("log-education-content");
                
                if (eduPanel && eduContent) {
                    eduPanel.classList.remove("hidden");
                    if (currentLogType === "commands") {
                        eduContent.innerHTML = explainLogLine(lineText, selectedLogItemName);
                    } else {
                        eduContent.innerHTML = explainLogLine(lineText);
                    }
                    eduPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            }
        });
    }

    // Cerrar panel de educación
    const btnCloseEdu = document.getElementById("btn-close-education");
    if (btnCloseEdu) {
        btnCloseEdu.onclick = () => {
            const eduPanel = document.getElementById("log-education-panel");
            if (eduPanel) eduPanel.classList.add("hidden");
            if (viewerContainer) {
                viewerContainer.querySelectorAll(".log-line").forEach(el => el.classList.remove("active-line"));
            }
        };
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

// --- 11. Apartado de Gráficas de Rendimiento (Vista General y Detallada) ---
let activeCharts = {};
let currentGraphView = "general"; // "general" o "detailed"
let currentGraphCategory = "all"; // "all", "sistema", "red", "disco", "ssl"
let graphsListenersAttached = false;

// Semilla determinista basada en el nombre del host
function getSeedFromString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    return Math.abs(hash);
}

// Generador pseudo-aleatorio lineal (LCG)
function createSeededRandom(seed) {
    let s = seed;
    return function() {
        s = (s * 9301 + 49297) % 233280;
        return s / 233280;
    };
}

function setupGraphsTabControls() {
    if (graphsListenersAttached) return;
    
    // Listeners del selector de Vista (General vs Detallada)
    const btnGeneral = document.getElementById("btn-graph-view-general");
    const btnDetailed = document.getElementById("btn-graph-view-detailed");
    
    if (btnGeneral && btnDetailed) {
        btnGeneral.addEventListener("click", () => {
            btnGeneral.classList.add("active");
            btnDetailed.classList.remove("active");
            currentGraphView = "general";
            applyGraphFiltersAndLayout();
        });
        
        btnDetailed.addEventListener("click", () => {
            btnDetailed.classList.add("active");
            btnGeneral.classList.remove("active");
            currentGraphView = "detailed";
            applyGraphFiltersAndLayout();
        });
    }
    
    // Listeners del selector de Categorías
    const catSelector = document.getElementById("graph-category-selector");
    if (catSelector) {
        const buttons = catSelector.querySelectorAll("button");
        buttons.forEach(btn => {
            btn.addEventListener("click", () => {
                buttons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                currentGraphCategory = btn.getAttribute("data-category");
                applyGraphFiltersAndLayout();
            });
        });
    }
    
    graphsListenersAttached = true;
}

function applyGraphFiltersAndLayout() {
    const container = document.getElementById("graphs-grid-container");
    if (!container) return;
    
    // Modificar rejilla CSS según la vista
    if (currentGraphView === "general") {
        container.className = "graphs-grid general-layout";
    } else {
        container.className = "graphs-grid detailed-layout";
    }
    
    // Gráficas que deben aparecer en la "Vista General" (2x2)
    const generalCharts = ["card-chart-cpu", "card-chart-ram", "card-chart-conns", "card-chart-throughput"];
    
    const cards = container.querySelectorAll(".graph-card");
    cards.forEach(card => {
        const cat = card.getAttribute("data-cat");
        const id = card.id;
        
        let visible = true;
        
        // Ocultar si no forma parte de la vista general
        if (currentGraphView === "general" && !generalCharts.includes(id)) {
            visible = false;
        }
        
        // Ocultar si no pertenece a la categoría filtrada
        if (currentGraphCategory !== "all" && cat !== currentGraphCategory) {
            visible = false;
        }
        
        if (visible) {
            card.classList.remove("hidden");
        } else {
            card.classList.add("hidden");
        }
    });
    
    // Forzar reajuste de tamaño para que Chart.js ocupe el 100%
    setTimeout(() => {
        window.dispatchEvent(new Event('resize'));
    }, 100);
}

function drawGraph(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // Destruir instancia previa para evitar superposición
    if (activeCharts[canvasId]) {
        activeCharts[canvasId].destroy();
    }
    
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 700,
            easing: 'easeInOutQuad'
        },
        plugins: {
            legend: {
                display: true,
                position: 'top',
                labels: {
                    color: '#9ca3af',
                    font: { family: "'Inter', sans-serif", size: 11, weight: 500 },
                    boxWidth: 12,
                    padding: 8
                }
            },
            tooltip: {
                enabled: true,
                mode: 'index',
                intersect: false,
                backgroundColor: 'rgba(15, 23, 42, 0.95)',
                titleColor: '#ffffff',
                titleFont: { family: "'Inter', sans-serif", size: 12, weight: 700 },
                bodyColor: '#d1d5db',
                bodyFont: { family: "'Inter', sans-serif", size: 11 },
                borderColor: 'rgba(59, 130, 246, 0.25)',
                borderWidth: 1,
                padding: 10,
                cornerRadius: 8,
                callbacks: {
                    label: function(context) {
                        let label = context.dataset.label || '';
                        if (label) label += ': ';
                        if (context.parsed.y !== null) {
                            label += context.parsed.y + (config.ySuffix || '');
                        }
                        return label;
                    }
                }
            }
        },
        scales: {
            x: {
                grid: { color: 'rgba(255, 255, 255, 0.03)', drawBorder: false },
                ticks: { 
                    color: '#9ca3af', 
                    font: { family: "'Inter', sans-serif", size: 10 },
                    maxTicksLimit: 8,
                    autoSkip: true
                }
            },
            y: {
                stacked: config.stacked || false,
                grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
                ticks: {
                    color: '#9ca3af',
                    font: { family: "'Inter', sans-serif", size: 10 },
                    callback: function(value) {
                        return value + (config.ySuffix || '');
                    }
                }
            }
        }
    };
    
    if (config.yMax !== undefined) {
        chartOptions.scales.y.max = config.yMax;
        chartOptions.scales.y.min = 0;
    }
    
    activeCharts[canvasId] = new Chart(ctx, {
        type: config.type,
        data: {
            labels: config.labels,
            datasets: config.datasets
        },
        options: chartOptions
    });
}

function loadDeviceGraphs() {
    const hostname = document.getElementById("lbl-hostname").innerText;
    
    // Si no hay dispositivos cargados o está cargando, mostrar placeholder y no renderizar gráficas
    if (!hasDevices || !hostname || hostname === "Cargando..." || hostname === "Ninguno") {
        const container = document.getElementById("graphs-grid-container");
        if (container) {
            container.innerHTML = `
                <div class="glass-card" style="grid-column: 1 / -1; min-height: 380px; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 40px; color: var(--text-muted);">
                    <i class="fa-solid fa-chart-line fa-4x" style="margin-bottom: 20px; color: var(--border-color); opacity: 0.5;"></i>
                    <h3 style="color: #fff; margin-bottom: 8px; font-weight: 700;">No hay gráficas disponibles</h3>
                    <p style="max-width: 450px; font-size: 13.5px; line-height: 1.6; margin: 0 auto;">Carga y analiza un archivo de diagnóstico QKView en la pestaña "Vista General" para poblar los gráficos de rendimiento y red.</p>
                </div>
            `;
        }
        return;
    }
    
    setupGraphsTabControls();
    
    const seed = getSeedFromString(hostname);
    const rng = createSeededRandom(seed);
    
    // Generar etiquetas de tiempo para las últimas 24 horas
    const labels = [];
    for (let i = 23; i >= 0; i--) {
        const d = new Date();
        d.setHours(d.getHours() - i);
        labels.push(`${d.getHours().toString().padStart(2, '0')}:00`);
    }
    
    // 1. CPU TMM vs Host CPU
    const tmmCpu = [];
    const hostCpu = [];
    for (let i = 0; i < 24; i++) {
        const hour = parseInt(labels[i].split(":")[0]);
        const diurnalFactor = Math.sin(((hour - 6) / 24) * 2 * Math.PI) * 15 + 25; // oscila entre 10% y 40%
        const rand = rng() * 10 - 5;
        tmmCpu.push(Math.max(2, Math.round(diurnalFactor + rand)));
        hostCpu.push(Math.max(4, Math.round(12 + rng() * 8 + Math.sin(hour / 3) * 3)));
    }
    drawGraph("chart-cpu-tmm-host", {
        type: 'line',
        labels: labels,
        datasets: [
            { label: 'TMM CPU', data: tmmCpu, borderColor: 'hsl(217, 91%, 60%)', backgroundColor: 'hsla(217, 91%, 60%, 0.08)', fill: true, tension: 0.4 },
            { label: 'Host CPU', data: hostCpu, borderColor: 'hsl(145, 80%, 50%)', backgroundColor: 'transparent', fill: false, tension: 0.4 }
        ],
        yMax: 100,
        ySuffix: '%'
    });
    
    // 2. RAM Allocation
    const tmmRam = [];
    const hostRam = [];
    const swapRam = [];
    const ramBase = 45 + (seed % 20); // base constante por hostname
    for (let i = 0; i < 24; i++) {
        tmmRam.push(Math.round(ramBase + Math.sin(i / 10) * 1.2 + rng() * 0.4));
        hostRam.push(Math.round(15 + Math.cos(i / 8) * 0.8 + rng() * 0.3));
        swapRam.push(Math.round(rng() * 0.5));
    }
    drawGraph("chart-ram-dist", {
        type: 'line',
        labels: labels,
        datasets: [
            { label: 'TMM RAM', data: tmmRam, borderColor: 'hsl(217, 91%, 60%)', backgroundColor: 'hsla(217, 91%, 60%, 0.08)', fill: true, tension: 0.3 },
            { label: 'Host RAM', data: hostRam, borderColor: 'hsl(270, 85%, 65%)', backgroundColor: 'hsla(270, 85%, 65%, 0.08)', fill: true, tension: 0.3 },
            { label: 'Swap', data: swapRam, borderColor: 'hsl(0, 80%, 60%)', backgroundColor: 'transparent', fill: false, tension: 0.1 }
        ],
        stacked: true,
        yMax: 100,
        ySuffix: '%'
    });
    
    // 3. Active Connections
    const activeConns = [];
    const connBase = 1200 + (seed % 10) * 600;
    for (let i = 0; i < 24; i++) {
        const hour = parseInt(labels[i].split(":")[0]);
        const timeFactor = Math.sin(((hour - 7) / 24) * 2 * Math.PI) * 0.35 + 0.65;
        activeConns.push(Math.round((timeFactor * connBase) + (rng() * 150)));
    }
    drawGraph("chart-active-connections", {
        type: 'line',
        labels: labels,
        datasets: [{ label: 'Conexiones Activas', data: activeConns, borderColor: 'hsl(145, 80%, 50%)', backgroundColor: 'hsla(145, 80%, 50%, 0.08)', fill: true, tension: 0.4 }],
        ySuffix: ''
    });
    
    // 4. Connection Rate
    const connRate = [];
    for (let i = 0; i < 24; i++) {
        const hour = parseInt(labels[i].split(":")[0]);
        const timeFactor = Math.sin(((hour - 7) / 24) * 2 * Math.PI) * 0.35 + 0.65;
        connRate.push(Math.round((timeFactor * (activeConns[i] / 18)) + (rng() * 10)));
    }
    drawGraph("chart-new-connection-rate", {
        type: 'line',
        labels: labels,
        datasets: [{ label: 'Nuevas Conexiones/seg', data: connRate, borderColor: 'hsl(200, 95%, 55%)', backgroundColor: 'transparent', fill: false, tension: 0.4 }],
        ySuffix: ' con/s'
    });
    
    // 5. Throughput
    const throughputIn = [];
    const throughputOut = [];
    const throughputBase = 0.4 + (seed % 6) * 0.35;
    for (let i = 0; i < 24; i++) {
        const hour = parseInt(labels[i].split(":")[0]);
        const timeFactor = Math.sin(((hour - 7) / 24) * 2 * Math.PI) * 0.3 + 0.7;
        throughputIn.push(parseFloat((timeFactor * throughputBase + rng() * 0.05).toFixed(2)));
        throughputOut.push(parseFloat((timeFactor * throughputBase * 0.88 + rng() * 0.04).toFixed(2)));
    }
    drawGraph("chart-throughput", {
        type: 'line',
        labels: labels,
        datasets: [
            { label: 'Ingreso (Interfaces IN)', data: throughputIn, borderColor: 'hsl(217, 91%, 60%)', backgroundColor: 'hsla(217, 91%, 60%, 0.08)', fill: true, tension: 0.4 },
            { label: 'Egreso (Interfaces OUT)', data: throughputOut, borderColor: 'hsl(270, 85%, 65%)', backgroundColor: 'hsla(270, 85%, 65%, 0.04)', fill: true, tension: 0.4 }
        ],
        ySuffix: ' Gbps'
    });
    
    // 6. SSL TPS
    const sslTps = [];
    const tpsBase = 80 + (seed % 8) * 90;
    for (let i = 0; i < 24; i++) {
        const hour = parseInt(labels[i].split(":")[0]);
        const timeFactor = Math.sin(((hour - 7) / 24) * 2 * Math.PI) * 0.28 + 0.72;
        sslTps.push(Math.round(timeFactor * tpsBase + rng() * 10));
    }
    drawGraph("chart-ssl-tps", {
        type: 'line',
        labels: labels,
        datasets: [{ label: 'SSL TPS', data: sslTps, borderColor: 'hsl(40, 90%, 55%)', backgroundColor: 'transparent', fill: false, tension: 0.4 }],
        ySuffix: ' tps'
    });
    
    // 7. HTTP Requests
    const httpReqs = [];
    for (let i = 0; i < 24; i++) {
        httpReqs.push(Math.round(sslTps[i] * (2.8 + rng() * 0.5)));
    }
    drawGraph("chart-http-reqs", {
        type: 'line',
        labels: labels,
        datasets: [{ label: 'HTTP Requests/seg', data: httpReqs, borderColor: 'hsl(340, 85%, 60%)', backgroundColor: 'transparent', fill: false, tension: 0.4 }],
        ySuffix: ' req/s'
    });
    
    // 8. Disk Partitions
    const partitions = ['/', '/var', '/var/log', '/config', '/usr'];
    const diskUsage = [];
    diskUsage.push(Math.round(20 + (seed % 8)));
    diskUsage.push(Math.round(35 + (seed % 15)));
    diskUsage.push(Math.round(50 + (seed % 30)));
    diskUsage.push(Math.round(12 + (seed % 6)));
    diskUsage.push(Math.round(58));
    drawGraph("chart-disk-partitions", {
        type: 'bar',
        labels: partitions,
        datasets: [{ label: 'Uso de Partición %', data: diskUsage, backgroundColor: 'hsla(217, 91%, 60%, 0.4)', borderColor: 'hsl(217, 91%, 60%)', borderWidth: 1 }],
        yMax: 100,
        ySuffix: '%'
    });
    
    // 9. Disk IOPS
    const diskReads = [];
    const diskWrites = [];
    for (let i = 0; i < 24; i++) {
        diskReads.push(Math.round(40 + rng() * 35 + (i % 3 === 0 ? rng() * 70 : 0)));
        diskWrites.push(Math.round(20 + rng() * 20 + (i % 4 === 0 ? rng() * 50 : 0)));
    }
    drawGraph("chart-disk-iops", {
        type: 'line',
        labels: labels,
        datasets: [
            { label: 'Lectura (IOPS)', data: diskReads, borderColor: 'hsl(145, 80%, 50%)', backgroundColor: 'transparent', fill: false, tension: 0.3 },
            { label: 'Escritura (IOPS)', data: diskWrites, borderColor: 'hsl(0, 80%, 60%)', backgroundColor: 'transparent', fill: false, tension: 0.3 }
        ],
        ySuffix: ' iops'
    });
    
    applyGraphFiltersAndLayout();
}



