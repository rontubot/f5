# F5 iHealth Watcher & Automated Diagnostic Ecosistema

Este repositorio contiene la arquitectura de software completa para automatizar la recolección de diagnósticos (`QKView`) e informes de respaldo (`UCS`) desde dispositivos F5 BIG-IP, procesarlos a través de la API oficial de F5 iHealth, y visualizarlos en un panel de control web moderno, privado y multi-dispositivo.

---

## 1. Estructura del Proyecto

Para organizar este proyecto de cara a tu repositorio de GitHub (`rontubot/f5`), hemos estructurado el código en tres módulos independientes y profesionales:

```text
f5-ihealth-watcher/
├── client/                 # Agente/Scripts para instalar en el F5 BIG-IP
│   ├── backup_ucs.sh       # Respaldos UCS con rotación (mantiene 5)
│   ├── generate_qkview.sh  # Generación de QKViews y envío HTTP POST
│   └── README.md           # Guía de instalación rápida en el F5
└── backend/                # Servidor de Tránsito (API en Python FastAPI)
    ├── main.py             # Servidor API (Endpoints de carga y consulta)
    ├── ihealth.py          # Cliente API de F5 iHealth (OAuth2, upload, poll)
    ├── requirements.txt    # Dependencias de Python (incluye aiofiles)
    ├── Procfile            # Comando de arranque para Railway
    ├── database/           # Diagnósticos históricos en JSON
    └── frontend/           # Panel de Control Visual (Dashboard Web integrado)
        ├── index.html      # Interfaz de usuario premium (Dark Mode)
        ├── styles.css      # Estilos modernos con Glassmorphism
        └── app.js          # Controlador interactivo y consumo de API
```

---

## 2. Flujo de Funcionamiento Técnico

1.  **Generación:** El F5 BIG-IP (módulo `client`) corre un script diario que genera un archivo de diagnóstico ligero (`.qkview`).
2.  **Tránsito Seguro:** El F5 envía el archivo mediante un túnel seguro HTTPS POST a la API de tu `backend` de tránsito.
3.  **Análisis en la Nube:** Tu `backend` recibe el archivo, solicita un token OAuth2 a F5 iHealth, sube el QKView de forma segura, espera a que termine el procesamiento y descarga los resultados en un JSON estructurado.
4.  **Visualización:** El `frontend` lee los datos del backend y te muestra de forma gráfica y cómoda el estado de salud, alertas críticas de red, vulnerabilidades de seguridad (CVEs) y las soluciones oficiales recomendadas por F5.

---

## 3. Potencial de Monetización y Patente (SaaS)
Este ecosistema resuelve un problema real para empresas que gestionan decenas de F5s y para proveedores de servicios gestionados (MSPs):

*   **Panel Multi-Tenant:** Centraliza la salud de múltiples F5s de diferentes clientes en una sola pantalla (BIG-IQ de F5 es costoso y complejo de desplegar).
*   **Alertas de Seguridad Proactivas:** Mapea de forma inmediata qué CVEs de seguridad afectan a la versión específica del F5 del cliente sin tener que subir archivos manualmente.
*   **Reportes de Cumplimiento:** Generación de PDFs semanales de auditoría de configuración para enviar a los clientes como servicio de valor agregado.

---

## 4. Cómo empezar a desarrollar

Los archivos correspondientes a cada módulo han sido generados y organizados en este espacio de trabajo. 

Como la consola local no tiene acceso directo a comandos de Git en tu variable de entorno, puedes copiar esta carpeta completa en tu repositorio local sincronizado con GitHub (`rontubot/f5`) y subirla ejecutando desde tu Git Bash local:

```bash
git add .
git commit -m "Initial commit of F5 iHealth Watcher Ecosystem"
git push origin main
```
