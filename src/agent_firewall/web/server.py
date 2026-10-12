import asyncio
import logging
from typing import Dict, Set, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("agent_firewall.web.server")

class ConnectionManager:
    """Manages active WebSocket connections for real-time dashboard telemetry."""
    
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.debug("WebSocket client connected. Total active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        logger.debug("WebSocket client disconnected. Total active: %d", len(self.active_connections))

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcasts structured telemetry events to all connected UI clients."""
        if not self.active_connections:
            return
            
        message = {
            "type": event_type,
            "data": data
        }
        
        dead_connections: Set[WebSocket] = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning("Failed to send telemetry to WebSocket client: %s", e)
                dead_connections.add(connection)
                
        for dead in dead_connections:
            self.disconnect(dead)


# Global connection manager instance
manager = ConnectionManager()

def create_app(audit_logger: Any = None) -> FastAPI:
    """Factory function to initialize and configure the FastAPI web application and WebSocket endpoints."""
    app = FastAPI(
        title="Agent Firewall",
        description="Sovereign Security & Observability Proxy for Autonomous AI Agents",
        version="1.0.0"
    )

    @app.get("/health", response_class=JSONResponse)
    async def health_check() -> Dict[str, str]:
        """System health and readiness check."""
        return {"status": "operational", "sovereign": "secured"}

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """Real-time telemetry stream for the Cyberpunk Tailwind dashboard."""
        await manager.connect(websocket)
        try:
            while True:
                # Keep connection alive and handle incoming client commands if any
                data = await websocket.receive_text()
                # Acknowledge heartbeat or ping
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error("WebSocket error encountered: %s", e)
            manager.disconnect(websocket)

    @app.get("/api/stats", response_class=JSONResponse)
    async def get_stats() -> Dict[str, Any]:
        """Retrieves aggregated security metrics from the audit log store."""
        if not audit_logger:
            return {
                "total_requests": 0,
                "blocked_requests": 0,
                "secrets_redacted": 0,
                "budget_spent": 0.0
            }
        
        try:
            stats = audit_logger.get_aggregated_stats()
            return stats
        except Exception as e:
            logger.error("Failed to fetch aggregate stats: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal database retrieval error"
            )

    @app.get("/api/logs", response_class=JSONResponse)
    async def get_recent_logs(limit: int = 50) -> list:
        """Retrieves recent intercepted request logs."""
        if not audit_logger:
            return []
            
        try:
            logs = audit_logger.get_recent_logs(limit=limit)
            return logs
        except Exception as e:
            logger.error("Failed to fetch recent logs: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal database retrieval error"
            )

    # Mount static assets if needed, or fallback to embedded dashboard HTML view
    @app.get("/", response_class=HTMLResponse)
    async def serve_dashboard() -> str:
        """Serves the Cyberpunk Tailwind single-page application dashboard."""
        return """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Firewall // Sovereign Security Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        cyber: {
                            bg: '#05050a',
                            panel: '#0a0a16',
                            border: '#1e1e3f',
                            cyan: '#00f0ff',
                            magenta: '#ff007f',
                            yellow: '#f3e600',
                            green: '#00ff66'
                        }
                    }
                }
            }
        }
    </script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'JetBrains Mono', monospace; }
        .glow-cyan { text-shadow: 0 0 10px rgba(0, 240, 255, 0.6); }
        .glow-magenta { text-shadow: 0 0 10px rgba(255, 0, 127, 0.6); }
        .glow-box { box-shadow: 0 0 15px rgba(0, 240, 255, 0.15); }
    </style>
</head>
<body class="bg-cyber-bg text-gray-200 min-h-screen flex flex-col">
    <!-- Top Nav -->
    <header class="border-b border-cyber-border bg-cyber-panel/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-3 h-3 bg-cyber-cyan rounded-full animate-ping"></div>
            <h1 class="text-xl font-bold tracking-wider text-cyber-cyan glow-cyan">AGENT_FIREWALL // SOVEREIGN_PROXY</h1>
        </div>
        <div class="flex items-center space-x-4 text-xs">
            <span id="ws-status" class="px-2.5 py-1 rounded border border-cyber-yellow text-cyber-yellow">CONNECTING...</span>
            <span class="text-gray-400">SECURE WAL DB ACTIVE</span>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 p-6 grid grid-cols-1 lg:grid-cols-4 gap-6 max-w-[1800px] w-full mx-auto">
        <!-- Left Column: Metrics & Stats -->
        <div class="lg:col-span-1 flex flex-col gap-6">
            <div class="bg-cyber-panel border border-cyber-border rounded-xl p-5 glow-box">
                <h2 class="text-sm uppercase tracking-widest text-gray-400 mb-4 font-bold">Telemetry Metrics</h2>
                <div class="space-y-4">
                    <div class="bg-cyber-bg p-3 rounded border border-cyber-border">
                        <div class="text-xs text-gray-400">Total Intercepted</div>
                        <div id="metric-total" class="text-2xl font-bold text-cyber-cyan">0</div>
                    </div>
                    <div class="bg-cyber-bg p-3 rounded border border-cyber-border">
                        <div class="text-xs text-gray-400">Blocked Threats</div>
                        <div id="metric-blocked" class="text-2xl font-bold text-cyber-magenta">0</div>
                    </div>
                    <div class="bg-cyber-bg p-3 rounded border border-cyber-border">
                        <div class="text-xs text-gray-400">Secrets Redacted</div>
                        <div id="metric-secrets" class="text-2xl font-bold text-cyber-yellow">0</div>
                    </div>
                    <div class="bg-cyber-bg p-3 rounded border border-cyber-border">
                        <div class="text-xs text-gray-400">Token Budget Spent</div>
                        <div id="metric-budget" class="text-2xl font-bold text-cyber-green">$0.0000</div>
                    </div>
                </div>
            </div>

            <div class="bg-cyber-panel border border-cyber-border rounded-xl p-5 glow-box flex-1">
                <h2 class="text-sm uppercase tracking-widest text-gray-400 mb-4 font-bold">Active Defenses</h2>
                <ul class="space-y-2 text-xs">
                    <li class="flex items-center justify-between p-2 bg-cyber-bg rounded border border-cyber-border">
                        <span>Secret Redaction</span>
                        <span class="text-cyber-green font-bold">ACTIVE</span>
                    </li>
                    <li class="flex items-center justify-between p-2 bg-cyber-bg rounded border border-cyber-border">
                        <span>Bash Command Block</span>
                        <span class="text-cyber-green font-bold">ACTIVE</span>
                    </li>
                    <li class="flex items-center justify-between p-2 bg-cyber-bg rounded border border-cyber-border">
                        <span>Token Circuit Breaker</span>
                        <span class="text-cyber-green font-bold">ACTIVE</span>
                    </li>
                </ul>
            </div>
        </div>

        <!-- Right Column: Real-Time Stream -->
        <div class="lg:col-span-3 flex flex-col bg-cyber-panel border border-cyber-border rounded-xl p-5 glow-box">
            <div class="flex justify-between items-center mb-4 pb-3 border-b border-cyber-border">
                <h2 class="text-sm uppercase tracking-widest text-gray-400 font-bold">Live Request Stream</h2>
                <button onclick="clearLogs()" class="text-xs px-3 py-1 bg-cyber-bg border border-cyber-border hover:border-cyber-cyan text-gray-300 rounded transition">Clear View</button>
            </div>
            
            <div id="log-container" class="flex-1 overflow-y-auto space-y-3 max-h-[700px] pr-2">
                <!-- Log entries injected dynamically -->
                <div class="text-xs text-gray-500 italic text-center py-12">Listening for autonomous agent traffic...</div>
            </div>
        </div>
    </main>

    <footer class="border-t border-cyber-border bg-cyber-panel/80 py-4 px-6 text-center text-xs text-gray-500">
        Agent Firewall v1.0.0 // Sovereign Autonomous Security Subsystem
    </footer>

    <script>
        let ws;
        const logContainer = document.getElementById('log-container');
        const wsStatus = document.getElementById('ws-status');
        
        const metricTotal = document.getElementById('metric-total');
        const metricBlocked = document.getElementById('metric-blocked');
        const metricSecrets = document.getElementById('metric-secrets');
        const metricBudget = document.getElementById('metric-budget');

        let statsData = { total: 0, blocked: 0, secrets: 0, budget: 0.0 };

        function updateStatsDisplay() {
            metricTotal.textContent = statsData.total;
            metricBlocked.textContent = statsData.blocked;
            metricSecrets.textContent = statsData.secrets;
            metricBudget.textContent = '$' + statsData.budget.toFixed(4);
        }

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onopen = () => {
                wsStatus.textContent = 'CONNECTED';
                wsStatus.className = 'px-2.5 py-1 rounded border border-cyber-green text-cyber-green';
            };

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'telemetry') {
                        addLogEntry(message.data);
                    }
                } catch (err) {
                    console.error('Failed to parse WS message:', err);
                }
            };

            ws.onclose = () => {
                wsStatus.textContent = 'RECONNECTING...';
                wsStatus.className = 'px-2.5 py-1 rounded border border-cyber-magenta text-cyber-magenta';
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = (err) => {
                console.error('WebSocket error:', err);
                ws.close();
            };
        }

        function addLogEntry(data) {
            // Remove placeholder if present
            if (logContainer.querySelector('.italic')) {
                logContainer.innerHTML = '';
            }

            // Update stats
            statsData.total += 1;
            if (data.blocked) statsData.blocked += 1;
            if (data.redacted_count) statsData.secrets += data.redacted_count;
            if (data.cost) statsData.budget += data.cost;
            updateStatsDisplay();

            const entry = document.createElement('div');
            entry.className = `p-4 rounded border text-xs bg-cyber-bg transition-all duration-300 ${data.blocked ? 'border-cyber-magenta/60' : 'border-cyber-border'}`;
            
            const timestamp = new Date(data.timestamp * 1000).toLocaleTimeString();
            const statusColor = data.blocked ? 'text-cyber-magenta' : 'text-cyber-green';
            const statusText = data.blocked ? 'BLOCKED' : 'ALLOWED';

            entry.innerHTML = `
                <div class="flex justify-between items-center mb-2">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded font-bold ${statusColor} border border-current">${statusText}</span>
                        <span class="text-gray-400 uppercase font-bold">${data.provider || 'UNKNOWN'}</span>
                        <span class="text-gray-500">model: ${data.model || 'N/A'}</span>
                    </div>
                    <span class="text-gray-500">${timestamp}</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-gray-300 mt-2">
                    <div>Tokens: <span class="text-cyber-cyan">${data.total_tokens || 0}</span></div>
                    <div>Cost: <span class="text-cyber-green">$${(data.cost || 0).toFixed(4)}</span></div>
                    <div>Secrets Redacted: <span class="text-cyber-yellow">${data.redacted_count || 0}</span></div>
                    <div>Latency: <span class="text-gray-300">${(data.latency_ms || 0).toFixed(0)}ms</span></div>
                </div>
                ${data.block_reason ? `<div class="mt-2 p-2 rounded bg-cyber-magenta/10 border border-cyber-magenta/30 text-cyber-magenta font-bold">Reason: ${data.block_reason}</div>` : ''}
            `;

            logContainer.prepend(entry);
            
            // Cap at 100 entries in DOM
            if (logContainer.children.length > 100) {
                logContainer.removeChild(logContainer.lastChild);
            }
        }

        function clearLogs() {
            logContainer.innerHTML = '<div class="text-xs text-gray-500 italic text-center py-12">Listening for autonomous agent traffic...</div>';
        }

        // Fetch initial metrics on load
        async function fetchInitialStats() {
            try {
                const res = await fetch('/api/stats');
                if (res.ok) {
                    const data = await res.json();
                    statsData.total = data.total_requests || 0;
                    statsData.blocked = data.blocked_requests || 0;
                    statsData.secrets = data.secrets_redacted || 0;
                    statsData.budget = data.budget_spent || 0.0;
                    updateStatsDisplay();
                }
            } catch (err) {
                console.error('Failed to fetch initial stats:', err);
            }
        }

        fetchInitialStats();
        connectWebSocket();
    </script>
</body>
</html>
"""

    return app
