/**
 * Agent Firewall - Sovereign Security & Observability Proxy
 * Frontend State Management and WebSocket Client Logic
 */

class FirewallDashboard {
    constructor() {
        this.state = {
            connected: false,
            stats: {
                total_requests: 0,
                blocked_requests: 0,
                secrets_redacted: 0,
                tokens_used: 0,
                budget_spent: 0.0,
                budget_limit: 10.0
            },
            requests: [],
            selectedRequest: null,
            filter: 'all', // 'all', 'allowed', 'blocked', 'redacted'
            searchQuery: '',
            autoScroll: true
        };

        this.ws = null;
        this.wsReconnectInterval = 3000;
        this.maxRequestsLimit = 100;

        this.initDOM();
        this.initEventListeners();
        this.connectWebSocket();
        this.fetchInitialData();
    }

    initDOM() {
        // Status indicators
        this.wsStatusEl = document.getElementById('ws-status');
        this.wsDotEl = document.getElementById('ws-dot');
        this.wsTextEl = document.getElementById('ws-text');

        // Metrics elements
        this.metricTotalReq = document.getElementById('metric-total-requests');
        this.metricBlockedReq = document.getElementById('metric-blocked-requests');
        this.metricSecretsRedacted = document.getElementById('metric-secrets-redacted');
        this.metricTokenBudget = document.getElementById('metric-token-budget');
        this.budgetProgressBar = document.getElementById('budget-progress-bar');

        // Controls & Filters
        this.searchInput = document.getElementById('search-input');
        this.filterButtons = document.querySelectorAll('.filter-btn');
        this.clearLogsBtn = document.getElementById('clear-logs-btn');

        // Table & Modal
        this.requestsTableBody = document.getElementById('requests-table-body');
        this.emptyStateEl = document.getElementById('empty-state');
        this.requestModal = document.getElementById('request-modal');
        this.modalCloseBtn = document.getElementById('modal-close-btn');
        this.modalContent = document.getElementById('modal-content');
    }

    initEventListeners() {
        // Filter buttons
        this.filterButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.filterButtons.forEach(b => b.classList.remove('active', 'border-cyan-500', 'text-cyan-400'));
                b.classList.add('border-slate-700', 'text-slate-400');
                
                const target = e.currentTarget;
                target.classList.remove('border-slate-700', 'text-slate-400');
                target.classList.add('active', 'border-cyan-500', 'text-cyan-400');

                this.state.filter = target.dataset.filter;
                this.renderRequests();
            });
        });

        // Search input
        this.searchInput.addEventListener('input', (e) => {
            this.state.searchQuery = e.target.value.toLowerCase();
            this.renderRequests();
        });

        // Clear logs
        this.clearLogsBtn.addEventListener('click', () => {
            this.state.requests = [];
            this.renderRequests();
            this.showToast('Local view cleared', 'info');
        });

        // Modal close
        this.modalCloseBtn.addEventListener('click', () => this.closeModal());
        this.requestModal.addEventListener('click', (e) => {
            if (e.target === this.requestModal) this.closeModal();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
        });
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.updateConnectionStatus('connecting', 'Connecting to Sovereign Proxy...');

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                this.state.connected = true;
                this.updateConnectionStatus('connected', 'Sovereign Proxy Connected');
                this.showToast('Established real-time secure telemetry link', 'success');
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                } catch (err) {
                    console.error('Failed to parse incoming WebSocket message:', err);
                }
            };

            this.ws.onclose = () => {
                this.state.connected = false;
                this.updateConnectionStatus('disconnected', 'Disconnected. Reconnecting...');
                setTimeout(() => this.connectWebSocket(), this.wsReconnectInterval);
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket encountered error:', error);
                this.ws.close();
            };
        } catch (err) {
            console.error('Failed to initialize WebSocket connection:', err);
            setTimeout(() => this.connectWebSocket(), this.wsReconnectInterval);
        }
    }

    updateConnectionStatus(status, text) {
        this.wsTextEl.textContent = text;
        this.wsDotEl.className = 'w-2.5 h-2.5 rounded-full animate-pulse';

        if (status === 'connected') {
            this.wsDotEl.classList.add('bg-emerald-400', 'shadow-[0_0_8px_#34d399]');
        } else if (status === 'connecting') {
            this.wsDotEl.classList.add('bg-amber-400', 'shadow-[0_0_8px_#fbbf24]');
        } else {
            this.wsDotEl.classList.add('bg-rose-500', 'shadow-[0_0_8px_#f43f5e]');
        }
    }

    async fetchInitialData() {
        try {
            const response = await fetch('/api/stats');
            if (!response.ok) throw new Error('Failed to fetch initial stats');
            const data = await response.json();
            this.updateStats(data);

            const logsResponse = await fetch('/api/logs?limit=50');
            if (!logsResponse.ok) throw new Error('Failed to fetch initial logs');
            const logsData = await logsResponse.json();
            
            if (Array.isArray(logsData)) {
                this.state.requests = logsData.reverse();
                this.renderRequests();
            }
        } catch (err) {
            console.error('Error fetching initial proxy state:', err);
            this.showToast('Failed to load initial sovereign state', 'error');
        }
    }

    handleWebSocketMessage(message) {
        const { type, data } = message;

        if (type === 'request_intercepted') {
            this.addRequest(data);
        } else if (type === 'stats_update') {
            this.updateStats(data);
        } else if (type === 'circuit_breaker_tripped') {
            this.showToast(`CIRCUIT BREAKER TRIPPED: ${data.reason}`, 'error');
            this.updateStats(data.stats);
        }
    }

    addRequest(req) {
        this.state.requests.unshift(req);
        if (this.state.requests.length > this.maxRequestsLimit) {
            this.state.requests.pop();
        }

        // Increment stats locally if missing from full push
        this.state.stats.total_requests += 1;
        if (req.action === 'block') this.state.stats.blocked_requests += 1;
        if (req.redacted_count > 0) this.state.stats.secrets_redacted += req.redacted_count;
        if (req.tokens_used) {
            this.state.stats.tokens_used += req.tokens_used;
            this.state.stats.budget_spent += (req.cost || 0.0);
        }

        this.renderStats();
        this.renderRequests();
    }

    updateStats(stats) {
        this.state.stats = { ...this.state.stats, ...stats };
        this.renderStats();
    }

    renderStats() {
        const { total_requests, blocked_requests, secrets_redacted, tokens_used, budget_spent, budget_limit } = this.state.stats;

        this.metricTotalReq.textContent = total_requests.toLocaleString();
        this.metricBlockedReq.textContent = blocked_requests.toLocaleString();
        this.metricSecretsRedacted.textContent = secrets_redacted.toLocaleString();
        
        const budgetFormatted = budget_spent.toFixed(4);
        const limitFormatted = budget_limit.toFixed(2);
        this.metricTokenBudget.textContent = `$${budgetFormatted} / $${limitFormatted}`;

        const percentage = Math.min(100, Math.max(0, (budget_spent / budget_limit) * 100));
        this.budgetProgressBar.style.width = `${percentage}%`;

        if (percentage > 90) {
            this.budgetProgressBar.className = 'h-full bg-rose-500 shadow-[0_0_10px_#f43f5e] transition-all duration-300';
        } else if (percentage > 70) {
            this.budgetProgressBar.className = 'h-full bg-amber-400 shadow-[0_0_10px_#fbbf24] transition-all duration-300';
        } else {
            this.budgetProgressBar.className = 'h-full bg-cyan-400 shadow-[0_0_10px_#22d3ee] transition-all duration-300';
        }
    }

    renderRequests() {
        const filtered = this.state.requests.filter(req => {
            // Apply status filter
            if (this.state.filter === 'allowed' && req.action !== 'allow') return false;
            if (this.state.filter === 'blocked' && req.action !== 'block') return false;
            if (this.state.filter === 'redacted' && (!req.redacted_count || req.redacted_count === 0)) return false;

            // Apply search query
            if (this.state.searchQuery) {
                const query = this.state.searchQuery;
                const matchId = req.id && req.id.toLowerCase().includes(query);
                const matchModel = req.model && req.model.toLowerCase().includes(query);
                const matchProvider = req.provider && req.provider.toLowerCase().includes(query);
                const matchPayload = req.payload_preview && req.payload_preview.toLowerCase().includes(query);
                return matchId || matchModel || matchProvider || matchPayload;
            }

            return true;
        });

        if (filtered.length === 0) {
            this.requestsTableBody.innerHTML = '';
            this.emptyStateEl.classList.remove('hidden');
            return;
        }

        this.emptyStateEl.classList.add('hidden');

        this.requestsTableBody.innerHTML = filtered.map(req => {
            const timestamp = new Date(req.timestamp * 1000).toLocaleTimeString();
            const actionBadge = this.getActionBadge(req.action);
            const providerBadge = this.getProviderBadge(req.provider);
            const truncatedPreview = this.escapeHtml(req.payload_preview || 'No payload preview available.');

            return `
                <tr class="hover:bg-slate-800/50 transition-colors cursor-pointer border-b border-slate-800/60 font-mono text-xs" onclick="dashboard.openRequestModal('${req.id}')">
                    <td class="px-4 py-3 whitespace-nowrap text-slate-400">${timestamp}</td>
                    <td class="px-4 py-3 whitespace-nowrap">${providerBadge}</td>
                    <td class="px-4 py-3 whitespace-nowrap text-slate-200 font-semibold">${this.escapeHtml(req.model || 'unknown')}</td>
                    <td class="px-4 py-3 whitespace-nowrap">${actionBadge}</td>
                    <td class="px-4 py-3 whitespace-nowrap text-amber-400 font-medium">${req.redacted_count || 0} redacted</td>
                    <td class="px-4 py-3 text-slate-400 max-w-xs truncate">${truncatedPreview}</td>
                </tr>
            `;
        }).join('');
    }

    getActionBadge(action) {
        if (action === 'allow') {
            return `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800/60 shadow-[0_0_8px_rgba(52,211,153,0.2)]">Allowed</span>`;
        } else if (action === 'block') {
            return `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-rose-950 text-rose-400 border border-rose-800/60 shadow-[0_0_8px_rgba(244,63,94,0.2)]">Blocked</span>`;
        } else if (action === 'redact') {
            return `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-amber-950 text-amber-400 border border-amber-800/60 shadow-[0_0_8px_rgba(251,191,36,0.2)]">Redacted</span>`;
        }
        return `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-slate-800 text-slate-400">${action}</span>`;
    }

    getProviderBadge(provider) {
        if (!provider) return `<span class="text-slate-500">unknown</span>`;
        const p = provider.toLowerCase();
        if (p.includes('openai')) {
            return `<span class="text-emerald-400 font-bold">OpenAI</span>`;
        } else if (p.includes('anthropic')) {
            return `<span class="text-amber-400 font-bold">Anthropic</span>`;
        }
        return `<span class="text-cyan-400 font-bold">${this.escapeHtml(provider)}</span>`;
    }

    openRequestModal(requestId) {
        const req = this.state.requests.find(r => r.id === requestId);
        if (!req) return;

        this.state.selectedRequest = req;

        const timestampFull = new Date(req.timestamp * 1000).toLocaleString();
        
        this.modalContent.innerHTML = `
            <div class="space-y-4 font-mono text-xs">
                <div class="grid grid-cols-2 gap-4 bg-slate-950 p-4 rounded border border-slate-800">
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Request ID</span>
                        <span class="text-cyan-400 font-bold">${this.escapeHtml(req.id)}</span>
                    </div>
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Timestamp</span>
                        <span class="text-slate-200">${timestampFull}</span>
                    </div>
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Provider / Model</span>
                        <span class="text-slate-200">${this.escapeHtml(req.provider)} / ${this.escapeHtml(req.model)}</span>
                    </div>
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Security Action</span>
                        <div class="mt-1">${this.getActionBadge(req.action)}</div>
                    </div>
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Secrets Redacted</span>
                        <span class="text-amber-400 font-bold">${req.redacted_count || 0}</span>
                    </div>
                    <div>
                        <span class="text-slate-500 block text-[10px] uppercase tracking-wider">Tokens / Cost</span>
                        <span class="text-emerald-400 font-bold">${req.tokens_used || 0} tokens ($${(req.cost || 0).toFixed(4)})</span>
                    </div>
                </div>

                ${req.block_reason ? `
                    <div class="bg-rose-950/40 border border-rose-800/80 p-3 rounded text-rose-300">
                        <span class="font-bold block uppercase text-[10px] tracking-wider mb-1">Block / Circuit Breaker Reason</span>
                        ${this.escapeHtml(req.block_reason)}
                    </div>
                ` : ''}

                <div>
                    <span class="text-slate-400 block font-bold mb-1 uppercase text-[10px] tracking-wider">Intercepted Payload / Prompt</span>
                    <pre class="bg-slate-950 p-4 rounded border border-slate-800 text-slate-300 overflow-x-auto max-h-64 whitespace-pre-wrap">${this.escapeHtml(JSON.stringify(req.payload || {}, null, 2))}</pre>
                </div>

                ${req.response_payload ? `
                    <div>
                        <span class="text-slate-400 block font-bold mb-1 uppercase text-[10px] tracking-wider">Proxy Response Output</span>
                        <pre class="bg-slate-950 p-4 rounded border border-slate-800 text-slate-300 overflow-x-auto max-h-64 whitespace-pre-wrap">${this.escapeHtml(JSON.stringify(req.response_payload || {}, null, 2))}</pre>
                    </div>
                ` : ''}
            </div>
        `;

        this.requestModal.classList.remove('hidden');
        this.requestModal.classList.add('flex');
    }

    closeModal() {
        this.requestModal.classList.remove('flex');
        this.requestModal.classList.add('hidden');
        this.state.selectedRequest = null;
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        let borderColor = 'border-cyan-500';
        let textColor = 'text-cyan-400';
        let shadowColor = 'shadow-[0_0_15px_rgba(34,211,238,0.2)]';

        if (type === 'success') {
            borderColor = 'border-emerald-500';
            textColor = 'text-emerald-400';
            shadowColor = 'shadow-[0_0_15px_rgba(52,211,153,0.2)]';
        } else if (type === 'error') {
            borderColor = 'border-rose-500';
            textColor = 'text-rose-400';
            shadowColor = 'shadow-[0_0_15px_rgba(244,63,94,0.3)]';
        }

        toast.className = `pointer-events-auto bg-slate-900 border ${borderColor} ${textColor} px-4 py-3 rounded shadow-xl ${shadowColor} font-mono text-xs flex items-center justify-between space-x-4 transition-all duration-300 transform translate-y-2 opacity-0`;
        
        toast.innerHTML = `
            <span>${this.escapeHtml(message)}</span>
            <button class="text-slate-500 hover:text-slate-300 font-bold ml-2">&times;</button>
        `;

        toast.querySelector('button').addEventListener('click', () => {
            toast.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => toast.remove(), 300);
        });

        container.appendChild(toast);

        // Trigger entrance transition
        requestAnimationFrame(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
        });

        // Auto dismiss after 4 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('translate-y-2', 'opacity-0');
                setTimeout(() => toast.remove(), 300);
            }
        }, 4000);
    }

    escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

// Initialize Dashboard when DOM is ready
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new FirewallDashboard();
});
