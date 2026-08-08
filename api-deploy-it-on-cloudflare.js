
const CONFIG = {
    TIMEOUT: 8080,
    MAX_IPS_PER_REQUEST: 200,
    CACHE_TTL: 300,
    EXIT_ADDRESSES_URL: 'https://check.torproject.org/exit-addresses',
    ONIONOO_API_URL: 'https://onionoo.torproject.org/details?search=flag:exit',
    IP_API_URL: 'http://ip-api.com/json/',
    IP_API_BATCH_URL: 'http://ip-api.com/batch',
    IPWHOIS_URL: 'https://ipwhois.app/json/',
    ABUSEIPDB_URL: 'https://api.abuseipdb.com/api/v2/check',
    USER_AGENTS: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
};

const PORTS = {
    WEB: [80, 443, 8080, 8443, 8000, 8888],
    EMAIL: [25, 110, 143, 465, 587, 993, 995],
    FTP: [21, 22, 23],
    DATABASE: [3306, 5432, 27017, 6379],
    OTHER: [53, 67, 68, 69, 123, 161, 389, 636, 1194]
};

class TorScanner {
    constructor() {
        this.cache = new Map();
        this.exitNodesCache = null;
        this.onionooCache = null;
        this.lastExitUpdate = null;
        this.lastOnionooUpdate = null;
        this.stats = {
            totalRequests: 0,
            totalScans: 0,
            successScans: 0,
            failedScans: 0,
            exitNodesCount: 0,
            onionooRelaysCount: 0,
            countriesCount: 0,
            lastFetch: null
        };
        this.torCheckCache = new Map();
    }

    async handleRequest(request) {
        const url = new URL(request.url);
        const path = url.pathname;
        
        const headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Content-Type': 'application/json'
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers });
        }

        // Tor/Proxy Check endpoints
        if (path === '/tor-check' && request.method === 'GET') {
            return await this.handleTorCheck(request, headers);
        }
        if (path === '/tor-check' && request.method === 'POST') {
            return await this.handleTorCheckPost(request, headers);
        }
        if (path === '/proxy-check' && request.method === 'GET') {
            return await this.handleTorCheck(request, headers);
        }
        if (path === '/proxy-check' && request.method === 'POST') {
            return await this.handleTorCheckPost(request, headers);
        }

        // Scan endpoints
        if (path === '/scan' && request.method === 'POST') {
            try {
                const body = await request.json();
                const ips = body.ips || [];
                const ports = body.ports || [80, 443];
                
                if (!ips || ips.length === 0) {
                    return this.jsonResponse({
                        success: false,
                        error: 'No IPs provided',
                        example: '{"ips": ["1.1.1.1", "8.8.8.8"]}'
                    }, 400, headers);
                }
                if (ips.length > CONFIG.MAX_IPS_PER_REQUEST) {
                    return this.jsonResponse({
                        success: false,
                        error: `Too many IPs (max ${CONFIG.MAX_IPS_PER_REQUEST})`,
                        count: ips.length
                    }, 400, headers);
                }
                
                const results = await this.scanIPs(ips, ports);
                this.stats.totalScans++;
                this.stats.successScans++;
                
                return this.jsonResponse({
                    success: true,
                    total: results.length,
                    online: results.filter(r => r.online).length,
                    offline: results.filter(r => !r.online).length,
                    results: results,
                    timestamp: new Date().toISOString()
                }, 200, headers);
                
            } catch (error) {
                this.stats.failedScans++;
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/scan/single' && request.method === 'GET') {
            const ip = url.searchParams.get('ip');
            const ports = url.searchParams.get('ports')?.split(',').map(Number) || [80, 443];
            
            if (!ip) {
                return this.jsonResponse({
                    success: false,
                    error: 'Missing ip parameter',
                    example: '/scan/single?ip=1.1.1.1&ports=80,443'
                }, 400, headers);
            }
            
            const result = await this.scanSingleIP(ip, ports);
            return this.jsonResponse({
                success: true,
                result: result
            }, 200, headers);
        }

        if (path === '/scan/all-ports' && request.method === 'POST') {
            try {
                const body = await request.json();
                const ips = body.ips || [];
                const allPorts = [...PORTS.WEB, ...PORTS.EMAIL, ...PORTS.FTP, ...PORTS.DATABASE, ...PORTS.OTHER];
                
                if (!ips || ips.length === 0) {
                    return this.jsonResponse({
                        success: false,
                        error: 'No IPs provided'
                    }, 400, headers);
                }
                
                const results = await this.scanIPs(ips, allPorts);
                return this.jsonResponse({
                    success: true,
                    total: results.length,
                    online: results.filter(r => r.online).length,
                    results: results,
                    portsScanned: allPorts.length
                }, 200, headers);
                
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        // Health/Lookup/Detection endpoints
        if (path === '/health' && request.method === 'GET') {
            const ip = url.searchParams.get('ip');
            if (!ip) {
                return this.jsonResponse({
                    success: false,
                    error: 'Missing ip parameter'
                }, 400, headers);
            }
            
            const result = await this.fullHealthCheck(ip);
            return this.jsonResponse({
                success: true,
                result: result
            }, 200, headers);
        }

        if (path === '/lookup' && request.method === 'GET') {
            const ip = url.searchParams.get('ip');
            if (!ip) {
                return this.jsonResponse({
                    success: false,
                    error: 'Missing ip parameter',
                    example: '/lookup?ip=1.1.1.1'
                }, 400, headers);
            }
            
            try {
                const result = await this.getIPInfo(ip);
                return this.jsonResponse({
                    success: true,
                    result: result
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/lookup/batch' && request.method === 'POST') {
            try {
                const body = await request.json();
                const ips = body.ips || [];
                
                if (!ips || ips.length === 0) {
                    return this.jsonResponse({
                        success: false,
                        error: 'No IPs provided'
                    }, 400, headers);
                }
                
                if (ips.length > 100) {
                    return this.jsonResponse({
                        success: false,
                        error: 'Maximum 100 IPs per batch request'
                    }, 400, headers);
                }
                
                const results = await this.getBatchIPInfo(ips);
                return this.jsonResponse({
                    success: true,
                    total: results.length,
                    results: results
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/detect' && request.method === 'GET') {
            const ip = url.searchParams.get('ip');
            if (!ip) {
                return this.jsonResponse({
                    success: false,
                    error: 'Missing ip parameter',
                    example: '/detect?ip=1.1.1.1'
                }, 400, headers);
            }
            
            try {
                const result = await this.detectIP(ip);
                return this.jsonResponse({
                    success: true,
                    result: result
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        // Exit nodes endpoints
        if (path === '/exit-nodes' && request.method === 'GET') {
            try {
                const data = await this.getExitNodes();
                return this.jsonResponse({
                    success: true,
                    total: data.nodes.length,
                    nodes: data.nodes,
                    countries: data.countries,
                    source: 'exit-addresses',
                    timestamp: new Date().toISOString()
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/exit-nodes/detailed' && request.method === 'GET') {
            try {
                const data = await this.getExitNodes();
                const detailedNodes = await this.getDetailedExitNodes(data.nodes.slice(0, 50));
                
                return this.jsonResponse({
                    success: true,
                    total: detailedNodes.length,
                    nodes: detailedNodes,
                    timestamp: new Date().toISOString()
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/ips.txt' && request.method === 'GET') {
            try {
                const data = await this.getExitNodes();
                const ipsText = this.generateIpsTxt(data.nodes);
                
                const txtHeaders = {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'text/plain',
                    'Content-Disposition': 'attachment; filename="ips.txt"'
                };
                
                return new Response(ipsText, {
                    status: 200,
                    headers: txtHeaders
                });
            } catch (error) {
                return new Response(`Error: ${error.message}`, {
                    status: 500,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'text/plain'
                    }
                });
            }
        }

        if (path === '/countries' && request.method === 'GET') {
            try {
                const data = await this.getOnionooData();
                return this.jsonResponse({
                    success: true,
                    countries: data.countries,
                    totalRelays: data.totalRelays,
                    source: 'onionoo',
                    timestamp: data.timestamp
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        if (path === '/all' && request.method === 'GET') {
            try {
                const [exitNodes, onionooData] = await Promise.all([
                    this.getExitNodes(),
                    this.getOnionooData()
                ]);
                
                return this.jsonResponse({
                    success: true,
                    exitNodes: {
                        total: exitNodes.nodes.length,
                        nodes: exitNodes.nodes,
                        countries: exitNodes.countries,
                        source: 'exit-addresses'
                    },
                    onionoo: {
                        totalRelays: onionooData.totalRelays,
                        countries: onionooData.countries,
                        source: 'onionoo'
                    },
                    timestamp: new Date().toISOString()
                }, 200, headers);
            } catch (error) {
                return this.jsonResponse({
                    success: false,
                    error: error.message
                }, 500, headers);
            }
        }

        // Management endpoints
        if (path === '/refresh' && request.method === 'POST') {
            this.exitNodesCache = null;
            this.onionooCache = null;
            this.lastExitUpdate = null;
            this.lastOnionooUpdate = null;
            
            const [exitData, onionooData] = await Promise.all([
                this.getExitNodes(true),
                this.getOnionooData(true)
            ]);
            
            return this.jsonResponse({
                success: true,
                message: 'Cache refreshed',
                exitNodes: exitData.nodes.length,
                onionooRelays: onionooData.totalRelays,
                timestamp: new Date().toISOString()
            }, 200, headers);
        }

        if (path === '/stats' && request.method === 'GET') {
            return this.jsonResponse({
                success: true,
                stats: this.stats,
                cacheSize: this.cache.size,
                exitNodesCache: this.exitNodesCache ? this.exitNodesCache.length : 0,
                onionooCache: this.onionooCache ? Object.keys(this.onionooCache).length : 0,
                lastExitUpdate: this.lastExitUpdate,
                lastOnionooUpdate: this.lastOnionooUpdate
            }, 200, headers);
        }

        if (path === '/clear-cache' && request.method === 'POST') {
            const size = this.cache.size;
            this.cache.clear();
            this.exitNodesCache = null;
            this.onionooCache = null;
            this.torCheckCache.clear();
            return this.jsonResponse({
                success: true,
                cleared: size,
                message: `Cache cleared (${size} items)`
            }, 200, headers);
        }

        // Root/Info endpoint
        if (path === '/' || path === '/info') {
            return this.jsonResponse({
                name: 'Tor Exit Node Scanner',
                version: '10.0 NO LIMITS',
                description: 'Returns ALL fingerprints - No 10 limit on any endpoint',
                endpoints: {
                    'GET /tor-check': 'Check current IP',
                    'POST /tor-check': 'Check specific IP {"ip": "1.1.1.1"}',
                    'GET /proxy-check': 'Alias for /tor-check GET',
                    'POST /proxy-check': 'Alias for /tor-check POST',
                    'POST /scan': 'Batch scan {"ips": [...], "ports": [80,443]}',
                    'GET /scan/single': 'Single scan /scan/single?ip=1.1.1.1',
                    'GET /health': 'Health check /health?ip=1.1.1.1',
                    'GET /lookup': 'IP info /lookup?ip=1.1.1.1',
                    'GET /detect': 'Detection /detect?ip=1.1.1.1',
                    'GET /exit-nodes': 'All exit nodes',
                    'GET /ips.txt': 'Download ips.txt',
                    'GET /countries': 'Onionoo data (ALL fingerprints)',
                    'GET /all': 'Combined data',
                    'GET /stats': 'Statistics',
                    'POST /refresh': 'Force refresh',
                    'POST /clear-cache': 'Clear cache'
                }
            }, 200, headers);
        }

        return this.jsonResponse({ success: false, error: 'Invalid endpoint' }, 404, headers);
    }

    // ===== TOR CHECK HANDLERS =====

    async handleTorCheck(request, headers) {
        try {
            const clientIP = request.headers.get('CF-Connecting-IP') || 
                           request.headers.get('x-forwarded-for')?.split(',')[0] || 
                           'unknown';
            
            const cacheKey = `torcheck:${clientIP}`;
            if (this.torCheckCache.has(cacheKey)) {
                const cached = this.torCheckCache.get(cacheKey);
                if (Date.now() - cached.timestamp < 60000) {
                    return this.jsonResponse(cached.data, 200, headers);
                }
            }
            
            const exitData = await this.getExitNodes();
            const isTorExit = exitData.nodes.some(node => node.exit_address === clientIP);
            
            let ipInfo = null, detection = null;
            try { ipInfo = await this.getIPInfo(clientIP); } catch (e) {}
            try { detection = await this.detectIP(clientIP); } catch (e) {}
            
            const response = {
                success: true,
                isTor: isTorExit,
                isExit: isTorExit,
                ip: clientIP,
                timestamp: new Date().toISOString(),
                details: {
                    isExitNode: isTorExit,
                    isTorNetwork: detection?.isTor || false,
                    riskLevel: detection?.riskLevel || 'unknown',
                    confidence: detection?.confidence || 0
                },
                location: ipInfo?.location || null,
                isp: ipInfo?.isp || null,
                detection: detection || null,
                fingerprint: isTorExit ? exitData.nodes.find(n => n.exit_address === clientIP)?.fingerprint : null,
                message: isTorExit ? 'This IP is a Tor exit node' : 'This IP is not a Tor exit node'
            };
            
            this.torCheckCache.set(cacheKey, { data: response, timestamp: Date.now() });
            return this.jsonResponse(response, 200, headers);
        } catch (error) {
            return this.jsonResponse({ success: false, error: error.message }, 500, headers);
        }
    }

    async handleTorCheckPost(request, headers) {
        try {
            const body = await request.json();
            const ip = body.ip || body.address || body.query;
            
            if (!ip) {
                return this.jsonResponse({ success: false, error: 'Missing ip' }, 400, headers);
            }
            
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            if (!ipRegex.test(ip)) {
                return this.jsonResponse({ success: false, error: 'Invalid IP' }, 400, headers);
            }
            
            const cacheKey = `torcheck:${ip}`;
            if (this.torCheckCache.has(cacheKey)) {
                const cached = this.torCheckCache.get(cacheKey);
                if (Date.now() - cached.timestamp < 60000) {
                    return this.jsonResponse(cached.data, 200, headers);
                }
            }
            
            const exitData = await this.getExitNodes();
            const isTorExit = exitData.nodes.some(node => node.exit_address === ip);
            
            let ipInfo = null, detection = null;
            try { ipInfo = await this.getIPInfo(ip); } catch (e) {}
            try { detection = await this.detectIP(ip); } catch (e) {}
            
            const response = {
                success: true,
                isTor: isTorExit,
                isExit: isTorExit,
                ip: ip,
                timestamp: new Date().toISOString(),
                details: {
                    isExitNode: isTorExit,
                    isTorNetwork: detection?.isTor || false,
                    riskLevel: detection?.riskLevel || 'unknown',
                    confidence: detection?.confidence || 0
                },
                location: ipInfo?.location || null,
                isp: ipInfo?.isp || null,
                detection: detection || null,
                fingerprint: isTorExit ? exitData.nodes.find(n => n.exit_address === ip)?.fingerprint : null,
                message: isTorExit ? 'This IP is a Tor exit node' : 'This IP is not a Tor exit node'
            };
            
            this.torCheckCache.set(cacheKey, { data: response, timestamp: Date.now() });
            return this.jsonResponse(response, 200, headers);
        } catch (error) {
            return this.jsonResponse({ success: false, error: error.message }, 500, headers);
        }
    }

    // ===== SCANNING METHODS =====

    async scanIPs(ips, ports) {
        const results = [];
        for (let i = 0; i < ips.length; i += 20) {
            const batch = ips.slice(i, i + 20);
            const batchResults = await Promise.allSettled(batch.map(ip => this.scanSingleIP(ip, ports)));
            for (const result of batchResults) {
                results.push(result.status === 'fulfilled' ? result.value : { ip: 'unknown', online: false, error: 'Scan failed' });
            }
        }
        return results;
    }

    async scanSingleIP(ip, ports) {
        const cacheKey = `${ip}:${ports.join(',')}`;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL * 1000) {
                return cached.data;
            }
        }

        const result = {
            ip,
            online: false,
            ports: {},
            responseTime: 0,
            methods: [],
            timestamp: new Date().toISOString()
        };

        const startTime = Date.now();

        for (const port of ports) {
            try {
                const pr = await this.checkPort(ip, port);
                result.ports[port] = pr;
                if (pr.open) {
                    result.online = true;
                    result.methods.push(`tcp:${port}`);
                }
            } catch (e) {
                result.ports[port] = { open: false, error: e.message };
            }
        }

        if (!result.online) {
            try {
                const hr = await this.checkHTTP(ip);
                if (hr.online) {
                    result.online = true;
                    result.methods.push('http');
                    result.httpInfo = hr.info;
                }
            } catch (e) {}
        }

        result.responseTime = Date.now() - startTime;
        
        this.cache.set(cacheKey, { data: result, timestamp: Date.now() });
        this.stats.totalRequests++;
        return result;
    }

    async checkPort(ip, port) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT);
        
        try {
            const url = port === 443 ? `https://${ip}` : `http://${ip}:${port}`;
            const response = await fetch(url, {
                method: 'HEAD',
                headers: {
                    'User-Agent': this.getRandomUserAgent(),
                    'Cache-Control': 'no-cache'
                },
                signal: controller.signal,
                redirect: 'manual'
            });
            
            clearTimeout(timeoutId);
            return { open: true, status: response.status, statusText: response.statusText };
        } catch (error) {
            clearTimeout(timeoutId);
            return { open: false, error: error.message };
        }
    }

    async checkHTTP(ip) {
        const result = { online: false, info: {} };
        
        try {
            const response = await fetch(`https://${ip}`, {
                method: 'GET',
                headers: {
                    'User-Agent': this.getRandomUserAgent(),
                    'Accept': '*/*'
                },
                signal: AbortSignal.timeout(CONFIG.TIMEOUT),
                redirect: 'manual'
            });
            
            if (response.status < 500 || response.status === 403 || response.status === 401) {
                result.online = true;
                result.info = {
                    protocol: 'https',
                    status: response.status,
                    server: response.headers.get('server') || 'Unknown'
                };
                return result;
            }
        } catch (e) {}

        try {
            const response = await fetch(`http://${ip}`, {
                method: 'GET',
                headers: {
                    'User-Agent': this.getRandomUserAgent(),
                    'Accept': '*/*'
                },
                signal: AbortSignal.timeout(CONFIG.TIMEOUT),
                redirect: 'manual'
            });
            
            if (response.status < 500 || response.status === 403 || response.status === 401) {
                result.online = true;
                result.info = {
                    protocol: 'http',
                    status: response.status,
                    server: response.headers.get('server') || 'Unknown'
                };
            }
        } catch (e) {}

        return result;
    }

    async fullHealthCheck(ip) {
        const result = {
            ip,
            online: false,
            methods: [],
            details: {},
            timestamp: new Date().toISOString()
        };

        const methods = [
            { name: 'TCP 80', fn: () => this.checkPort(ip, 80) },
            { name: 'TCP 443', fn: () => this.checkPort(ip, 443) },
            { name: 'HTTP', fn: () => this.checkHTTP(ip) }
        ];

        for (const method of methods) {
            try {
                const res = await method.fn();
                result.details[method.name] = res;
                if (res.online) {
                    result.online = true;
                    result.methods.push(method.name);
                }
            } catch (e) {
                result.details[method.name] = { error: e.message };
            }
        }

        return result;
    }

    // ===== IP INFO METHODS =====

    async getIPInfo(ip) {
        const cacheKey = `ipinfo:${ip}`;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL * 1000) {
                return cached.data;
            }
        }

        const result = {
            ip,
            isp: null,
            location: null,
            detection: null,
            timestamp: new Date().toISOString()
        };

        try {
            const [ipApi, ipwhois] = await Promise.allSettled([
                this.fetchIPAPI(ip),
                this.fetchIPWhois(ip)
            ]);

            if (ipApi.status === 'fulfilled' && ipApi.value) {
                const d = ipApi.value;
                result.isp = {
                    name: d.isp || 'Unknown',
                    org: d.org || 'Unknown',
                    as: d.as || 'Unknown'
                };
                result.location = {
                    country: d.country || 'Unknown',
                    countryCode: d.countryCode || 'Unknown',
                    region: d.regionName || 'Unknown',
                    city: d.city || 'Unknown',
                    lat: d.lat || 0,
                    lon: d.lon || 0,
                    timezone: d.timezone || 'Unknown'
                };
            }

            if (ipwhois.status === 'fulfilled' && ipwhois.value) {
                const d = ipwhois.value;
                if (!result.isp) {
                    result.isp = {
                        name: d.isp || 'Unknown',
                        org: d.org || 'Unknown',
                        as: d.asn || 'Unknown'
                    };
                }
                if (!result.location) {
                    result.location = {
                        country: d.country || 'Unknown',
                        countryCode: d.country_code || 'Unknown',
                        city: d.city || 'Unknown'
                    };
                }
            }
        } catch (error) {
            result.error = error.message;
        }

        try {
            result.detection = await this.detectIP(ip);
        } catch (error) {
            result.detection = { error: error.message };
        }

        this.cache.set(cacheKey, { data: result, timestamp: Date.now() });
        return result;
    }

    async fetchIPAPI(ip) {
        try {
            const r = await fetch(`${CONFIG.IP_API_URL}${ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query`, {
                signal: AbortSignal.timeout(5000)
            });
            if (r.ok) {
                const d = await r.json();
                if (d.status === 'success') return d;
            }
        } catch (e) {}
        return null;
    }

    async fetchIPWhois(ip) {
        try {
            const r = await fetch(`${CONFIG.IPWHOIS_URL}${ip}`, {
                signal: AbortSignal.timeout(5000)
            });
            if (r.ok) {
                const d = await r.json();
                if (d.success) return d;
            }
        } catch (e) {}
        return null;
    }

    async getBatchIPInfo(ips) {
        const results = [];
        for (let i = 0; i < ips.length; i += 10) {
            const batch = ips.slice(i, i + 10);
            const batchResults = await Promise.allSettled(batch.map(ip => this.getIPInfo(ip)));
            for (const r of batchResults) {
                results.push(r.status === 'fulfilled' ? r.value : { error: 'Failed' });
            }
        }
        return results;
    }

    // ===== DETECTION METHODS =====

    async detectIP(ip) {
        const cacheKey = `detect:${ip}`;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL * 1000) {
                return cached.data;
            }
        }

        const result = {
            ip,
            isVPN: false,
            isProxy: false,
            isTor: false,
            isDatacenter: false,
            isHosting: false,
            riskLevel: 'low',
            confidence: 0,
            checks: {},
            timestamp: new Date().toISOString()
        };

        let checks = 0, positive = 0;

        try {
            const exitNodes = await this.getExitNodes();
            if (exitNodes.nodes.some(n => n.exit_address === ip)) {
                result.isTor = true;
                positive++;
            }
            checks++;
        } catch (e) {}

        if (checks > 0) {
            result.confidence = Math.round((positive / checks) * 100);
        }

        if (result.confidence >= 75) result.riskLevel = 'high';
        else if (result.confidence >= 50) result.riskLevel = 'medium';
        else if (result.confidence >= 25) result.riskLevel = 'low';
        if (result.isTor) result.riskLevel = 'critical';

        this.cache.set(cacheKey, { data: result, timestamp: Date.now() });
        return result;
    }

    // ===== EXIT NODES METHODS =====

    async getExitNodes(forceRefresh = false) {
        if (!forceRefresh && this.exitNodesCache && this.lastExitUpdate) {
            const age = (Date.now() - this.lastExitUpdate) / 1000;
            if (age < CONFIG.CACHE_TTL) {
                return {
                    nodes: this.exitNodesCache,
                    countries: this.extractCountries(this.exitNodesCache),
                    cached: true
                };
            }
        }

        try {
            const response = await fetch(CONFIG.EXIT_ADDRESSES_URL, {
                signal: AbortSignal.timeout(10000)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const text = await response.text();
            const nodes = this.parseExitAddresses(text);
            
            this.exitNodesCache = nodes;
            this.lastExitUpdate = Date.now();
            this.stats.exitNodesCount = nodes.length;
            this.stats.lastFetch = new Date().toISOString();
            
            return {
                nodes,
                countries: this.extractCountries(nodes),
                cached: false
            };
        } catch (error) {
            if (this.exitNodesCache) {
                return {
                    nodes: this.exitNodesCache,
                    countries: this.extractCountries(this.exitNodesCache),
                    cached: true,
                    error: error.message
                };
            }
            throw error;
        }
    }

    async getDetailedExitNodes(nodes) {
        const detailed = [];
        for (const node of nodes) {
            try {
                const info = await this.getIPInfo(node.exit_address);
                detailed.push({
                    ...node,
                    isp: info.isp,
                    location: info.location,
                    detection: info.detection
                });
            } catch (e) {
                detailed.push({
                    ...node,
                    isp: null,
                    location: null,
                    detection: null,
                    error: e.message
                });
            }
        }
        return detailed;
    }

    parseExitAddresses(text) {
        const nodes = [];
        const lines = text.split('\n');
        let current = {};
        
        for (const line of lines) {
            const t = line.trim();
            if (!t) continue;
            
            if (t.startsWith('ExitNode ')) {
                if (current.fingerprint && current.exit_address) {
                    nodes.push(current);
                }
                current = {
                    fingerprint: t.replace('ExitNode ', '').trim(),
                    exit_address: '',
                    published: '',
                    last_status: '',
                    timestamp: ''
                };
            } else if (t.startsWith('Published ')) {
                current.published = t.replace('Published ', '').trim();
            } else if (t.startsWith('LastStatus ')) {
                current.last_status = t.replace('LastStatus ', '').trim();
            } else if (t.startsWith('ExitAddress ')) {
                const parts = t.replace('ExitAddress ', '').trim().split(' ');
                if (parts.length >= 2) {
                    current.exit_address = parts[0];
                    current.timestamp = parts.slice(1).join(' ');
                }
            }
        }
        
        if (current.fingerprint && current.exit_address) {
            nodes.push(current);
        }
        
        return nodes;
    }

    generateIpsTxt(nodes) {
        let output = '';
        for (const node of nodes) {
            output += `ExitNode ${node.fingerprint}\n`;
            if (node.published) output += `Published ${node.published}\n`;
            if (node.last_status) output += `LastStatus ${node.last_status}\n`;
            if (node.exit_address) output += `ExitAddress ${node.exit_address} ${node.timestamp || ''}\n`;
            output += '\n';
        }
        return output;
    }

    extractCountries(nodes) {
        const map = {};
        for (const node of nodes) {
            const ip = node.exit_address;
            if (ip) {
                const prefix = ip.split('.')[0] || 'unknown';
                if (!map[prefix]) {
                    map[prefix] = { count: 0, ips: [] };
                }
                map[prefix].count++;
                map[prefix].ips.push(ip);
            }
        }
        return map;
    }

    // ===== ONIONOO METHODS =====

    async getOnionooData(forceRefresh = false) {
        if (!forceRefresh && this.onionooCache && this.lastOnionooUpdate) {
            const age = (Date.now() - this.lastOnionooUpdate) / 1000;
            if (age < CONFIG.CACHE_TTL) {
                return {
                    countries: this.onionooCache,
                    totalRelays: this.stats.onionooRelaysCount,
                    cached: true,
                    timestamp: new Date(this.lastOnionooUpdate).toISOString()
                };
            }
        }

        try {
            const response = await fetch(CONFIG.ONIONOO_API_URL, {
                signal: AbortSignal.timeout(10000)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            const countries = this.parseOnionooCountries(data);
            
            this.onionooCache = countries;
            this.lastOnionooUpdate = Date.now();
            this.stats.onionooRelaysCount = data.relays ? data.relays.length : 0;
            this.stats.countriesCount = Object.keys(countries).length;
            
            return {
                countries,
                totalRelays: data.relays ? data.relays.length : 0,
                cached: false,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            if (this.onionooCache) {
                return {
                    countries: this.onionooCache,
                    totalRelays: this.stats.onionooRelaysCount,
                    cached: true,
                    error: error.message,
                    timestamp: new Date(this.lastOnionooUpdate).toISOString()
                };
            }
            throw error;
        }
    }

    parseOnionooCountries(data) {
        const countryMap = {};
        if (data.relays) {
            for (const relay of data.relays) {
                const country = relay.country || 'unknown';
                if (!countryMap[country]) {
                    countryMap[country] = {
                        name: country,
                        count: 0,
                        fingerprints: []
                    };
                }
                countryMap[country].count++;
                countryMap[country].fingerprints.push(relay.fingerprint || '');
            }
        }
        return countryMap;
    }

    // ===== UTILITY METHODS =====

    getRandomUserAgent() {
        return CONFIG.USER_AGENTS[Math.floor(Math.random() * CONFIG.USER_AGENTS.length)];
    }

    jsonResponse(data, status = 200, headers = {}) {
        return new Response(JSON.stringify(data), {
            status,
            headers
        });
    }
}

const scanner = new TorScanner();

addEventListener('fetch', event => {
    event.respondWith(scanner.handleRequest(event.request));
});
