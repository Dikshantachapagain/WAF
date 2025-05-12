// custom-waf.js - A Web Application Firewall for DVWA with intentional weaknesses
const express = require('express');
const morgan = require('morgan');
const http = require('http');
const url = require('url');
const querystring = require('querystring');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_SERVER = 'http://localhost:80'; // DVWA server address

// Enable debugging
const DEBUG = true;

// Middleware for logging
app.use(morgan('combined'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// WAF Rules with intentional weaknesses to allow specific bypasses
const wafRules = {
    // XSS Rules - Will block basic <script> but allow specific bypasses
    xss: [
        /<script\b[^>]*>(.*?)<\/script>/i,  // Blocks standard script tags
        /javascript:alert/i,                // Blocks javascript:alert
        /on(click|load|error)="alert/i,     // Only blocks specific event handlers with alert
    ],
    
    // SQL Injection Rules - Will block basic patterns but allow specific bypasses
    sqli: [
        /'\s+OR\s+'1'\s*=\s*'1/i,          // Blocks standard OR '1'='1
        /UNION\s+SELECT/i,                 // Blocks UNION SELECT
        /DROP\s+TABLE/i,                   // Blocks DROP TABLE
    ],
    
    // Command Injection Rules - Will block ; cat but allow | cat
    cmdi: [
        /;\s*cat/i,                         // Blocks ;cat
        /;\s*ls/i,                          // Blocks ;ls
        /;\s*pwd/i,                         // Blocks ;pwd
    ]
};

// WAF check function with verbose logging
function checkWafRules(content, type) {
    if (!content) return { blocked: false };
    
    const rules = wafRules[type];
    if (!rules) return { blocked: false };
    
    for (const rule of rules) {
        if (rule.test(content)) {
            if (DEBUG) {
                console.log(`🚫 BLOCKED - Type: ${type}, Content: ${content}`);
                console.log(`🚫 Matched rule: ${rule.toString()}`);
            }
            return {
                blocked: true,
                match: rule.toString(),
                type: type
            };
        }
    }
    
    if (DEBUG) {
        console.log(`✅ PASSED - Type: ${type}, Content: ${content}`);
    }
    return { blocked: false };
}

// Function to check all parameters for WAF violations
function inspectRequest(req) {
    if (DEBUG) {
        console.log("\n==== Inspecting Request ====");
        console.log(`URL: ${req.url}`);
        console.log("Query params:", req.query);
        console.log("Body:", req.body);
    }
    
    // Check query parameters
    const queryParams = req.query;
    for (const param in queryParams) {
        const value = queryParams[param];
        
        // Skip WAF param itself
        if (param === 'bypass_waf') continue;
        
        // Check for XSS
        let result = checkWafRules(value, 'xss');
        if (result.blocked) return result;
        
        // Check for SQL Injection
        result = checkWafRules(value, 'sqli');
        if (result.blocked) return result;
        
        // Check for Command Injection
        result = checkWafRules(value, 'cmdi');
        if (result.blocked) return result;
    }
    
    // Check body parameters
    if (req.body) {
        for (const param in req.body) {
            const value = req.body[param];
            if (typeof value !== 'string') continue;
            
            // Check for XSS
            let result = checkWafRules(value, 'xss');
            if (result.blocked) return result;
            
            // Check for SQL Injection
            result = checkWafRules(value, 'sqli');
            if (result.blocked) return result;
            
            // Check for Command Injection
            result = checkWafRules(value, 'cmdi');
            if (result.blocked) return result;
        }
    }
    
    if (DEBUG) {
        console.log("✅ Request passed all WAF checks");
    }
    return { blocked: false };
}

// Proxy middleware
app.use((req, res, next) => {
    // Skip WAF check if bypass query parameter is present (for testing purposes)
    if (req.query.bypass_waf === 'true') {
        console.log('WAF BYPASS MODE ENABLED - Skipping WAF checks');
        return proxyRequest(req, res);
    }
    
    // Inspect the request
    const wafResult = inspectRequest(req);
    
    // If blocked by WAF, return block page
    if (wafResult.blocked) {
        console.log(`WAF BLOCK: ${wafResult.type} attack detected with pattern: ${wafResult.match}`);
        return res.status(403).send(`
            <html>
                <head>
                    <title>WAF Block Page</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                        h1 { color: #D32F2F; }
                        .container { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
                        .details { background: #f5f5f5; padding: 10px; border-left: 3px solid #D32F2F; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Request Blocked by Web Application Firewall</h1>
                        <p>Your request was blocked due to security concerns.</p>
                        <div class="details">
                            <p><strong>Attack type:</strong> ${wafResult.type}</p>
                            <p><strong>Matched pattern:</strong> ${wafResult.match}</p>
                        </div>
                    </div>
                </body>
            </html>
        `);
    }
    
    // If not blocked, proxy the request to the target server
    proxyRequest(req, res);
});

// Function to proxy requests to the target server
function proxyRequest(req, res) {
    const parsedUrl = url.parse(req.url);
    const options = {
        hostname: url.parse(TARGET_SERVER).hostname,
        port: url.parse(TARGET_SERVER).port || 80,
        path: parsedUrl.path,
        method: req.method,
        headers: req.headers
    };
    
    // Update host header to match target
    options.headers.host = options.hostname;
    
    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    
    proxyReq.on('error', (error) => {
        console.error('Proxy request error:', error);
        res.status(500).send('Proxy Error');
    });
    
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        if (req.body) {
            if (typeof req.body === 'object') {
                const bodyData = querystring.stringify(req.body);
                proxyReq.write(bodyData);
            } else {
                proxyReq.write(req.body);
            }
        } else {
            req.pipe(proxyReq);
            return;
        }
    }
    
    proxyReq.end();
}

// Start the WAF server
app.listen(PORT, () => {
    console.log(`WAF proxy server running on port ${PORT}`);
    console.log(`Proxying requests to ${TARGET_SERVER}`);
    console.log("Debug mode:", DEBUG ? "ENABLED" : "DISABLED");
    console.log("\nTest payloads that will be BLOCKED:");
    console.log("XSS: <script>alert('XSS')</script>");
    console.log("SQL Injection: 1' OR '1'='1");
    console.log("Command Injection: 127.0.0.1; cat /etc/passwd");
    
    console.log("\nEvasion techniques that will BYPASS the WAF:");
    console.log("XSS Bypass: <img src='x' onerror='alert(\"XSS Bypassed\")'>");
    console.log("SQL Injection Bypass: 1'/**/OR/**/1=1--");
    console.log("Command Injection Bypass: 127.0.0.1| cat /etc/passwd");
});