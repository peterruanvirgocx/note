# Postman

## Scripts

### Pre-request

```
const yellowCardAuth = pm.require('@peterruan-3216028/yellow-card-auth');
yellowCardAuth.create_auth()
```

### Packages

```node
/**
 * Generate ISO8601 timestamp
 */
function generateTimestamp() {
    return new Date().toISOString();
}

/**
 * Generate SHA256 hash of request body and encode as base64
 */
function hashRequestBody(body) {
   if (!body) return "";
    var crypto = require('crypto-js');
    
    const hash = crypto.SHA256(body);
    return crypto.enc.Base64.stringify(hash);
}

/**
 * Build the message to sign according to YC API spec
 */
function buildMessageToSign(timestamp, path, method, requestBody) {
    let message = timestamp + path + method.toUpperCase();
    
    // For POST and PUT requests, add base64 encoded SHA256 hash of request body
    if ((method.toUpperCase() === "POST" || method.toUpperCase() === "PUT") && requestBody) {
        const bodyHash = hashRequestBody(requestBody);
        message += bodyHash;
    }
    
    return message;
}

/**
 * Generate HMAC-SHA256 signature
 */
function generateSignature(message, secretKey) {

    // Import the secret key
    var crypto = require('crypto-js');
    const hmac = crypto.HmacSHA256(message, secretKey);
    return crypto.enc.Base64.stringify(hmac);
}

/**
 * Extract path from URL (excluding host and query parameters)
 */
function extractPath(url) {
    try {
        let resolvedUrl = url;
        
        // Check if URL contains Postman variables ({{variable_name}})
        if (url.includes('{{') && url.includes('}}')) {
            // Replace common variables
            resolvedUrl = url.replace(/\{\{([^}]+)\}\}/g, (match, variableName) => {
                return pm.variables.get(variableName) || 
                       pm.environment.get(variableName) || 
                       pm.collectionVariables.get(variableName) || 
                       pm.globals.get(variableName) || 
                       match; // Keep original if not found
            });
        }
        
        // If still contains unresolved variables, try to extract path manually
        if (resolvedUrl.includes('{{')) {
            // Find the path part after the base URL variable
            const pathMatch = url.match(/\{\{[^}]+\}\}(.*)$/);
            if (pathMatch && pathMatch[1]) {
                return pathMatch[1].split('?')[0]; // Remove query params
            }
        }
        
        // Try to parse as complete URL
        const urlObj = new URL(resolvedUrl);
        return urlObj.pathname;
    } catch (e) {
        if (url.includes('{{') && url.includes('}}')) {
            const pathMatch = url.match(/\{\{[^}]+\}\}(.*)$/);
            if (pathMatch && pathMatch[1]) {
                return pathMatch[1].split('?')[0];
            }
        }
        
        // If it's already a path (starts with /)
        if (url.startsWith('/')) {
            return url.split('?')[0];
        }
        
        // Last resort: try to find path after domain
        const pathMatch = url.match(/^https?:\/\/[^\/]+(.*)$/);
        if (pathMatch) {
            return pathMatch[1] || '/';
        }
        
        // Default fallback
        return url.split('?')[0];
    }
}

// ==============================================
// GENERATE AUTHENTICATION HEADERS
// ==============================================
function create_auth(){
    try {
        const API_KEY = pm.environment.get("yc_api_key") || "your-api-key-here";
        const SECRET_KEY = pm.environment.get("yc_secret_key") || "your-secret-key-here";


        // Get request details
        const requestUrl = pm.request.url.toString();
        const requestMethod = pm.request.method;
        const requestBody = pm.request.body ? pm.request.body.raw : null;
        
        // Extract path from URL
        const path = extractPath(requestUrl);
        
        // Generate timestamp
        const timestamp = generateTimestamp();
        
        // Build message to sign
        const message = buildMessageToSign(timestamp, path, requestMethod, requestBody);
        console.log(message)
        // Generate signature
        const signature = generateSignature(message, SECRET_KEY);
        // console.log(signature)
        
        // Build authorization header
        const authHeader = `YcHmacV1 ${API_KEY}:${signature}`;
        
        // Set headers
        pm.request.headers.add({
            key: "X-YC-Timestamp",
            value: timestamp
        });
        
        pm.request.headers.add({
            key: "Authorization", 
            value: authHeader
        });
        
        // Optional: Log for debugging (remove in production)
        console.log("=== YC API Authentication Debug ===");
        console.log("Timestamp:", timestamp);
        console.log("Path:", path);
        console.log("Method:", requestMethod);
        console.log("Request Body:", requestBody);
        console.log("Message to sign:", message);
        console.log("Signature:", signature);
        console.log("Authorization Header:", authHeader);
        console.log("================================");
        
        // Store in variables for reference
        pm.collectionVariables.set("last_timestamp", timestamp);
        pm.collectionVariables.set("last_signature", signature);
        
    } catch (error) {
        console.error("Error generating YC API authentication:", error);
        throw error;
    }
}

module.exports = {
    create_auth
}
```
