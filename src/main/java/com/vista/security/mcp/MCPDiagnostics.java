package com.vista.security.mcp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Diagnostic utilities for MCP connection troubleshooting.
 */
public class MCPDiagnostics {
    
    /**
     * Run comprehensive diagnostics on MCP connection.
     * Returns detailed diagnostic report.
     */
    public static String runDiagnostics(String serverUrl) {
        StringBuilder report = new StringBuilder();
        report.append("=== MCP Connection Diagnostics ===\n\n");
        
        // Test 1: Basic connectivity
        report.append("Test 1: Basic Connectivity\n");
        report.append("URL: ").append(serverUrl).append("\n");
        
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            
            // Try GET request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Accept", "application/json, text/event-stream")
                    .GET()
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            report.append("Status Code: ").append(response.statusCode()).append("\n");
            report.append("Headers: ").append(response.headers().map()).append("\n");
            
            if (response.statusCode() == 200) {
                report.append("✓ Server is reachable and responding\n");
            } else if (response.statusCode() == 405) {
                report.append("✓ Server is reachable (GET not allowed, but server exists)\n");
            } else if (response.statusCode() == 404) {
                report.append("⚠ Server returned 404 - trying /sse endpoint...\n");
                
                // Try /sse endpoint
                String sseUrl = serverUrl.endsWith("/") ? serverUrl + "sse" : serverUrl + "/sse";
                HttpRequest sseRequest = HttpRequest.newBuilder()
                        .uri(URI.create(sseUrl))
                        .timeout(Duration.ofSeconds(5))
                        .header("Accept", "application/json, text/event-stream")
                        .GET()
                        .build();
                
                HttpResponse<String> sseResponse = client.send(sseRequest, HttpResponse.BodyHandlers.ofString());
                report.append("SSE Endpoint Status: ").append(sseResponse.statusCode()).append("\n");
                
                if (sseResponse.statusCode() == 200 || sseResponse.statusCode() == 405) {
                    report.append("✓ Server found at /sse endpoint\n");
                    report.append("💡 Try using URL: ").append(sseUrl).append("\n");
                }
            } else {
                report.append("✗ Unexpected status code: ").append(response.statusCode()).append("\n");
            }
            
        } catch (java.net.ConnectException e) {
            report.append("✗ Connection refused\n");
            report.append("Error: ").append(e.getMessage()).append("\n");
            report.append("\nPossible causes:\n");
            report.append("1. Burp MCP Server extension not installed\n");
            report.append("2. MCP server not enabled in Burp\n");
            report.append("3. Wrong port number (default is 9876)\n");
            report.append("4. Burp Suite not running\n");
        } catch (java.net.http.HttpTimeoutException e) {
            report.append("✗ Connection timeout\n");
            report.append("Error: ").append(e.getMessage()).append("\n");
            report.append("\nPossible causes:\n");
            report.append("1. Server is slow to respond\n");
            report.append("2. Network issues\n");
            report.append("3. Firewall blocking connection\n");
        } catch (IOException | InterruptedException e) {
            report.append("✗ Connection error\n");
            report.append("Error: ").append(e.getClass().getSimpleName()).append(" - ").append(e.getMessage()).append("\n");
        }
        
        // Test 2: Try POST request (MCP uses POST)
        report.append("\nTest 2: MCP Protocol Test (POST)\n");
        
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            
            // Simple JSON-RPC request
            String jsonBody = "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}";
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            report.append("POST Status Code: ").append(response.statusCode()).append("\n");
            
            if (response.statusCode() == 200) {
                report.append("✓ Server accepts POST requests\n");
                report.append("Response: ").append(response.body().substring(0, Math.min(200, response.body().length()))).append("\n");
            } else {
                report.append("⚠ POST returned: ").append(response.statusCode()).append("\n");
            }
            
        } catch (Exception e) {
            report.append("✗ POST request failed: ").append(e.getMessage()).append("\n");
        }
        
        // Recommendations
        report.append("\n=== Recommendations ===\n");
        report.append("1. Verify Burp MCP Server extension is installed:\n");
        report.append("   - Open Burp Suite\n");
        report.append("   - Go to Extensions tab\n");
        report.append("   - Look for 'MCP Server' in the list\n");
        report.append("   - Status should be 'Loaded'\n\n");
        
        report.append("2. Enable MCP server in Burp:\n");
        report.append("   - Go to MCP tab in Burp\n");
        report.append("   - Check 'Enabled' checkbox\n");
        report.append("   - Verify URL shows: http://127.0.0.1:9876\n\n");
        
        report.append("3. Check Burp's extension output:\n");
        report.append("   - Go to Extensions → Extension output\n");
        report.append("   - Look for MCP Server messages\n");
        report.append("   - Check for any error messages\n\n");
        
        report.append("4. Try accessing in browser:\n");
        report.append("   - Open: ").append(serverUrl).append("\n");
        report.append("   - Should see some response (even if error)\n");
        report.append("   - If browser can't connect, server isn't running\n");
        
        return report.toString();
    }
    
    /**
     * Quick connection test with simple pass/fail.
     */
    public static boolean quickTest(String serverUrl) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl))
                    .timeout(Duration.ofSeconds(3))
                    .header("Accept", "application/json, text/event-stream")
                    .GET()
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200 || response.statusCode() == 405;
            
        } catch (Exception e) {
            return false;
        }
    }
}
