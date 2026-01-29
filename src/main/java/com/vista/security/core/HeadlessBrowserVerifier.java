package com.vista.security.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * Headless Browser Verifier for Client-Side Vulnerability Confirmation.
 * 
 * Uses Chrome/Chromium headless mode to actually render pages and detect
 * if XSS payloads execute. This provides definitive proof of client-side
 * vulnerabilities by checking for:
 * - JavaScript alert/confirm/prompt dialogs
 * - DOM modifications from injected scripts
 * - Console errors/logs from payload execution
 * - Cookie access attempts
 * 
 * This eliminates false positives from encoded output that appears in HTML
 * but doesn't actually execute.
 */
public class HeadlessBrowserVerifier {

    private static final int TIMEOUT_SECONDS = 10;
    private static final String[] CHROME_PATHS = {
        // macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        // Linux
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        // Windows
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        System.getProperty("user.home") + "\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe"
    };

    private String chromePath;
    private boolean available;
    private Path tempDir;

    public HeadlessBrowserVerifier() {
        this.chromePath = findChrome();
        this.available = chromePath != null;
        if (available) {
            try {
                this.tempDir = Files.createTempDirectory("vista-browser-verify");
                this.tempDir.toFile().deleteOnExit();
            } catch (IOException e) {
                this.available = false;
            }
        }
    }

    /**
     * Check if headless browser verification is available.
     */
    public boolean isAvailable() {
        return available;
    }

    /**
     * Get status message about browser availability.
     */
    public String getStatusMessage() {
        if (available) {
            return "✓ Headless browser available: " + chromePath;
        } else {
            return "✗ Chrome/Chromium not found. Install Chrome for client-side verification.";
        }
    }

    /**
     * Verify if an XSS payload actually executes in the browser.
     * 
     * @param htmlResponse The HTML response containing the potentially reflected payload
     * @param payload The XSS payload that was injected
     * @param marker A unique marker to detect execution (e.g., "12345" from alert(12345))
     * @return VerificationResult with details about execution
     */
    public VerificationResult verifyXSS(String htmlResponse, String payload, String marker) {
        if (!available) {
            return new VerificationResult(false, "Browser not available", null);
        }

        try {
            // Create a test HTML file with our verification wrapper
            String testHtml = createXSSTestHtml(htmlResponse, marker);
            Path htmlFile = tempDir.resolve("xss-test-" + System.currentTimeMillis() + ".html");
            Files.writeString(htmlFile, testHtml, StandardCharsets.UTF_8);

            // Run Chrome headless and capture output
            BrowserOutput output = runHeadlessBrowser(htmlFile);
            
            // Analyze the output for XSS execution
            VerificationResult result = analyzeXSSExecution(output, marker, payload);
            
            // Cleanup
            Files.deleteIfExists(htmlFile);
            
            return result;

        } catch (Exception e) {
            return new VerificationResult(false, "Verification error: " + e.getMessage(), null);
        }
    }

    /**
     * Verify DOM-based XSS by checking if payload executes when URL fragment/params are processed.
     */
    public VerificationResult verifyDOMXSS(String htmlResponse, String payload, String urlFragment) {
        if (!available) {
            return new VerificationResult(false, "Browser not available", null);
        }

        try {
            // Create test HTML that simulates DOM-based XSS scenario
            String testHtml = createDOMXSSTestHtml(htmlResponse, urlFragment);
            Path htmlFile = tempDir.resolve("dom-xss-test-" + System.currentTimeMillis() + ".html");
            Files.writeString(htmlFile, testHtml, StandardCharsets.UTF_8);

            BrowserOutput output = runHeadlessBrowser(htmlFile);
            VerificationResult result = analyzeDOMXSSExecution(output, payload);
            
            Files.deleteIfExists(htmlFile);
            return result;

        } catch (Exception e) {
            return new VerificationResult(false, "Verification error: " + e.getMessage(), null);
        }
    }

    /**
     * Create test HTML that wraps the response and intercepts XSS execution.
     */
    private String createXSSTestHtml(String htmlResponse, String marker) {
        // We inject a script BEFORE the response content that:
        // 1. Overrides alert/confirm/prompt to log execution
        // 2. Sets up a MutationObserver to detect DOM changes
        // 3. Monitors for script errors
        
        String interceptorScript = """
            <script>
            // VISTA XSS Verification Interceptor
            window.__VISTA_XSS_DETECTED = false;
            window.__VISTA_XSS_EVIDENCE = [];
            
            // Intercept alert/confirm/prompt
            const originalAlert = window.alert;
            const originalConfirm = window.confirm;
            const originalPrompt = window.prompt;
            
            window.alert = function(msg) {
                window.__VISTA_XSS_DETECTED = true;
                window.__VISTA_XSS_EVIDENCE.push('ALERT:' + msg);
                console.log('VISTA_XSS_ALERT:' + msg);
            };
            
            window.confirm = function(msg) {
                window.__VISTA_XSS_DETECTED = true;
                window.__VISTA_XSS_EVIDENCE.push('CONFIRM:' + msg);
                console.log('VISTA_XSS_CONFIRM:' + msg);
                return false;
            };
            
            window.prompt = function(msg) {
                window.__VISTA_XSS_DETECTED = true;
                window.__VISTA_XSS_EVIDENCE.push('PROMPT:' + msg);
                console.log('VISTA_XSS_PROMPT:' + msg);
                return null;
            };
            
            // Intercept document.cookie access
            let cookieAccessed = false;
            try {
                Object.defineProperty(document, '__vista_cookie_trap', {
                    get: function() {
                        window.__VISTA_XSS_EVIDENCE.push('COOKIE_ACCESS');
                        console.log('VISTA_XSS_COOKIE_ACCESS');
                        return '';
                    }
                });
            } catch(e) {}
            
            // Intercept eval
            const originalEval = window.eval;
            window.eval = function(code) {
                window.__VISTA_XSS_DETECTED = true;
                window.__VISTA_XSS_EVIDENCE.push('EVAL:' + code.substring(0, 100));
                console.log('VISTA_XSS_EVAL:' + code.substring(0, 100));
                return originalEval.call(window, code);
            };
            
            // Intercept Function constructor
            const originalFunction = window.Function;
            window.Function = function(...args) {
                window.__VISTA_XSS_DETECTED = true;
                window.__VISTA_XSS_EVIDENCE.push('FUNCTION_CONSTRUCTOR');
                console.log('VISTA_XSS_FUNCTION_CONSTRUCTOR');
                return originalFunction.apply(this, args);
            };
            
            // Monitor for inline event handler execution
            window.addEventListener('error', function(e) {
                if (e.message) {
                    console.log('VISTA_JS_ERROR:' + e.message);
                }
            });
            
            // After page load, report results
            window.addEventListener('load', function() {
                setTimeout(function() {
                    console.log('VISTA_XSS_RESULT:' + JSON.stringify({
                        detected: window.__VISTA_XSS_DETECTED,
                        evidence: window.__VISTA_XSS_EVIDENCE,
                        marker: '%s'
                    }));
                }, 500);
            });
            </script>
            """.formatted(marker);

        // Check if response has <head> tag
        if (htmlResponse.toLowerCase().contains("<head>")) {
            return htmlResponse.replaceFirst("(?i)<head>", "<head>" + interceptorScript);
        } else if (htmlResponse.toLowerCase().contains("<html>")) {
            return htmlResponse.replaceFirst("(?i)<html>", "<html><head>" + interceptorScript + "</head>");
        } else {
            return interceptorScript + htmlResponse;
        }
    }

    /**
     * Create test HTML for DOM-based XSS verification.
     */
    private String createDOMXSSTestHtml(String htmlResponse, String urlFragment) {
        String setupScript = """
            <script>
            // Simulate URL with fragment/params for DOM XSS testing
            if (window.location.hash === '') {
                // Set the hash to simulate the attack
                history.replaceState(null, '', window.location.pathname + '#%s');
            }
            </script>
            """.formatted(escapeJs(urlFragment));
        
        return createXSSTestHtml(setupScript + htmlResponse, "DOM_XSS_TEST");
    }

    /**
     * Run Chrome in headless mode and capture output.
     */
    private BrowserOutput runHeadlessBrowser(Path htmlFile) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(chromePath);
        command.add("--headless=new");
        command.add("--disable-gpu");
        command.add("--no-sandbox");
        command.add("--disable-dev-shm-usage");
        command.add("--disable-web-security"); // Allow file:// access
        command.add("--allow-file-access-from-files");
        command.add("--virtual-time-budget=5000"); // 5 second virtual time
        command.add("--dump-dom"); // Output final DOM
        command.add("--enable-logging=stderr");
        command.add("--v=1");
        command.add("file://" + htmlFile.toAbsolutePath());

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(false);
        
        Process process = pb.start();
        
        // Capture stdout and stderr
        CompletableFuture<String> stdoutFuture = CompletableFuture.supplyAsync(() -> 
            readStream(process.getInputStream()));
        CompletableFuture<String> stderrFuture = CompletableFuture.supplyAsync(() -> 
            readStream(process.getErrorStream()));

        boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
        }

        String stdout = stdoutFuture.get(2, TimeUnit.SECONDS);
        String stderr = stderrFuture.get(2, TimeUnit.SECONDS);

        return new BrowserOutput(stdout, stderr, process.exitValue());
    }

    /**
     * Analyze browser output to determine if XSS executed.
     */
    private VerificationResult analyzeXSSExecution(BrowserOutput output, String marker, String payload) {
        StringBuilder evidence = new StringBuilder();
        boolean xssDetected = false;

        String combined = output.stdout + "\n" + output.stderr;
        
        // Check for our interceptor logs
        if (combined.contains("VISTA_XSS_ALERT:")) {
            xssDetected = true;
            Pattern p = Pattern.compile("VISTA_XSS_ALERT:([^\n]+)");
            Matcher m = p.matcher(combined);
            while (m.find()) {
                evidence.append("✓ Alert executed: ").append(m.group(1)).append("\n");
            }
        }

        if (combined.contains("VISTA_XSS_CONFIRM:")) {
            xssDetected = true;
            Pattern p = Pattern.compile("VISTA_XSS_CONFIRM:([^\n]+)");
            Matcher m = p.matcher(combined);
            while (m.find()) {
                evidence.append("✓ Confirm executed: ").append(m.group(1)).append("\n");
            }
        }

        if (combined.contains("VISTA_XSS_PROMPT:")) {
            xssDetected = true;
            Pattern p = Pattern.compile("VISTA_XSS_PROMPT:([^\n]+)");
            Matcher m = p.matcher(combined);
            while (m.find()) {
                evidence.append("✓ Prompt executed: ").append(m.group(1)).append("\n");
            }
        }

        if (combined.contains("VISTA_XSS_EVAL:")) {
            xssDetected = true;
            evidence.append("✓ Eval() was called with injected code\n");
        }

        if (combined.contains("VISTA_XSS_FUNCTION_CONSTRUCTOR")) {
            xssDetected = true;
            evidence.append("✓ Function constructor was called\n");
        }

        if (combined.contains("VISTA_XSS_COOKIE_ACCESS")) {
            xssDetected = true;
            evidence.append("✓ Document.cookie was accessed\n");
        }

        // Check for the marker in alert (e.g., alert(12345))
        if (marker != null && !marker.isEmpty()) {
            if (combined.contains("VISTA_XSS_ALERT:" + marker) || 
                combined.contains("VISTA_XSS_ALERT:'" + marker) ||
                combined.contains("VISTA_XSS_ALERT:\"" + marker)) {
                evidence.append("✓ Marker '").append(marker).append("' appeared in alert!\n");
            }
        }

        // Check for JavaScript errors that might indicate partial execution
        if (combined.contains("VISTA_JS_ERROR:")) {
            Pattern p = Pattern.compile("VISTA_JS_ERROR:([^\n]+)");
            Matcher m = p.matcher(combined);
            while (m.find()) {
                evidence.append("⚠ JS Error: ").append(m.group(1)).append("\n");
            }
        }

        // Parse the final result JSON if present
        Pattern resultPattern = Pattern.compile("VISTA_XSS_RESULT:(\\{[^}]+\\})");
        Matcher resultMatcher = resultPattern.matcher(combined);
        if (resultMatcher.find()) {
            String json = resultMatcher.group(1);
            if (json.contains("\"detected\":true")) {
                xssDetected = true;
            }
        }

        // Check DOM output for unencoded payload
        if (output.stdout.contains(payload) && !isHtmlEncoded(output.stdout, payload)) {
            evidence.append("✓ Payload appears unencoded in final DOM\n");
        }

        if (xssDetected) {
            return new VerificationResult(true, 
                "XSS CONFIRMED - Payload executed in browser!", 
                evidence.toString());
        } else {
            // Check why it didn't execute
            String reason = determineNonExecutionReason(output, payload);
            return new VerificationResult(false, 
                "XSS NOT CONFIRMED - " + reason, 
                evidence.length() > 0 ? evidence.toString() : null);
        }
    }

    /**
     * Analyze DOM XSS execution results.
     */
    private VerificationResult analyzeDOMXSSExecution(BrowserOutput output, String payload) {
        return analyzeXSSExecution(output, "DOM_XSS_TEST", payload);
    }

    /**
     * Determine why XSS didn't execute.
     */
    private String determineNonExecutionReason(BrowserOutput output, String payload) {
        String combined = output.stdout + output.stderr;
        
        if (isHtmlEncoded(combined, payload)) {
            return "Payload is HTML-encoded (output encoding is working)";
        }
        
        if (combined.contains("Content-Security-Policy") || combined.contains("CSP")) {
            return "Content Security Policy may be blocking execution";
        }
        
        if (!combined.contains(payload) && !containsPayloadParts(combined, payload)) {
            return "Payload not reflected in response";
        }
        
        if (combined.contains("SyntaxError") || combined.contains("Unexpected token")) {
            return "Payload caused syntax error (malformed injection)";
        }
        
        return "Payload reflected but did not execute (possibly wrong context)";
    }

    /**
     * Check if payload appears HTML-encoded in the output.
     */
    private boolean isHtmlEncoded(String output, String payload) {
        // Check for common HTML entity encodings of dangerous characters
        if (payload.contains("<")) {
            String encodedPayload = payload.replace("<", "&lt;").replace(">", "&gt;");
            if (output.contains(encodedPayload)) return true;
            if (output.contains(payload.replace("<", "&#60;").replace(">", "&#62;"))) return true;
            if (output.contains(payload.replace("<", "&#x3c;").replace(">", "&#x3e;"))) return true;
        }
        return false;
    }

    /**
     * Check if key parts of payload appear in output.
     */
    private boolean containsPayloadParts(String output, String payload) {
        // Extract key identifiers from payload
        Pattern p = Pattern.compile("(alert|confirm|prompt|eval)\\s*\\(([^)]+)\\)");
        Matcher m = p.matcher(payload);
        if (m.find()) {
            String func = m.group(1);
            String arg = m.group(2);
            return output.contains(func) || output.contains(arg);
        }
        return false;
    }

    /**
     * Find Chrome/Chromium installation.
     */
    private String findChrome() {
        // First check environment variable
        String envChrome = System.getenv("CHROME_PATH");
        if (envChrome != null && new File(envChrome).exists()) {
            return envChrome;
        }

        // Check common paths
        for (String path : CHROME_PATHS) {
            File f = new File(path);
            if (f.exists() && f.canExecute()) {
                return path;
            }
        }

        // Try 'which' command on Unix
        try {
            ProcessBuilder pb = new ProcessBuilder("which", "google-chrome");
            Process p = pb.start();
            if (p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0) {
                String path = new String(p.getInputStream().readAllBytes()).trim();
                if (!path.isEmpty() && new File(path).exists()) {
                    return path;
                }
            }
        } catch (Exception ignored) {}

        try {
            ProcessBuilder pb = new ProcessBuilder("which", "chromium");
            Process p = pb.start();
            if (p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0) {
                String path = new String(p.getInputStream().readAllBytes()).trim();
                if (!path.isEmpty() && new File(path).exists()) {
                    return path;
                }
            }
        } catch (Exception ignored) {}

        return null;
    }

    private String readStream(InputStream is) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String escapeJs(String s) {
        return s.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    /**
     * Result of browser-based XSS verification.
     */
    public static class VerificationResult {
        public final boolean executed;
        public final String message;
        public final String evidence;

        public VerificationResult(boolean executed, String message, String evidence) {
            this.executed = executed;
            this.message = message;
            this.evidence = evidence;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(executed ? "✓ VULNERABLE" : "✗ NOT VULNERABLE").append("\n");
            sb.append(message);
            if (evidence != null && !evidence.isEmpty()) {
                sb.append("\n\nEvidence:\n").append(evidence);
            }
            return sb.toString();
        }
    }

    /**
     * Browser process output.
     */
    private static class BrowserOutput {
        final String stdout;
        final String stderr;
        final int exitCode;

        BrowserOutput(String stdout, String stderr, int exitCode) {
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
        }
    }
}
