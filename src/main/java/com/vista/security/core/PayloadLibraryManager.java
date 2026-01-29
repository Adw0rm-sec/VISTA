package com.vista.security.core;

import com.vista.security.model.Payload;
import com.vista.security.model.PayloadLibrary;
import com.vista.security.model.PayloadTestResult;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Manages payload libraries, including built-in and custom payloads.
 * Handles loading, saving, searching, and tracking payload success rates.
 */
public class PayloadLibraryManager {
    
    private static PayloadLibraryManager instance;
    private final String payloadsDir;
    private final String builtInDir;
    private final String customDir;
    private final String testHistoryFile;
    
    private Map<String, PayloadLibrary> libraries;
    private List<PayloadTestResult> testHistory;
    private boolean initialized;
    
    private PayloadLibraryManager() {
        String homeDir = System.getProperty("user.home");
        this.payloadsDir = homeDir + File.separator + ".vista" + File.separator + "payloads";
        this.builtInDir = payloadsDir + File.separator + "built-in";
        this.customDir = payloadsDir + File.separator + "custom";
        this.testHistoryFile = payloadsDir + File.separator + "test-history.json";
        
        this.libraries = new HashMap<>();
        this.testHistory = new ArrayList<>();
        this.initialized = false;
    }
    
    public static synchronized PayloadLibraryManager getInstance() {
        if (instance == null) {
            instance = new PayloadLibraryManager();
        }
        return instance;
    }
    
    /**
     * Initialize the manager - create directories and load libraries.
     */
    public void initialize() {
        if (initialized) return;
        
        try {
            // Create directories
            Files.createDirectories(Paths.get(builtInDir));
            Files.createDirectories(Paths.get(customDir));
            
            // Load built-in libraries
            loadBuiltInLibraries();
            
            // Load custom libraries
            loadCustomLibraries();
            
            // Load test history
            loadTestHistory();
            
            initialized = true;
        } catch (Exception e) {
            System.err.println("Failed to initialize PayloadLibraryManager: " + e.getMessage());
        }
    }
    
    /**
     * Load built-in payload libraries from disk.
     */
    private void loadBuiltInLibraries() {
        File dir = new File(builtInDir);
        if (!dir.exists()) return;
        
        File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
        if (files == null) return;
        
        for (File file : files) {
            try {
                String json = new String(Files.readAllBytes(file.toPath()));
                PayloadLibrary library = PayloadLibrary.fromJson(json);
                library.setBuiltIn(true);
                libraries.put(library.getId(), library);
            } catch (Exception e) {
                System.err.println("Failed to load built-in library: " + file.getName());
            }
        }
    }
    
    /**
     * Load custom payload libraries from disk.
     */
    private void loadCustomLibraries() {
        File dir = new File(customDir);
        if (!dir.exists()) return;
        
        File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
        if (files == null) return;
        
        for (File file : files) {
            try {
                String json = new String(Files.readAllBytes(file.toPath()));
                PayloadLibrary library = PayloadLibrary.fromJson(json);
                libraries.put(library.getId(), library);
            } catch (Exception e) {
                System.err.println("Failed to load custom library: " + file.getName());
            }
        }
    }
    
    /**
     * Load test history from disk.
     */
    private void loadTestHistory() {
        File file = new File(testHistoryFile);
        if (!file.exists()) return;
        
        try {
            String json = new String(Files.readAllBytes(file.toPath()));
            // Parse JSON array of test results
            testHistory = parseTestHistoryJson(json);
        } catch (Exception e) {
            System.err.println("Failed to load test history: " + e.getMessage());
        }
    }
    
    /**
     * Parse test history JSON array.
     */
    private List<PayloadTestResult> parseTestHistoryJson(String json) {
        List<PayloadTestResult> results = new ArrayList<>();
        
        // Simple JSON array parsing
        int depth = 0;
        StringBuilder currentResult = new StringBuilder();
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            
            if (c == '{') {
                depth++;
                currentResult.append(c);
            } else if (c == '}') {
                currentResult.append(c);
                depth--;
                
                if (depth == 0 && currentResult.length() > 0) {
                    String resultJson = currentResult.toString().trim();
                    if (!resultJson.isEmpty()) {
                        try {
                            results.add(PayloadTestResult.fromJson(resultJson));
                        } catch (Exception e) {
                            // Skip malformed result
                        }
                    }
                    currentResult = new StringBuilder();
                }
            } else if (depth > 0) {
                currentResult.append(c);
            }
        }
        
        return results;
    }
    
    /**
     * Save test history to disk.
     */
    private void saveTestHistory() {
        try {
            StringBuilder json = new StringBuilder();
            json.append("[\n");
            for (int i = 0; i < testHistory.size(); i++) {
                json.append("  ").append(testHistory.get(i).toJson());
                if (i < testHistory.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            json.append("]");
            
            Files.write(Paths.get(testHistoryFile), json.toString().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save test history: " + e.getMessage());
        }
    }
    
    // ========== Library Management ==========
    
    /**
     * Get all libraries (built-in and custom).
     */
    public List<PayloadLibrary> getAllLibraries() {
        return new ArrayList<>(libraries.values());
    }
    
    /**
     * Get library by ID.
     */
    public PayloadLibrary getLibrary(String id) {
        return libraries.get(id);
    }
    
    /**
     * Save a library (custom only - built-in cannot be modified).
     */
    public void saveLibrary(PayloadLibrary library) {
        if (library.isBuiltIn()) {
            throw new IllegalArgumentException("Cannot modify built-in libraries");
        }
        
        libraries.put(library.getId(), library);
        
        // Save to disk
        try {
            String filename = sanitizeFilename(library.getName()) + ".json";
            String filepath = customDir + File.separator + filename;
            Files.write(Paths.get(filepath), library.toJson().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save library: " + e.getMessage());
        }
    }
    
    /**
     * Delete a library (custom only).
     */
    public void deleteLibrary(String id) {
        PayloadLibrary library = libraries.get(id);
        if (library == null) return;
        
        if (library.isBuiltIn()) {
            throw new IllegalArgumentException("Cannot delete built-in libraries");
        }
        
        libraries.remove(id);
        
        // Delete from disk
        try {
            String filename = sanitizeFilename(library.getName()) + ".json";
            String filepath = customDir + File.separator + filename;
            Files.deleteIfExists(Paths.get(filepath));
        } catch (Exception e) {
            System.err.println("Failed to delete library: " + e.getMessage());
        }
    }
    
    /**
     * Create a new custom library.
     */
    public PayloadLibrary createLibrary(String name, String category, String subcategory) {
        PayloadLibrary library = new PayloadLibrary(name, category, subcategory);
        saveLibrary(library);
        return library;
    }
    
    // ========== Payload Operations ==========
    
    /**
     * Get all payloads from all libraries.
     */
    public List<Payload> getAllPayloads() {
        List<Payload> allPayloads = new ArrayList<>();
        for (PayloadLibrary library : libraries.values()) {
            allPayloads.addAll(library.getPayloads());
        }
        return allPayloads;
    }
    
    /**
     * Get payloads by category.
     */
    public List<Payload> getPayloadsByCategory(String category) {
        List<Payload> result = new ArrayList<>();
        for (PayloadLibrary library : libraries.values()) {
            if (library.getCategory().equalsIgnoreCase(category)) {
                result.addAll(library.getPayloads());
            }
        }
        return result;
    }
    
    /**
     * Get payloads by context.
     */
    public List<Payload> getPayloadsByContext(String context) {
        List<Payload> result = new ArrayList<>();
        for (PayloadLibrary library : libraries.values()) {
            result.addAll(library.getPayloadsByContext(context));
        }
        return result;
    }
    
    /**
     * Search payloads across all libraries.
     */
    public List<Payload> searchPayloads(String query) {
        List<Payload> result = new ArrayList<>();
        for (PayloadLibrary library : libraries.values()) {
            result.addAll(library.searchPayloads(query));
        }
        return result;
    }
    
    /**
     * Get top payload by category (highest success rate).
     */
    public Payload getTopPayload(String category) {
        List<Payload> payloads = getPayloadsByCategory(category);
        return payloads.stream()
            .filter(Payload::hasBeenUsed)
            .max(Comparator.comparingDouble(Payload::getSuccessRate))
            .orElse(null);
    }
    
    /**
     * Get recently used payloads.
     */
    public List<Payload> getRecentPayloads(int limit) {
        return getAllPayloads().stream()
            .filter(Payload::hasBeenUsed)
            .sorted((p1, p2) -> Long.compare(p2.getLastUsed(), p1.getLastUsed()))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    /**
     * Get top performing payloads across all libraries.
     */
    public List<Payload> getTopPayloads(int limit) {
        return getAllPayloads().stream()
            .filter(Payload::hasBeenUsed)
            .sorted((p1, p2) -> Double.compare(p2.getSuccessRate(), p1.getSuccessRate()))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    // ========== Testing History ==========
    
    /**
     * Record a test result.
     */
    public void recordTestResult(PayloadTestResult result) {
        testHistory.add(result);
        
        // Update payload stats
        updatePayloadStats(result.getPayloadId(), result.isSuccess());
        
        // Save to disk
        saveTestHistory();
    }
    
    /**
     * Get test history for a specific payload.
     */
    public List<PayloadTestResult> getTestHistory(String payloadId) {
        return testHistory.stream()
            .filter(r -> r.getPayloadId().equals(payloadId))
            .sorted((r1, r2) -> Long.compare(r2.getTimestamp(), r1.getTimestamp()))
            .collect(Collectors.toList());
    }
    
    /**
     * Get all test history.
     */
    public List<PayloadTestResult> getAllTestHistory() {
        return new ArrayList<>(testHistory);
    }
    
    /**
     * Update payload statistics based on test result.
     */
    public void updatePayloadStats(String payloadId, boolean success) {
        // Find the payload across all libraries
        for (PayloadLibrary library : libraries.values()) {
            Payload payload = library.getPayload(payloadId);
            if (payload != null) {
                if (success) {
                    payload.recordSuccess();
                } else {
                    payload.recordFailure();
                }
                
                // Save the library if it's custom
                if (!library.isBuiltIn()) {
                    saveLibrary(library);
                }
                break;
            }
        }
    }
    
    // ========== Import/Export ==========
    
    /**
     * Import library from file.
     */
    public PayloadLibrary importFromFile(File file) throws IOException {
        String json = new String(Files.readAllBytes(file.toPath()));
        PayloadLibrary library = PayloadLibrary.fromJson(json);
        
        // Mark as custom (not built-in)
        library.setBuiltIn(false);
        library.setSource("Imported");
        
        saveLibrary(library);
        return library;
    }
    
    /**
     * Export library to file.
     */
    public void exportLibrary(String id, File destination) throws IOException {
        PayloadLibrary library = libraries.get(id);
        if (library == null) {
            throw new IllegalArgumentException("Library not found: " + id);
        }
        
        Files.write(destination.toPath(), library.toJson().getBytes());
    }
    
    // ========== Statistics ==========
    
    /**
     * Get total number of payloads.
     */
    public int getTotalPayloadCount() {
        return getAllPayloads().size();
    }
    
    /**
     * Get total number of libraries.
     */
    public int getTotalLibraryCount() {
        return libraries.size();
    }
    
    /**
     * Get categories.
     */
    public List<String> getCategories() {
        return libraries.values().stream()
            .map(PayloadLibrary::getCategory)
            .distinct()
            .sorted()
            .collect(Collectors.toList());
    }
    
    /**
     * Get statistics summary.
     */
    public String getStatsSummary() {
        int totalLibraries = getTotalLibraryCount();
        int totalPayloads = getTotalPayloadCount();
        int usedPayloads = (int) getAllPayloads().stream().filter(Payload::hasBeenUsed).count();
        int totalTests = testHistory.size();
        
        return String.format("Libraries: %d | Payloads: %d | Used: %d | Tests: %d",
            totalLibraries, totalPayloads, usedPayloads, totalTests);
    }
    
    // ========== Utility Methods ==========
    
    /**
     * Sanitize filename for safe file system operations.
     */
    private String sanitizeFilename(String name) {
        return name.replaceAll("[^a-zA-Z0-9-_]", "_").toLowerCase();
    }
    
    /**
     * Check if manager is initialized.
     */
    public boolean isInitialized() {
        return initialized;
    }
}
