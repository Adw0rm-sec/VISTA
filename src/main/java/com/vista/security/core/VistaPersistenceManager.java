package com.vista.security.core;

import com.vista.security.model.ExploitFinding;
import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Centralized data persistence manager for VISTA.
 * 
 * Handles saving/loading of:
 * - Traffic transactions (HttpTransaction) → ~/.vista/data/traffic.json
 * - Exploit findings (ExploitFinding) → ~/.vista/data/findings.json
 * - Traffic findings (TrafficFinding) → ~/.vista/data/traffic-findings.json
 * 
 * Features:
 * - Auto-save every 60 seconds (configurable)
 * - Save on demand (e.g., on extension unload)
 * - JVM shutdown hook for unexpected termination
 * - Atomic file writes (write to .tmp, then rename) to prevent corruption
 * - Thread-safe operations
 * 
 * @version 1.0
 */
public class VistaPersistenceManager {
    
    private static VistaPersistenceManager instance;
    
    private static final String DATA_DIR = System.getProperty("user.home") + File.separator + ".vista" + File.separator + "data";
    private static final String TRAFFIC_FILE = "traffic.json";
    private static final String FINDINGS_FILE = "findings.json";
    private static final String TRAFFIC_FINDINGS_FILE = "traffic-findings.json";
    private static final int AUTO_SAVE_INTERVAL_SECONDS = 60;
    private static final int MAX_TRAFFIC_TO_PERSIST = 2000; // Limit to prevent huge files
    
    private ScheduledExecutorService autoSaveExecutor;
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private Thread shutdownHook;
    
    private VistaPersistenceManager() {
        // Ensure data directory exists
        try {
            Files.createDirectories(Paths.get(DATA_DIR));
        } catch (IOException e) {
            System.err.println("[VISTA] Failed to create data directory: " + e.getMessage());
        }
    }
    
    public static synchronized VistaPersistenceManager getInstance() {
        if (instance == null) {
            instance = new VistaPersistenceManager();
        }
        return instance;
    }
    
    /**
     * Initializes the persistence manager.
     * Loads all persisted data into the in-memory managers.
     * Starts auto-save timer and registers JVM shutdown hook.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            return; // Already initialized
        }
        
        System.out.println("[VISTA] Initializing persistence manager...");
        
        // Load persisted data
        loadAllData();
        
        // Start auto-save timer
        startAutoSave();
        
        // Register JVM shutdown hook for unexpected termination
        shutdownHook = new Thread(() -> {
            System.out.println("[VISTA] Shutdown hook triggered - saving all data...");
            saveAllDataSync();
        }, "VISTA-ShutdownHook");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        
        System.out.println("[VISTA] Persistence manager initialized successfully");
    }
    
    /**
     * Marks data as dirty (needs saving).
     * Called by managers when data changes.
     */
    public void markDirty() {
        dirty.set(true);
    }
    
    /**
     * Saves all data immediately (synchronous).
     * Called on extension unload and from shutdown hook.
     */
    public void saveAllDataSync() {
        try {
            System.out.println("[VISTA] Saving all data...");
            long start = System.currentTimeMillis();
            
            saveTrafficData();
            saveExploitFindings();
            saveTrafficFindings();
            
            dirty.set(false);
            long elapsed = System.currentTimeMillis() - start;
            System.out.println("[VISTA] All data saved in " + elapsed + "ms");
        } catch (Exception e) {
            System.err.println("[VISTA] Error saving data: " + e.getMessage());
        }
    }
    
    /**
     * Loads all persisted data into the in-memory managers.
     */
    private void loadAllData() {
        try {
            long start = System.currentTimeMillis();
            
            int trafficCount = loadTrafficData();
            int findingsCount = loadExploitFindings();
            int trafficFindingsCount = loadTrafficFindings();
            
            long elapsed = System.currentTimeMillis() - start;
            System.out.println("[VISTA] Loaded " + trafficCount + " traffic records, " 
                    + findingsCount + " findings, " + trafficFindingsCount 
                    + " traffic findings in " + elapsed + "ms");
        } catch (Exception e) {
            System.err.println("[VISTA] Error loading persisted data: " + e.getMessage());
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Traffic Data (HttpTransaction)
    // ═══════════════════════════════════════════════════════════════
    
    private void saveTrafficData() {
        try {
            TrafficBufferManager buffer = TrafficBufferManager.getGlobalInstance();
            if (buffer == null) return;
            
            List<HttpTransaction> transactions = buffer.getAllTransactions();
            
            // Limit to most recent N to prevent huge files
            int startIdx = Math.max(0, transactions.size() - MAX_TRAFFIC_TO_PERSIST);
            List<HttpTransaction> toSave = transactions.subList(startIdx, transactions.size());
            
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            for (int i = 0; i < toSave.size(); i++) {
                sb.append(toSave.get(i).toJson());
                if (i < toSave.size() - 1) sb.append(",\n");
            }
            sb.append("\n]");
            
            writeFileAtomic(TRAFFIC_FILE, sb.toString());
        } catch (Exception e) {
            System.err.println("[VISTA] Error saving traffic data: " + e.getMessage());
        }
    }
    
    private int loadTrafficData() {
        try {
            String json = readFile(TRAFFIC_FILE);
            if (json == null || json.trim().isEmpty()) return 0;
            
            List<String> items = splitJsonArray(json);
            if (items.isEmpty()) return 0;
            
            TrafficBufferManager buffer = TrafficBufferManager.getGlobalInstance();
            if (buffer == null) return 0;
            
            int loaded = 0;
            for (String item : items) {
                HttpTransaction tx = HttpTransaction.fromJson(item);
                if (tx != null) {
                    buffer.addTransactionSilently(tx); // Don't trigger listeners during load
                    loaded++;
                }
            }
            return loaded;
        } catch (Exception e) {
            System.err.println("[VISTA] Error loading traffic data: " + e.getMessage());
            return 0;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Exploit Findings (ExploitFinding)
    // ═══════════════════════════════════════════════════════════════
    
    private void saveExploitFindings() {
        try {
            FindingsManager fm = FindingsManager.getInstance();
            List<ExploitFinding> findings = fm.getFindings();
            
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            for (int i = 0; i < findings.size(); i++) {
                sb.append(findings.get(i).toJson());
                if (i < findings.size() - 1) sb.append(",\n");
            }
            sb.append("\n]");
            
            writeFileAtomic(FINDINGS_FILE, sb.toString());
        } catch (Exception e) {
            System.err.println("[VISTA] Error saving exploit findings: " + e.getMessage());
        }
    }
    
    private int loadExploitFindings() {
        try {
            String json = readFile(FINDINGS_FILE);
            if (json == null || json.trim().isEmpty()) return 0;
            
            List<String> items = splitJsonArray(json);
            if (items.isEmpty()) return 0;
            
            FindingsManager fm = FindingsManager.getInstance();
            
            int loaded = 0;
            for (String item : items) {
                ExploitFinding finding = ExploitFinding.fromJson(item);
                if (finding != null) {
                    fm.addFindingSilently(finding); // Don't trigger listeners during load
                    loaded++;
                }
            }
            return loaded;
        } catch (Exception e) {
            System.err.println("[VISTA] Error loading exploit findings: " + e.getMessage());
            return 0;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Traffic Findings (TrafficFinding) 
    // ═══════════════════════════════════════════════════════════════
    
    private void saveTrafficFindings() {
        try {
            // Traffic findings are stored in TrafficMonitorPanel's analysis engine
            // We access them via a static holder
            List<TrafficFinding> findings = TrafficFindingsHolder.getInstance().getFindings();
            if (findings == null || findings.isEmpty()) {
                // Write empty array
                writeFileAtomic(TRAFFIC_FINDINGS_FILE, "[]");
                return;
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            for (int i = 0; i < findings.size(); i++) {
                sb.append(findings.get(i).toJson());
                if (i < findings.size() - 1) sb.append(",\n");
            }
            sb.append("\n]");
            
            writeFileAtomic(TRAFFIC_FINDINGS_FILE, sb.toString());
        } catch (Exception e) {
            System.err.println("[VISTA] Error saving traffic findings: " + e.getMessage());
        }
    }
    
    private int loadTrafficFindings() {
        try {
            String json = readFile(TRAFFIC_FINDINGS_FILE);
            if (json == null || json.trim().isEmpty()) return 0;
            
            List<String> items = splitJsonArray(json);
            if (items.isEmpty()) return 0;
            
            List<TrafficFinding> findings = new ArrayList<>();
            for (String item : items) {
                TrafficFinding finding = TrafficFinding.fromJson(item);
                if (finding != null) {
                    findings.add(finding);
                }
            }
            
            if (!findings.isEmpty()) {
                TrafficFindingsHolder.getInstance().setFindings(findings);
            }
            return findings.size();
        } catch (Exception e) {
            System.err.println("[VISTA] Error loading traffic findings: " + e.getMessage());
            return 0;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Auto-Save Timer
    // ═══════════════════════════════════════════════════════════════
    
    private void startAutoSave() {
        autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "VISTA-AutoSave");
            t.setDaemon(true);
            return t;
        });
        
        autoSaveExecutor.scheduleWithFixedDelay(() -> {
            if (dirty.getAndSet(false)) {
                try {
                    saveAllDataSync();
                } catch (Exception e) {
                    System.err.println("[VISTA] Auto-save error: " + e.getMessage());
                }
            }
        }, AUTO_SAVE_INTERVAL_SECONDS, AUTO_SAVE_INTERVAL_SECONDS, TimeUnit.SECONDS);
        
        System.out.println("[VISTA] Auto-save started (every " + AUTO_SAVE_INTERVAL_SECONDS + "s)");
    }
    
    /**
     * Shuts down the persistence manager.
     * Saves all data, stops auto-save timer, removes shutdown hook.
     */
    public void shutdown() {
        System.out.println("[VISTA] Shutting down persistence manager...");
        
        // Final save
        saveAllDataSync();
        
        // Stop auto-save
        if (autoSaveExecutor != null) {
            autoSaveExecutor.shutdownNow();
            autoSaveExecutor = null;
        }
        
        // Remove shutdown hook (we already saved)
        if (shutdownHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // JVM is already shutting down
            }
            shutdownHook = null;
        }
        
        initialized.set(false);
        System.out.println("[VISTA] Persistence manager shut down");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Backup Export / Import
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Exports all VISTA data to a backup directory at the given destination.
     * Creates a timestamped "vista-backup-YYYYMMDD-HHmmss" folder containing:
     *   - data/          (traffic, findings)
     *   - prompts/       (custom templates)
     *   - payloads/      (custom + built-in payloads, test history)
     *   - sessions/      (conversation history)
     *   - ai-config.json (AI provider configuration)
     *
     * @param destDir parent directory where the backup folder will be created
     * @return the backup folder path
     * @throws IOException if any I/O error occurs
     */
    public File exportBackup(File destDir) throws IOException {
        // Force a fresh save before exporting
        saveAllDataSync();
        
        String timestamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(new java.util.Date());
        File backupDir = new File(destDir, "vista-backup-" + timestamp);
        if (!backupDir.mkdirs()) {
            throw new IOException("Failed to create backup directory: " + backupDir.getAbsolutePath());
        }
        
        String vistaHome = System.getProperty("user.home") + File.separator + ".vista";
        String aiConfigFile = System.getProperty("user.home") + File.separator + ".vista-ai-config.json";
        
        // Copy data directory
        copyDirectoryIfExists(new File(vistaHome, "data"), new File(backupDir, "data"));
        
        // Copy custom prompts
        copyDirectoryIfExists(new File(vistaHome, "prompts" + File.separator + "custom"),
                new File(backupDir, "prompts" + File.separator + "custom"));
        
        // Copy payloads (custom + built-in + test history)
        copyDirectoryIfExists(new File(vistaHome, "payloads"), new File(backupDir, "payloads"));
        
        // Copy sessions
        copyDirectoryIfExists(new File(vistaHome, "sessions"), new File(backupDir, "sessions"));
        
        // Copy AI config file
        File configSrc = new File(aiConfigFile);
        if (configSrc.exists()) {
            Files.copy(configSrc.toPath(), new File(backupDir, "ai-config.json").toPath());
        }
        
        System.out.println("[VISTA] Backup exported to: " + backupDir.getAbsolutePath());
        return backupDir;
    }
    
    /**
     * Imports a VISTA backup from the given backup directory.
     * Restores all data files and reloads them into memory.
     *
     * @param backupDir the backup directory to import from (e.g. vista-backup-20250101-120000)
     * @return number of items restored
     * @throws IOException if the backup is invalid or I/O error occurs
     */
    public int importBackup(File backupDir) throws IOException {
        // Validate backup directory
        if (!backupDir.exists() || !backupDir.isDirectory()) {
            throw new IOException("Invalid backup directory: " + backupDir.getAbsolutePath());
        }
        
        // Check it looks like a VISTA backup (must have at least data/ or ai-config.json)
        boolean hasData = new File(backupDir, "data").exists();
        boolean hasConfig = new File(backupDir, "ai-config.json").exists();
        boolean hasPrompts = new File(backupDir, "prompts").exists();
        boolean hasPayloads = new File(backupDir, "payloads").exists();
        boolean hasSessions = new File(backupDir, "sessions").exists();
        
        if (!hasData && !hasConfig && !hasPrompts && !hasPayloads && !hasSessions) {
            throw new IOException("This doesn't appear to be a valid VISTA backup.\n" +
                    "Expected folders: data/, prompts/, payloads/, sessions/ or ai-config.json");
        }
        
        String vistaHome = System.getProperty("user.home") + File.separator + ".vista";
        String aiConfigFile = System.getProperty("user.home") + File.separator + ".vista-ai-config.json";
        int restored = 0;
        
        // Restore data directory
        if (hasData) {
            copyDirectoryIfExists(new File(backupDir, "data"), new File(vistaHome, "data"));
            restored++;
        }
        
        // Restore custom prompts
        if (hasPrompts) {
            copyDirectoryIfExists(new File(backupDir, "prompts" + File.separator + "custom"),
                    new File(vistaHome, "prompts" + File.separator + "custom"));
            restored++;
        }
        
        // Restore payloads
        if (hasPayloads) {
            copyDirectoryIfExists(new File(backupDir, "payloads"), new File(vistaHome, "payloads"));
            restored++;
        }
        
        // Restore sessions
        if (hasSessions) {
            copyDirectoryIfExists(new File(backupDir, "sessions"), new File(vistaHome, "sessions"));
            restored++;
        }
        
        // Restore AI config
        if (hasConfig) {
            Files.copy(new File(backupDir, "ai-config.json").toPath(), 
                    new File(aiConfigFile).toPath(), StandardCopyOption.REPLACE_EXISTING);
            restored++;
        }
        
        // Reload all data into memory
        loadAllData();
        
        System.out.println("[VISTA] Backup imported from: " + backupDir.getAbsolutePath() 
                + " (" + restored + " sections restored)");
        return restored;
    }
    
    /**
     * Recursively copies a directory. Creates destination if it doesn't exist.
     */
    private void copyDirectoryIfExists(File src, File dest) throws IOException {
        if (!src.exists() || !src.isDirectory()) return;
        
        if (!dest.exists()) {
            dest.mkdirs();
        }
        
        File[] files = src.listFiles();
        if (files == null) return;
        
        for (File file : files) {
            File destFile = new File(dest, file.getName());
            if (file.isDirectory()) {
                copyDirectoryIfExists(file, destFile);
            } else {
                Files.copy(file.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // File I/O Utilities
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Writes content to a file atomically (write to .tmp, then rename).
     * Prevents file corruption if the process is killed mid-write.
     */
    private void writeFileAtomic(String filename, String content) throws IOException {
        Path targetPath = Paths.get(DATA_DIR, filename);
        Path tmpPath = Paths.get(DATA_DIR, filename + ".tmp");
        
        // Write to temp file
        Files.write(tmpPath, content.getBytes(StandardCharsets.UTF_8), 
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        
        // Atomic rename
        Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    
    /**
     * Reads a file's content, or returns null if it doesn't exist.
     */
    private String readFile(String filename) {
        try {
            Path path = Paths.get(DATA_DIR, filename);
            if (!Files.exists(path)) return null;
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("[VISTA] Error reading file " + filename + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Splits a JSON array string into individual JSON object strings.
     * Hand-rolled parser that tracks brace nesting depth.
     */
    private List<String> splitJsonArray(String json) {
        List<String> items = new ArrayList<>();
        if (json == null) return items;
        
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) return items;
        
        // Remove outer brackets
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return items;
        
        int depth = 0;
        int start = -1;
        boolean inString = false;
        boolean escaped = false;
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            
            if (escaped) {
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                continue;
            }
            
            if (c == '"') {
                inString = !inString;
                continue;
            }
            
            if (inString) continue;
            
            if (c == '{') {
                if (depth == 0) start = i;
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && start >= 0) {
                    items.add(json.substring(start, i + 1));
                    start = -1;
                }
            }
        }
        
        return items;
    }
}
