package com.vista.security.core;

import com.vista.security.model.HttpTransaction;
import com.vista.security.model.TrafficFinding;

import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * AnalysisQueueManager - Manages async queue-based AI analysis
 * 
 * Features:
 * - Single-threaded sequential processing (one request at a time)
 * - URL deduplication (skip already analyzed URLs)
 * - Callback-based result notification
 * - Non-blocking queue submission
 * - Graceful shutdown support
 */
public class AnalysisQueueManager {
    
    private static AnalysisQueueManager instance;
    
    private final ExecutorService analysisExecutor;
    private final BlockingQueue<AnalysisTask> analysisQueue;
    private final Set<String> analyzedUrls;
    private final Set<String> pendingUrls; // URLs currently in queue
    
    private volatile boolean running = true;
    private IntelligentTrafficAnalyzer analyzer;
    private Consumer<AnalysisResult> resultCallback;
    private Consumer<String> logCallback;
    
    /**
     * Analysis task wrapper
     */
    public static class AnalysisTask {
        public final HttpTransaction transaction;
        public final long submittedAt;
        
        public AnalysisTask(HttpTransaction transaction) {
            this.transaction = transaction;
            this.submittedAt = System.currentTimeMillis();
        }
    }
    
    /**
     * Analysis result wrapper
     */
    public static class AnalysisResult {
        public final HttpTransaction transaction;
        public final List<TrafficFinding> findings;
        public final long duration;
        public final boolean success;
        public final String error;
        
        public AnalysisResult(HttpTransaction transaction, List<TrafficFinding> findings, long duration) {
            this.transaction = transaction;
            this.findings = findings;
            this.duration = duration;
            this.success = true;
            this.error = null;
        }
        
        public AnalysisResult(HttpTransaction transaction, String error, long duration) {
            this.transaction = transaction;
            this.findings = null;
            this.duration = duration;
            this.success = false;
            this.error = error;
        }
    }
    
    private AnalysisQueueManager() {
        this.analysisQueue = new LinkedBlockingQueue<>(1000); // Max 1000 pending
        this.analyzedUrls = ConcurrentHashMap.newKeySet();
        this.pendingUrls = ConcurrentHashMap.newKeySet();
        
        // Single-threaded executor for sequential processing
        this.analysisExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "VISTA-AI-Analysis-Worker");
            t.setDaemon(true);
            return t;
        });
        
        // Start the processing loop
        startProcessingLoop();
    }
    
    public static synchronized AnalysisQueueManager getInstance() {
        if (instance == null) {
            instance = new AnalysisQueueManager();
        }
        return instance;
    }
    
    /**
     * Set the analyzer to use for processing
     */
    public void setAnalyzer(IntelligentTrafficAnalyzer analyzer) {
        this.analyzer = analyzer;
    }
    
    /**
     * Set callback for analysis results
     */
    public void setResultCallback(Consumer<AnalysisResult> callback) {
        this.resultCallback = callback;
    }
    
    /**
     * Set callback for logging
     */
    public void setLogCallback(Consumer<String> callback) {
        this.logCallback = callback;
    }
    
    /**
     * Submit a transaction for analysis (non-blocking)
     * Returns true if queued, false if skipped (already analyzed or in queue)
     */
    public boolean submitForAnalysis(HttpTransaction transaction) {
        if (transaction == null || analyzer == null) {
            return false;
        }
        
        String url = normalizeUrl(transaction.getUrl());
        
        // Debug: Check response state at queue submission
        byte[] response = transaction.getResponse();
        log("📝 SUBMIT CHECK: URL=" + url + ", Response=" + (response != null ? response.length + " bytes" : "NULL"));
        
        // Check if already analyzed
        if (analyzedUrls.contains(url)) {
            log("⏭️ QUEUE SKIP (already analyzed): " + url);
            return false;
        }
        
        // Check if already pending in queue
        if (pendingUrls.contains(url)) {
            log("⏭️ QUEUE SKIP (already pending): " + url);
            return false;
        }
        
        // Add to pending and queue
        pendingUrls.add(url);
        
        try {
            boolean added = analysisQueue.offer(new AnalysisTask(transaction), 100, TimeUnit.MILLISECONDS);
            if (!added) {
                pendingUrls.remove(url);
                log("⚠️ QUEUE FULL: Dropped " + url);
                return false;
            }
            
            log("📥 QUEUED [" + getQueueSize() + " pending]: " + url);
            return true;
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pendingUrls.remove(url);
            return false;
        }
    }
    
    /**
     * Normalize URL for deduplication (remove query params for certain cases)
     */
    private String normalizeUrl(String url) {
        if (url == null) return "";
        
        // For now, use full URL. Can be enhanced to normalize query params
        // Remove fragment
        int fragmentIndex = url.indexOf('#');
        if (fragmentIndex > 0) {
            url = url.substring(0, fragmentIndex);
        }
        
        return url;
    }
    
    /**
     * Start the background processing loop
     */
    private void startProcessingLoop() {
        analysisExecutor.submit(() -> {
            log("🚀 Analysis queue processor started");
            
            while (running) {
                try {
                    // Wait for next task (blocking with timeout)
                    AnalysisTask task = analysisQueue.poll(1, TimeUnit.SECONDS);
                    
                    if (task == null) {
                        continue; // No task, check running flag and loop
                    }
                    
                    processTask(task);
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log("⚠️ Analysis processor interrupted");
                    break;
                } catch (Exception e) {
                    log("❌ Analysis processor error: " + e.getMessage());
                }
            }
            
            log("🛑 Analysis queue processor stopped");
        });
    }
    
    /**
     * Process a single analysis task
     */
    private void processTask(AnalysisTask task) {
        String url = normalizeUrl(task.transaction.getUrl());
        long startTime = System.currentTimeMillis();
        
        try {
            log("═══════════════════════════════════════");
            log("🔍 PROCESSING [Queue: " + getQueueSize() + " remaining]");
            log("URL: " + url);
            log("Content-Type: " + task.transaction.getContentType());
            log("═══════════════════════════════════════");
            
            // Double-check not already analyzed (race condition safety)
            if (analyzedUrls.contains(url)) {
                log("⏭️ SKIP (analyzed while queued): " + url);
                return;
            }
            
            // Perform analysis
            List<TrafficFinding> findings = analyzer.analyzeTransaction(task.transaction);
            
            // Mark as analyzed
            analyzedUrls.add(url);
            
            long duration = System.currentTimeMillis() - startTime;
            
            log("═══════════════════════════════════════");
            log("✅ COMPLETED in " + duration + "ms");
            log("Findings: " + (findings != null ? findings.size() : 0));
            log("═══════════════════════════════════════");
            
            // Notify callback
            if (resultCallback != null && findings != null) {
                resultCallback.accept(new AnalysisResult(task.transaction, findings, duration));
            }
            
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log("❌ ERROR analyzing " + url + ": " + e.getMessage());
            
            if (resultCallback != null) {
                resultCallback.accept(new AnalysisResult(task.transaction, e.getMessage(), duration));
            }
        } finally {
            // Remove from pending
            pendingUrls.remove(url);
        }
    }
    
    /**
     * Check if a URL has already been analyzed
     */
    public boolean isAlreadyAnalyzed(String url) {
        return analyzedUrls.contains(normalizeUrl(url));
    }
    
    /**
     * Check if a URL is pending analysis
     */
    public boolean isPending(String url) {
        return pendingUrls.contains(normalizeUrl(url));
    }
    
    /**
     * Get current queue size
     */
    public int getQueueSize() {
        return analysisQueue.size();
    }
    
    /**
     * Get count of analyzed URLs
     */
    public int getAnalyzedCount() {
        return analyzedUrls.size();
    }
    
    /**
     * Clear analyzed URLs (for fresh start)
     */
    public void clearAnalyzedUrls() {
        analyzedUrls.clear();
        log("🗑️ Cleared analyzed URLs cache");
    }
    
    /**
     * Clear entire queue
     */
    public void clearQueue() {
        analysisQueue.clear();
        pendingUrls.clear();
        log("🗑️ Cleared analysis queue");
    }
    
    /**
     * Shutdown the queue manager
     */
    public void shutdown() {
        running = false;
        analysisExecutor.shutdown();
        try {
            if (!analysisExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                analysisExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            analysisExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        log("🛑 Analysis queue manager shutdown complete");
    }
    
    /**
     * Get queue status string
     */
    public String getStatus() {
        return String.format("Queue: %d pending | Analyzed: %d URLs", 
            getQueueSize(), getAnalyzedCount());
    }
    
    private void log(String message) {
        String logMessage = "[Traffic Monitor] " + message;
        System.out.println(logMessage);
        if (logCallback != null) {
            logCallback.accept(logMessage);
        }
    }
}
