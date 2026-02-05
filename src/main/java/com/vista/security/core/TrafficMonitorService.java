package com.vista.security.core;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import com.vista.security.model.HttpTransaction;

import java.util.*;

/**
 * TrafficMonitorService automatically monitors HTTP traffic from Burp's proxy.
 * 
 * Features:
 * - Implements IHttpListener for real-time traffic capture
 * - Automatically captures ALL proxy traffic as it happens
 * - Adds to buffer for analysis
 * - Triggers AI analysis for intelligent findings
 * - Non-blocking background operation
 * 
 * This enables fully automated traffic monitoring and analysis without user intervention.
 */
public class TrafficMonitorService implements IHttpListener {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TrafficBufferManager bufferManager;
    private final TrafficCaptureListener captureListener;
    private volatile boolean running;
    private final Set<String> processedTransactionIds;
    
    /**
     * Creates a new TrafficMonitorService.
     * 
     * @param callbacks Burp callbacks for API access
     * @param bufferManager Buffer manager to store captured transactions
     * @param captureListener Capture listener to process transactions
     */
    public TrafficMonitorService(IBurpExtenderCallbacks callbacks,
                                  TrafficBufferManager bufferManager,
                                  TrafficCaptureListener captureListener) {
        this(callbacks, bufferManager, captureListener, 5);
    }
    
    /**
     * Creates a new TrafficMonitorService with custom polling interval.
     * 
     * @param callbacks Burp callbacks for API access
     * @param bufferManager Buffer manager to store captured transactions
     * @param captureListener Capture listener to process transactions
     * @param pollingIntervalSeconds Polling interval (not used with IHttpListener, kept for compatibility)
     */
    public TrafficMonitorService(IBurpExtenderCallbacks callbacks,
                                  TrafficBufferManager bufferManager,
                                  TrafficCaptureListener captureListener,
                                  int pollingIntervalSeconds) {
        if (callbacks == null) {
            throw new IllegalArgumentException("callbacks cannot be null");
        }
        if (bufferManager == null) {
            throw new IllegalArgumentException("bufferManager cannot be null");
        }
        if (captureListener == null) {
            throw new IllegalArgumentException("captureListener cannot be null");
        }
        
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.bufferManager = bufferManager;
        this.captureListener = captureListener;
        this.processedTransactionIds = Collections.synchronizedSet(new HashSet<>());
        this.running = false;
    }
    
    /**
     * Starts the automatic traffic monitoring service.
     * 
     * Registers as HTTP listener to capture traffic in real-time.
     */
    public void start() {
        if (running) {
            callbacks.printOutput("[Traffic Monitor] Service already running");
            return;
        }
        
        running = true;
        callbacks.printOutput("[Traffic Monitor] Starting automatic traffic monitoring...");
        callbacks.printOutput("[Traffic Monitor] Registering HTTP listener for real-time capture");
        
        // Register as HTTP listener to capture all proxy traffic
        callbacks.registerHttpListener(this);
    }
    
    /**
     * Stops the automatic traffic monitoring service.
     */
    public void stop() {
        if (!running) {
            return;
        }
        
        running = false;
        callbacks.printOutput("[Traffic Monitor] Stopping automatic traffic monitoring...");
        
        // Unregister HTTP listener
        callbacks.removeHttpListener(this);
        
        callbacks.printOutput("[Traffic Monitor] Service stopped");
    }
    
    /**
     * Checks if the service is currently running.
     * 
     * @return True if running, false otherwise
     */
    public boolean isRunning() {
        return running;
    }
    
    /**
     * Gets the number of transactions processed so far.
     * 
     * @return The count of processed transactions
     */
    public int getProcessedCount() {
        return processedTransactionIds.size();
    }
    
    /**
     * Clears the processed transaction tracking.
     */
    public void resetProcessedTracking() {
        processedTransactionIds.clear();
        callbacks.printOutput("[Traffic Monitor] Reset processed transaction tracking");
    }
    
    /**
     * IHttpListener implementation - called by Burp for every HTTP request/response.
     * 
     * @param toolFlag The Burp tool that processed the request
     * @param messageIsRequest True if this is a request, false if response
     * @param messageInfo The HTTP message
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process responses (we need both request and response)
        if (messageIsRequest) {
            return;
        }
        
        // Only capture if monitoring is active
        if (!running) {
            return;
        }
        
        // Only capture proxy traffic (tool flag 4 = Proxy)
        // You can add other tools if needed: 8 = Repeater, 16 = Scanner, etc.
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }
        
        try {
            // Generate unique ID to avoid duplicates
            String transactionId = generateTransactionId(messageInfo);
            
            // Skip if already processed
            if (processedTransactionIds.contains(transactionId)) {
                return;
            }
            
            // Capture the transaction
            captureListener.captureMessage(messageInfo);
            
            // Mark as processed
            processedTransactionIds.add(transactionId);
            
        } catch (Exception e) {
            callbacks.printError("[Traffic Monitor] Error processing HTTP message: " + e.getMessage());
        }
    }
    
    /**
     * Generates a unique ID for a transaction to track if it's been processed.
     * 
     * @param transaction The transaction
     * @return A unique identifier string
     */
    private String generateTransactionId(IHttpRequestResponse transaction) {
        try {
            byte[] request = transaction.getRequest();
            byte[] response = transaction.getResponse();
            
            if (request == null || response == null) {
                return UUID.randomUUID().toString();
            }
            
            // Create ID from request/response hash
            int hash = Arrays.hashCode(request) ^ Arrays.hashCode(response);
            return String.valueOf(hash);
            
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }
}
