package com.vista.security.core;

import burp.IHttpRequestResponse;
import com.vista.security.model.RequestCollection;
import com.vista.security.model.CollectionItem;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Manages request collections - organizing and analyzing similar requests together.
 * Provides CRUD operations, bulk import, pattern detection, and AI integration.
 */
public class RequestCollectionManager {
    
    private static RequestCollectionManager instance;
    private final String collectionsDir;
    
    private Map<String, RequestCollection> collections;
    private boolean initialized;
    
    private RequestCollectionManager() {
        String homeDir = System.getProperty("user.home");
        this.collectionsDir = homeDir + File.separator + ".vista" + File.separator + "collections";
        this.collections = new LinkedHashMap<>();
        this.initialized = false;
    }
    
    public static synchronized RequestCollectionManager getInstance() {
        if (instance == null) {
            instance = new RequestCollectionManager();
        }
        return instance;
    }
    
    /**
     * Initialize the manager - create directories and load collections.
     */
    public void initialize() {
        if (initialized) return;
        
        try {
            // Create directory
            Files.createDirectories(Paths.get(collectionsDir));
            
            // Load existing collections
            loadCollections();
            
            initialized = true;
        } catch (Exception e) {
            System.err.println("Failed to initialize RequestCollectionManager: " + e.getMessage());
        }
    }
    
    /**
     * Load all collections from disk.
     */
    private void loadCollections() {
        File dir = new File(collectionsDir);
        if (!dir.exists()) return;
        
        File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
        if (files == null) return;
        
        for (File file : files) {
            try {
                String json = new String(Files.readAllBytes(file.toPath()));
                RequestCollection collection = RequestCollection.fromJson(json);
                collections.put(collection.getId(), collection);
            } catch (Exception e) {
                System.err.println("Failed to load collection: " + file.getName());
            }
        }
    }
    
    // ========== Collection Management ==========
    
    /**
     * Get all collections.
     */
    public List<RequestCollection> getAllCollections() {
        return new ArrayList<>(collections.values());
    }
    
    /**
     * Get collection by ID.
     */
    public RequestCollection getCollection(String id) {
        return collections.get(id);
    }
    
    /**
     * Create a new collection.
     */
    public RequestCollection createCollection(String name, String description) {
        RequestCollection collection = new RequestCollection(name, description);
        collections.put(collection.getId(), collection);
        saveCollection(collection);
        return collection;
    }
    
    /**
     * Save a collection to disk.
     */
    public void saveCollection(RequestCollection collection) {
        collections.put(collection.getId(), collection);
        
        try {
            String filename = sanitizeFilename(collection.getName()) + "_" + collection.getId().substring(0, 8) + ".json";
            String filepath = collectionsDir + File.separator + filename;
            Files.write(Paths.get(filepath), collection.toJson().getBytes());
        } catch (Exception e) {
            System.err.println("Failed to save collection: " + e.getMessage());
        }
    }
    
    /**
     * Delete a collection.
     */
    public void deleteCollection(String id) {
        RequestCollection collection = collections.remove(id);
        if (collection == null) return;
        
        try {
            String filename = sanitizeFilename(collection.getName()) + "_" + collection.getId().substring(0, 8) + ".json";
            String filepath = collectionsDir + File.separator + filename;
            Files.deleteIfExists(Paths.get(filepath));
        } catch (Exception e) {
            System.err.println("Failed to delete collection: " + e.getMessage());
        }
    }
    
    // ========== Item Management ==========
    
    /**
     * Add an item to a collection.
     */
    public void addItem(String collectionId, IHttpRequestResponse requestResponse) {
        RequestCollection collection = collections.get(collectionId);
        if (collection == null) return;
        
        CollectionItem item = new CollectionItem(requestResponse);
        collection.addItem(item);
        saveCollection(collection);
    }
    
    /**
     * Add multiple items to a collection.
     */
    public void addItems(String collectionId, List<IHttpRequestResponse> requestResponses) {
        RequestCollection collection = collections.get(collectionId);
        if (collection == null) return;
        
        for (IHttpRequestResponse rr : requestResponses) {
            CollectionItem item = new CollectionItem(rr);
            collection.addItem(item);
        }
        saveCollection(collection);
    }
    
    /**
     * Remove an item from a collection.
     */
    public void removeItem(String collectionId, String itemId) {
        RequestCollection collection = collections.get(collectionId);
        if (collection == null) return;
        
        collection.removeItem(itemId);
        saveCollection(collection);
    }
    
    /**
     * Update item metadata.
     */
    public void updateItem(String collectionId, String itemId, String notes, boolean tested, boolean success) {
        RequestCollection collection = collections.get(collectionId);
        if (collection == null) return;
        
        CollectionItem item = collection.getItem(itemId);
        if (item == null) return;
        
        item.setNotes(notes);
        item.setTested(tested);
        item.setSuccess(success);
        saveCollection(collection);
    }
    
    // ========== Pattern Detection ==========
    
    /**
     * Detect similar requests based on URL patterns.
     * Returns collections that might be relevant for this request.
     */
    public List<RequestCollection> detectSimilarRequests(IHttpRequestResponse requestResponse) {
        List<RequestCollection> similar = new ArrayList<>();
        
        String url = extractUrl(requestResponse);
        String host = extractHost(requestResponse);
        
        for (RequestCollection collection : collections.values()) {
            // Check if any items in collection match this request
            for (CollectionItem item : collection.getItems()) {
                if (isSimilar(url, host, item.getUrl(), item.getHost())) {
                    similar.add(collection);
                    break;
                }
            }
        }
        
        return similar;
    }
    
    /**
     * Check if two requests are similar based on URL pattern.
     */
    private boolean isSimilar(String url1, String host1, String url2, String host2) {
        // Same host
        if (host1 != null && host1.equals(host2)) {
            // Same base path
            String path1 = getBasePath(url1);
            String path2 = getBasePath(url2);
            return path1.equals(path2);
        }
        return false;
    }
    
    /**
     * Get base path from URL (e.g., /api/user/123 -> /api/user).
     */
    private String getBasePath(String url) {
        if (url == null) return "";
        
        // Remove query string
        int queryIndex = url.indexOf('?');
        if (queryIndex > 0) {
            url = url.substring(0, queryIndex);
        }
        
        // Remove last segment if it looks like an ID
        String[] parts = url.split("/");
        if (parts.length > 1) {
            String lastPart = parts[parts.length - 1];
            if (lastPart.matches("\\d+") || lastPart.matches("[a-f0-9-]{32,}")) {
                // Looks like an ID, remove it
                return url.substring(0, url.lastIndexOf('/'));
            }
        }
        
        return url;
    }
    
    /**
     * Suggest a collection name based on request patterns.
     */
    public String suggestCollectionName(List<IHttpRequestResponse> requests) {
        if (requests.isEmpty()) return "New Collection";
        
        // Find common path prefix
        List<String> urls = requests.stream()
            .map(this::extractUrl)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
        
        if (urls.isEmpty()) return "New Collection";
        
        String commonPrefix = findCommonPrefix(urls);
        if (commonPrefix.isEmpty()) {
            // Use host name
            String host = extractHost(requests.get(0));
            return host != null ? host + " Requests" : "New Collection";
        }
        
        // Clean up the prefix
        commonPrefix = commonPrefix.replaceAll("^/+", "").replaceAll("/+$", "");
        if (commonPrefix.isEmpty()) return "Root Requests";
        
        // Capitalize and format
        String[] parts = commonPrefix.split("/");
        String name = parts[parts.length - 1];
        name = name.substring(0, 1).toUpperCase() + name.substring(1);
        
        return name + " Endpoints";
    }
    
    /**
     * Find common prefix among URLs.
     */
    private String findCommonPrefix(List<String> urls) {
        if (urls.isEmpty()) return "";
        
        String prefix = urls.get(0);
        for (int i = 1; i < urls.size(); i++) {
            while (!urls.get(i).startsWith(prefix)) {
                prefix = prefix.substring(0, prefix.length() - 1);
                if (prefix.isEmpty()) return "";
            }
        }
        
        // Trim to last slash
        int lastSlash = prefix.lastIndexOf('/');
        if (lastSlash > 0) {
            prefix = prefix.substring(0, lastSlash);
        }
        
        return prefix;
    }
    
    // ========== Export/Import ==========
    
    /**
     * Export collection to file.
     */
    public void exportCollection(String id, File destination) throws IOException {
        RequestCollection collection = collections.get(id);
        if (collection == null) {
            throw new IllegalArgumentException("Collection not found: " + id);
        }
        
        Files.write(destination.toPath(), collection.toJson().getBytes());
    }
    
    /**
     * Import collection from file.
     */
    public RequestCollection importCollection(File file) throws IOException {
        String json = new String(Files.readAllBytes(file.toPath()));
        RequestCollection collection = RequestCollection.fromJson(json);
        
        // Generate new ID to avoid conflicts
        String oldId = collection.getId();
        java.lang.reflect.Field idField = null;
        try {
            idField = RequestCollection.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(collection, UUID.randomUUID().toString());
        } catch (Exception e) {
            // Keep original ID if reflection fails
        }
        
        collections.put(collection.getId(), collection);
        saveCollection(collection);
        return collection;
    }
    
    // ========== Statistics ==========
    
    /**
     * Get total number of collections.
     */
    public int getTotalCollectionCount() {
        return collections.size();
    }
    
    /**
     * Get total number of requests across all collections.
     */
    public int getTotalRequestCount() {
        return collections.values().stream()
            .mapToInt(RequestCollection::getItemCount)
            .sum();
    }
    
    /**
     * Get statistics summary.
     */
    public String getStatsSummary() {
        int totalCollections = getTotalCollectionCount();
        int totalRequests = getTotalRequestCount();
        int testedRequests = collections.values().stream()
            .mapToInt(RequestCollection::getTestedCount)
            .sum();
        
        return String.format("Collections: %d | Requests: %d | Tested: %d",
            totalCollections, totalRequests, testedRequests);
    }
    
    // ========== Helper Methods ==========
    
    /**
     * Extract URL from request.
     */
    private String extractUrl(IHttpRequestResponse requestResponse) {
        try {
            byte[] request = requestResponse.getRequest();
            if (request == null) return null;
            
            String requestStr = new String(request);
            String[] lines = requestStr.split("\n");
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length >= 2) {
                    return parts[1];
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    /**
     * Extract host from request.
     */
    private String extractHost(IHttpRequestResponse requestResponse) {
        try {
            if (requestResponse.getHttpService() != null) {
                return requestResponse.getHttpService().getHost();
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
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
