package com.vista.security.core;

import com.vista.security.model.ContentTypeCategory;
import com.vista.security.model.HttpTransaction;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * TrafficFilterEngine applies filters to HTTP transactions.
 * 
 * Supports:
 * - Content-type filtering by category (JavaScript, XML, JSON, CSS, Images, Fonts)
 * - HTTP method filtering (GET, POST, PUT, DELETE, PATCH, OPTIONS)
 * - Custom regex pattern filtering
 * 
 * Filter Logic:
 * - If no filters enabled: show all transactions
 * - If filters enabled: show transactions matching ANY enabled filter (OR logic)
 * - Custom pattern applied in addition to category filters
 * 
 * Thread-safe for concurrent read access.
 */
public class TrafficFilterEngine {
    
    private final Set<ContentTypeCategory> enabledContentTypes;
    private final Set<String> enabledMethods;
    private Pattern customPattern;
    
    /**
     * Creates a new TrafficFilterEngine with no filters enabled.
     */
    public TrafficFilterEngine() {
        this.enabledContentTypes = new HashSet<>();
        this.enabledMethods = new HashSet<>();
        this.customPattern = null;
    }
    
    /**
     * Enables or disables a content-type category filter.
     * 
     * @param category The content-type category to filter
     * @param enabled True to enable, false to disable
     */
    public synchronized void setContentTypeFilter(ContentTypeCategory category, boolean enabled) {
        if (category == null) {
            return;
        }
        
        if (enabled) {
            enabledContentTypes.add(category);
        } else {
            enabledContentTypes.remove(category);
        }
    }
    
    /**
     * Enables or disables an HTTP method filter.
     * 
     * @param method The HTTP method to filter (e.g., "GET", "POST")
     * @param enabled True to enable, false to disable
     */
    public synchronized void setMethodFilter(String method, boolean enabled) {
        if (method == null || method.trim().isEmpty()) {
            return;
        }
        
        String normalizedMethod = method.trim().toUpperCase();
        
        if (enabled) {
            enabledMethods.add(normalizedMethod);
        } else {
            enabledMethods.remove(normalizedMethod);
        }
    }
    
    /**
     * Sets a custom regex pattern for filtering.
     * 
     * @param regex The regex pattern to match against URLs
     * @throws PatternSyntaxException If the regex is invalid
     */
    public synchronized void setCustomPattern(String regex) throws PatternSyntaxException {
        if (regex == null || regex.trim().isEmpty()) {
            this.customPattern = null;
        } else {
            this.customPattern = Pattern.compile(regex);
        }
    }
    
    /**
     * Clears all filters.
     */
    public synchronized void clearFilters() {
        enabledContentTypes.clear();
        enabledMethods.clear();
        customPattern = null;
    }
    
    /**
     * Filters a list of transactions based on enabled filters.
     * 
     * @param transactions The transactions to filter
     * @return A new list containing only matching transactions
     */
    public synchronized List<HttpTransaction> filter(List<HttpTransaction> transactions) {
        if (transactions == null) {
            return new ArrayList<>();
        }
        
        // If no filters enabled, return all transactions
        if (!hasFiltersEnabled()) {
            return new ArrayList<>(transactions);
        }
        
        List<HttpTransaction> filtered = new ArrayList<>();
        for (HttpTransaction transaction : transactions) {
            if (matches(transaction)) {
                filtered.add(transaction);
            }
        }
        
        return filtered;
    }
    
    /**
     * Checks if a single transaction matches the enabled filters.
     * 
     * @param transaction The transaction to check
     * @return True if the transaction matches any enabled filter
     */
    public synchronized boolean matches(HttpTransaction transaction) {
        if (transaction == null) {
            return false;
        }
        
        // If no filters enabled, match all
        if (!hasFiltersEnabled()) {
            return true;
        }
        
        // OR logic: match if ANY filter matches
        return matchesContentType(transaction) 
            || matchesMethod(transaction) 
            || matchesCustomPattern(transaction);
    }
    
    /**
     * Checks if any filters are currently enabled.
     * 
     * @return True if at least one filter is enabled
     */
    private boolean hasFiltersEnabled() {
        return !enabledContentTypes.isEmpty() 
            || !enabledMethods.isEmpty() 
            || customPattern != null;
    }
    
    /**
     * Checks if a transaction matches the content-type filters.
     * 
     * @param transaction The transaction to check
     * @return True if content-type filter is enabled and matches
     */
    private boolean matchesContentType(HttpTransaction transaction) {
        if (enabledContentTypes.isEmpty()) {
            return false;
        }
        
        String contentType = transaction.getContentType();
        String url = transaction.getUrl();
        
        for (ContentTypeCategory category : enabledContentTypes) {
            if (category.matches(contentType, url)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if a transaction matches the HTTP method filters.
     * 
     * @param transaction The transaction to check
     * @return True if method filter is enabled and matches
     */
    private boolean matchesMethod(HttpTransaction transaction) {
        if (enabledMethods.isEmpty()) {
            return false;
        }
        
        String method = transaction.getMethod();
        if (method == null) {
            return false;
        }
        
        return enabledMethods.contains(method.toUpperCase());
    }
    
    /**
     * Checks if a transaction matches the custom regex pattern.
     * 
     * @param transaction The transaction to check
     * @return True if custom pattern is set and matches the URL
     */
    private boolean matchesCustomPattern(HttpTransaction transaction) {
        if (customPattern == null) {
            return false;
        }
        
        String url = transaction.getUrl();
        if (url == null) {
            return false;
        }
        
        return customPattern.matcher(url).find();
    }
    
    /**
     * Gets the currently enabled content-type categories.
     * 
     * @return A copy of the enabled content-type categories
     */
    public synchronized Set<ContentTypeCategory> getEnabledContentTypes() {
        return new HashSet<>(enabledContentTypes);
    }
    
    /**
     * Gets the currently enabled HTTP methods.
     * 
     * @return A copy of the enabled HTTP methods
     */
    public synchronized Set<String> getEnabledMethods() {
        return new HashSet<>(enabledMethods);
    }
    
    /**
     * Gets the current custom pattern.
     * 
     * @return The custom pattern, or null if not set
     */
    public synchronized Pattern getCustomPattern() {
        return customPattern;
    }
}
