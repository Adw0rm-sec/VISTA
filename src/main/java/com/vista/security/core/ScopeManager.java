package com.vista.security.core;

import com.vista.security.model.ScopeRule;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages scope rules for filtering HTTP traffic.
 * Supports wildcard patterns and multiple domains.
 */
public class ScopeManager {
    private final List<ScopeRule> rules;
    private boolean scopeEnabled;
    
    public ScopeManager() {
        this.rules = new CopyOnWriteArrayList<>();
        this.scopeEnabled = false;
    }
    
    /**
     * Adds a scope rule.
     * 
     * @param pattern Domain pattern (e.g., "example.com" or "*.example.com")
     */
    public void addScope(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return;
        }
        
        pattern = pattern.trim();
        
        // Check if already exists
        for (ScopeRule rule : rules) {
            if (rule.getPattern().equals(pattern)) {
                return; // Already exists
            }
        }
        
        rules.add(new ScopeRule(pattern));
    }
    
    /**
     * Removes a scope rule.
     * 
     * @param pattern Domain pattern to remove
     */
    public void removeScope(String pattern) {
        rules.removeIf(rule -> rule.getPattern().equals(pattern));
    }
    
    /**
     * Checks if a URL is in scope.
     * 
     * @param url The URL to check
     * @return True if in scope or scope is disabled, false otherwise
     */
    public boolean isInScope(String url) {
        if (!scopeEnabled || rules.isEmpty()) {
            return true; // No scope filtering
        }
        
        for (ScopeRule rule : rules) {
            if (rule.matches(url)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Gets all scope patterns.
     * 
     * @return List of scope patterns
     */
    public List<String> getScopes() {
        List<String> patterns = new ArrayList<>();
        for (ScopeRule rule : rules) {
            patterns.add(rule.getPattern());
        }
        return patterns;
    }
    
    /**
     * Clears all scope rules.
     */
    public void clearScopes() {
        rules.clear();
    }
    
    /**
     * Enables or disables scope filtering.
     * 
     * @param enabled True to enable, false to disable
     */
    public void setScopeEnabled(boolean enabled) {
        this.scopeEnabled = enabled;
    }
    
    /**
     * Checks if scope filtering is enabled.
     * 
     * @return True if enabled, false otherwise
     */
    public boolean isScopeEnabled() {
        return scopeEnabled;
    }
    
    /**
     * Gets the number of scope rules.
     * 
     * @return Number of rules
     */
    public int size() {
        return rules.size();
    }
}
