package com.vista.security.service;

import com.vista.security.core.MCPConfigManager;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enhances AI prompts with context from Burp MCP server.
 * Detects when user queries mention Burp data and automatically fetches it.
 */
public class MCPContextEnhancer {
    private final MCPConfigManager mcpConfig;
    
    // Patterns to detect when user wants Burp data
    private static final Pattern HISTORY_PATTERN = Pattern.compile(
        "\\b(history|proxy history|http history|requests? in history)\\b", 
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SEARCH_PATTERN = Pattern.compile(
        "\\b(search|find|look for|check for).*\\b(in history|in proxy|in burp)\\b",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SCOPE_PATTERN = Pattern.compile(
        "\\b(scope|target scope|in scope)\\b",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SITEMAP_PATTERN = Pattern.compile(
        "\\b(site map|sitemap|discovered urls|endpoints)\\b",
        Pattern.CASE_INSENSITIVE
    );

    public MCPContextEnhancer(MCPConfigManager mcpConfig) {
        this.mcpConfig = mcpConfig;
    }

    /**
     * Enhance user prompt with MCP context if applicable.
     * Returns enhanced prompt with Burp data included.
     */
    public String enhancePrompt(String userPrompt) {
        if (mcpConfig == null || !mcpConfig.isEnabled()) {
            return userPrompt;
        }

        StringBuilder enhanced = new StringBuilder(userPrompt);
        boolean dataAdded = false;

        // Check if user wants proxy history
        if (HISTORY_PATTERN.matcher(userPrompt).find()) {
            List<Map<String, Object>> history = mcpConfig.queryProxyHistory(10);
            if (!history.isEmpty()) {
                enhanced.append("\n\n[BURP PROXY HISTORY - Last 10 requests]:\n");
                for (int i = 0; i < history.size(); i++) {
                    Map<String, Object> item = history.get(i);
                    enhanced.append(String.format("%d. %s %s - Status: %s\n",
                        i + 1,
                        item.getOrDefault("method", "?"),
                        item.getOrDefault("url", "?"),
                        item.getOrDefault("status", "?")));
                }
                dataAdded = true;
            }
        }

        // Check if user wants to search history
        Matcher searchMatcher = SEARCH_PATTERN.matcher(userPrompt);
        if (searchMatcher.find()) {
            // Try to extract search pattern
            String searchPattern = extractSearchPattern(userPrompt);
            if (searchPattern != null && !searchPattern.isEmpty()) {
                List<Map<String, Object>> results = mcpConfig.searchProxyHistory(searchPattern, 10);
                if (!results.isEmpty()) {
                    enhanced.append("\n\n[BURP PROXY HISTORY SEARCH - Pattern: \"")
                            .append(searchPattern).append("\"]:\n");
                    for (int i = 0; i < results.size(); i++) {
                        Map<String, Object> item = results.get(i);
                        enhanced.append(String.format("%d. %s %s - Status: %s\n",
                            i + 1,
                            item.getOrDefault("method", "?"),
                            item.getOrDefault("url", "?"),
                            item.getOrDefault("status", "?")));
                    }
                    dataAdded = true;
                }
            }
        }

        // Check if user wants scope
        if (SCOPE_PATTERN.matcher(userPrompt).find()) {
            List<String> scope = mcpConfig.getScope();
            if (!scope.isEmpty()) {
                enhanced.append("\n\n[BURP TARGET SCOPE]:\n");
                for (String target : scope) {
                    enhanced.append("• ").append(target).append("\n");
                }
                dataAdded = true;
            }
        }

        // Check if user wants site map
        if (SITEMAP_PATTERN.matcher(userPrompt).find()) {
            List<String> siteMap = mcpConfig.getSiteMap();
            if (!siteMap.isEmpty()) {
                enhanced.append("\n\n[BURP SITE MAP - Discovered URLs]:\n");
                int count = Math.min(siteMap.size(), 20); // Limit to 20 URLs
                for (int i = 0; i < count; i++) {
                    enhanced.append("• ").append(siteMap.get(i)).append("\n");
                }
                if (siteMap.size() > 20) {
                    enhanced.append("... and ").append(siteMap.size() - 20).append(" more URLs\n");
                }
                dataAdded = true;
            }
        }

        if (dataAdded) {
            enhanced.append("\n[Note: Above data was automatically fetched from Burp Suite via MCP integration]\n");
        }

        return enhanced.toString();
    }

    /**
     * Extract search pattern from user query.
     * Examples:
     * - "search for /api/login in history" -> "/api/login"
     * - "find requests with admin in proxy" -> "admin"
     */
    private String extractSearchPattern(String query) {
        // Try to find quoted strings first
        Pattern quotedPattern = Pattern.compile("['\"]([^'\"]+)['\"]");
        Matcher quotedMatcher = quotedPattern.matcher(query);
        if (quotedMatcher.find()) {
            return quotedMatcher.group(1);
        }

        // Try to find URL patterns
        Pattern urlPattern = Pattern.compile("(/[\\w/.-]+)");
        Matcher urlMatcher = urlPattern.matcher(query);
        if (urlMatcher.find()) {
            return urlMatcher.group(1);
        }

        // Try to find keywords after "for" or "with"
        Pattern keywordPattern = Pattern.compile("\\b(?:for|with)\\s+([\\w.-]+)");
        Matcher keywordMatcher = keywordPattern.matcher(query);
        if (keywordMatcher.find()) {
            return keywordMatcher.group(1);
        }

        return null;
    }

    /**
     * Check if prompt would benefit from MCP enhancement.
     */
    public boolean shouldEnhance(String userPrompt) {
        if (mcpConfig == null || !mcpConfig.isEnabled()) {
            return false;
        }

        return HISTORY_PATTERN.matcher(userPrompt).find() ||
               SEARCH_PATTERN.matcher(userPrompt).find() ||
               SCOPE_PATTERN.matcher(userPrompt).find() ||
               SITEMAP_PATTERN.matcher(userPrompt).find();
    }
}
