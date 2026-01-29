package com.vista.security.core;

import com.vista.security.model.Payload;
import com.vista.security.model.PayloadLibrary;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Integrates Payload Library with AI suggestions.
 * Provides context-aware payload recommendations to AI based on:
 * - Request analysis (detected vulnerability types)
 * - Reflection context (where input appears in response)
 * - Success rates (which payloads work best)
 * - Testing history (what has been tried)
 */
public class PayloadLibraryAIIntegration {
    
    private final PayloadLibraryManager libraryManager;
    
    public PayloadLibraryAIIntegration() {
        this.libraryManager = PayloadLibraryManager.getInstance();
        
        // Ensure manager is initialized
        if (!libraryManager.isInitialized()) {
            libraryManager.initialize();
        }
    }
    
    /**
     * Get AI-ready payload context based on detected vulnerability and reflection analysis.
     * This enriches the AI prompt with relevant, proven payloads.
     * 
     * @param detectedVulnType Detected vulnerability type (e.g., "XSS", "SQLi", "SSTI")
     * @param reflectionContext Where input reflects (e.g., "html-body", "html-attribute", "javascript")
     * @param includeSuccessful Whether to prioritize payloads with high success rates
     * @param limit Maximum number of payloads to include
     * @return Formatted string for AI prompt
     */
    public String getPayloadContextForAI(String detectedVulnType, String reflectionContext, 
                                         boolean includeSuccessful, int limit) {
        
        List<Payload> relevantPayloads = findRelevantPayloads(detectedVulnType, reflectionContext, includeSuccessful, limit);
        
        if (relevantPayloads.isEmpty()) {
            return ""; // No relevant payloads found
        }
        
        StringBuilder context = new StringBuilder();
        context.append("\n\n📚 RELEVANT PAYLOADS FROM LIBRARY:\n");
        context.append("(These are proven payloads from our library - consider using or adapting them)\n\n");
        
        for (int i = 0; i < relevantPayloads.size(); i++) {
            Payload payload = relevantPayloads.get(i);
            context.append(String.format("%d. %s\n", i + 1, payload.getValue()));
            context.append(String.format("   Context: %s | Encoding: %s\n", 
                payload.getContext(), payload.getEncoding()));
            
            if (payload.hasBeenUsed()) {
                context.append(String.format("   ✓ Success Rate: %s (proven effective!)\n", 
                    payload.getSuccessRateDisplay()));
            }
            
            if (!payload.getDescription().isEmpty()) {
                context.append(String.format("   Description: %s\n", payload.getDescription()));
            }
            
            context.append("\n");
        }
        
        context.append("💡 INSTRUCTIONS FOR AI:\n");
        context.append("- Prioritize payloads with high success rates\n");
        context.append("- Adapt payloads to match the specific context\n");
        context.append("- Explain WHY each payload might work\n");
        context.append("- Suggest variations based on WAF detection\n");
        context.append("- Reference payload numbers when making recommendations\n");
        
        return context.toString();
    }
    
    /**
     * Get top performing payloads for a category.
     * Used when AI needs to suggest the most effective payloads.
     */
    public String getTopPayloadsForAI(String category, int limit) {
        List<Payload> topPayloads = libraryManager.getPayloadsByCategory(category).stream()
            .filter(Payload::hasBeenUsed)
            .sorted((p1, p2) -> Double.compare(p2.getSuccessRate(), p1.getSuccessRate()))
            .limit(limit)
            .collect(Collectors.toList());
        
        if (topPayloads.isEmpty()) {
            return "";
        }
        
        StringBuilder context = new StringBuilder();
        context.append(String.format("\n\n🏆 TOP %d PERFORMING %s PAYLOADS:\n", limit, category));
        context.append("(These have the highest success rates in real testing)\n\n");
        
        for (int i = 0; i < topPayloads.size(); i++) {
            Payload payload = topPayloads.get(i);
            context.append(String.format("%d. %s\n", i + 1, payload.getValue()));
            context.append(String.format("   Success Rate: %s\n", payload.getSuccessRateDisplay()));
            context.append(String.format("   Context: %s | Tags: %s\n", 
                payload.getContext(), String.join(", ", payload.getTags())));
            context.append("\n");
        }
        
        return context.toString();
    }
    
    /**
     * Get payload suggestions based on WAF detection.
     * Returns bypass-focused payloads when WAF is detected.
     */
    public String getWAFBypassPayloadsForAI(String vulnType, String wafType) {
        List<Payload> bypassPayloads = libraryManager.getPayloadsByCategory(vulnType).stream()
            .filter(p -> p.getTags().contains("waf-bypass") || p.getTags().contains("bypass"))
            .limit(10)
            .collect(Collectors.toList());
        
        if (bypassPayloads.isEmpty()) {
            return "";
        }
        
        StringBuilder context = new StringBuilder();
        context.append(String.format("\n\n🛡️ WAF BYPASS PAYLOADS FOR %s:\n", vulnType));
        if (wafType != null && !wafType.isEmpty()) {
            context.append(String.format("(Detected WAF: %s)\n\n", wafType));
        } else {
            context.append("(Generic WAF bypass techniques)\n\n");
        }
        
        for (int i = 0; i < bypassPayloads.size(); i++) {
            Payload payload = bypassPayloads.get(i);
            context.append(String.format("%d. %s\n", i + 1, payload.getValue()));
            context.append(String.format("   Technique: %s\n", payload.getDescription()));
            
            if (payload.hasBeenUsed()) {
                context.append(String.format("   Success Rate: %s\n", payload.getSuccessRateDisplay()));
            }
            
            context.append("\n");
        }
        
        return context.toString();
    }
    
    /**
     * Get context-specific payloads (e.g., for JavaScript context, HTML attribute, etc.)
     */
    public String getContextSpecificPayloadsForAI(String vulnType, String context, int limit) {
        List<Payload> contextPayloads = libraryManager.getPayloadsByCategory(vulnType).stream()
            .filter(p -> p.getContext().equals(context) || p.getContext().equals("any"))
            .limit(limit)
            .collect(Collectors.toList());
        
        if (contextPayloads.isEmpty()) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        result.append(String.format("\n\n🎯 CONTEXT-SPECIFIC PAYLOADS (%s in %s):\n\n", vulnType, context));
        
        for (int i = 0; i < contextPayloads.size(); i++) {
            Payload payload = contextPayloads.get(i);
            result.append(String.format("%d. %s\n", i + 1, payload.getValue()));
            result.append(String.format("   %s\n", payload.getDescription()));
            
            if (payload.hasBeenUsed()) {
                result.append(String.format("   Success Rate: %s\n", payload.getSuccessRateDisplay()));
            }
            
            result.append("\n");
        }
        
        return result.toString();
    }
    
    /**
     * Get recently successful payloads.
     * Shows what's working right now in current testing session.
     */
    public String getRecentSuccessfulPayloadsForAI(int limit) {
        List<Payload> recentPayloads = libraryManager.getRecentPayloads(limit).stream()
            .filter(p -> p.getSuccessRate() > 50.0) // Only successful ones
            .collect(Collectors.toList());
        
        if (recentPayloads.isEmpty()) {
            return "";
        }
        
        StringBuilder context = new StringBuilder();
        context.append("\n\n⚡ RECENTLY SUCCESSFUL PAYLOADS:\n");
        context.append("(These worked in recent testing - high probability of success)\n\n");
        
        for (int i = 0; i < recentPayloads.size(); i++) {
            Payload payload = recentPayloads.get(i);
            context.append(String.format("%d. %s\n", i + 1, payload.getValue()));
            context.append(String.format("   Success Rate: %s | Last Used: %s\n", 
                payload.getSuccessRateDisplay(),
                formatTimestamp(payload.getLastUsed())));
            context.append("\n");
        }
        
        return context.toString();
    }
    
    /**
     * Find relevant payloads based on vulnerability type and context.
     */
    private List<Payload> findRelevantPayloads(String vulnType, String context, 
                                               boolean prioritizeSuccessful, int limit) {
        List<Payload> payloads;
        
        // Get payloads by category
        if (vulnType != null && !vulnType.isEmpty()) {
            payloads = libraryManager.getPayloadsByCategory(vulnType);
        } else {
            payloads = libraryManager.getAllPayloads();
        }
        
        // Filter by context if specified
        if (context != null && !context.isEmpty() && !context.equals("unknown")) {
            String finalContext = context;
            payloads = payloads.stream()
                .filter(p -> p.getContext().equals(finalContext) || p.getContext().equals("any"))
                .collect(Collectors.toList());
        }
        
        // Sort by success rate if requested
        if (prioritizeSuccessful) {
            payloads = payloads.stream()
                .sorted((p1, p2) -> {
                    // Prioritize used payloads with high success rates
                    if (p1.hasBeenUsed() && !p2.hasBeenUsed()) return -1;
                    if (!p1.hasBeenUsed() && p2.hasBeenUsed()) return 1;
                    return Double.compare(p2.getSuccessRate(), p1.getSuccessRate());
                })
                .collect(Collectors.toList());
        }
        
        // Limit results
        return payloads.stream().limit(limit).collect(Collectors.toList());
    }
    
    /**
     * Format timestamp for display.
     */
    private String formatTimestamp(long timestamp) {
        if (timestamp == 0) return "Never";
        
        long diff = System.currentTimeMillis() - timestamp;
        long minutes = diff / (1000 * 60);
        long hours = minutes / 60;
        long days = hours / 24;
        
        if (days > 0) return days + " days ago";
        if (hours > 0) return hours + " hours ago";
        if (minutes > 0) return minutes + " minutes ago";
        return "Just now";
    }
    
    /**
     * Get statistics summary for AI context.
     */
    public String getLibraryStatsForAI() {
        return String.format("\n\n📊 PAYLOAD LIBRARY STATS:\n" +
            "Total Payloads: %d | Categories: %d | Tested: %d\n" +
            "This library contains proven payloads with tracked success rates.\n",
            libraryManager.getTotalPayloadCount(),
            libraryManager.getCategories().size(),
            (int) libraryManager.getAllPayloads().stream().filter(Payload::hasBeenUsed).count());
    }
}
