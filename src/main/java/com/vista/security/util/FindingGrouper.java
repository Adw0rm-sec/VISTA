package com.vista.security.util;

import com.vista.security.model.TrafficFinding;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility for grouping traffic findings hierarchically.
 * Groups by: Type -> URL -> Parameter
 */
public class FindingGrouper {
    
    /**
     * Group findings by type (vulnerability category).
     */
    public static Map<String, List<TrafficFinding>> groupByType(List<TrafficFinding> findings) {
        return findings.stream()
            .collect(Collectors.groupingBy(
                TrafficFinding::getType,
                LinkedHashMap::new,
                Collectors.toList()
            ));
    }
    
    /**
     * Group findings by URL within a type group.
     */
    public static Map<String, List<TrafficFinding>> groupByUrl(List<TrafficFinding> findings) {
        return findings.stream()
            .collect(Collectors.groupingBy(
                f -> f.getSourceTransaction().getUrl(),
                LinkedHashMap::new,
                Collectors.toList()
            ));
    }
    
    /**
     * Group findings by parameter within a URL group.
     */
    public static Map<String, List<TrafficFinding>> groupByParameter(List<TrafficFinding> findings) {
        return findings.stream()
            .collect(Collectors.groupingBy(
                f -> {
                    String param = f.getAffectedParameter();
                    // If parameter is null or empty, use finding type as grouping key
                    if (param == null || param.trim().isEmpty()) {
                        return f.getType();
                    }
                    return param;
                },
                LinkedHashMap::new,
                Collectors.toList()
            ));
    }
    
    /**
     * Create hierarchical structure: Type -> URL -> Parameter -> Findings
     */
    public static Map<String, Map<String, Map<String, List<TrafficFinding>>>> createHierarchy(
            List<TrafficFinding> findings) {
        
        Map<String, Map<String, Map<String, List<TrafficFinding>>>> hierarchy = new LinkedHashMap<>();
        
        // Group by type first
        Map<String, List<TrafficFinding>> byType = groupByType(findings);
        
        // For each type, group by URL
        for (Map.Entry<String, List<TrafficFinding>> typeEntry : byType.entrySet()) {
            String type = typeEntry.getKey();
            List<TrafficFinding> typeFindings = typeEntry.getValue();
            
            Map<String, Map<String, List<TrafficFinding>>> urlMap = new LinkedHashMap<>();
            Map<String, List<TrafficFinding>> byUrl = groupByUrl(typeFindings);
            
            // For each URL, group by parameter
            for (Map.Entry<String, List<TrafficFinding>> urlEntry : byUrl.entrySet()) {
                String url = urlEntry.getKey();
                List<TrafficFinding> urlFindings = urlEntry.getValue();
                
                Map<String, List<TrafficFinding>> paramMap = groupByParameter(urlFindings);
                urlMap.put(url, paramMap);
            }
            
            hierarchy.put(type, urlMap);
        }
        
        return hierarchy;
    }
    
    /**
     * Get count of findings by severity.
     */
    public static Map<String, Integer> countBySeverity(List<TrafficFinding> findings) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("CRITICAL", 0);
        counts.put("HIGH", 0);
        counts.put("MEDIUM", 0);
        counts.put("LOW", 0);
        counts.put("INFO", 0);
        
        for (TrafficFinding finding : findings) {
            String severity = finding.getSeverity().toUpperCase();
            counts.put(severity, counts.getOrDefault(severity, 0) + 1);
        }
        
        return counts;
    }
    
    /**
     * Sort findings by severity (highest first).
     */
    public static List<TrafficFinding> sortBySeverity(List<TrafficFinding> findings) {
        List<TrafficFinding> sorted = new ArrayList<>(findings);
        sorted.sort((f1, f2) -> Integer.compare(f2.getSeverityValue(), f1.getSeverityValue()));
        return sorted;
    }
    
    /**
     * Get unique URLs from findings.
     */
    public static Set<String> getUniqueUrls(List<TrafficFinding> findings) {
        return findings.stream()
            .map(f -> f.getSourceTransaction().getUrl())
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }
    
    /**
     * Get unique types from findings.
     */
    public static Set<String> getUniqueTypes(List<TrafficFinding> findings) {
        return findings.stream()
            .map(TrafficFinding::getType)
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }
    
    /**
     * Filter findings by severity.
     */
    public static List<TrafficFinding> filterBySeverity(List<TrafficFinding> findings, String... severities) {
        Set<String> severitySet = Arrays.stream(severities)
            .map(String::toUpperCase)
            .collect(Collectors.toSet());
        
        return findings.stream()
            .filter(f -> severitySet.contains(f.getSeverity().toUpperCase()))
            .collect(Collectors.toList());
    }
    
    /**
     * Filter findings by type.
     */
    public static List<TrafficFinding> filterByType(List<TrafficFinding> findings, String... types) {
        Set<String> typeSet = Arrays.stream(types)
            .map(String::toUpperCase)
            .collect(Collectors.toSet());
        
        return findings.stream()
            .filter(f -> typeSet.contains(f.getType().toUpperCase()))
            .collect(Collectors.toList());
    }
}
