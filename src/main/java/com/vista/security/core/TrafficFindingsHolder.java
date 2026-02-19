package com.vista.security.core;

import com.vista.security.model.TrafficFinding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe holder for TrafficFinding objects.
 * Provides a centralized place for the persistence manager to save/load
 * traffic findings that are discovered by the analysis engine.
 */
public class TrafficFindingsHolder {
    
    private static TrafficFindingsHolder instance;
    
    private final List<TrafficFinding> findings = new CopyOnWriteArrayList<>();
    
    private TrafficFindingsHolder() {}
    
    public static synchronized TrafficFindingsHolder getInstance() {
        if (instance == null) {
            instance = new TrafficFindingsHolder();
        }
        return instance;
    }
    
    /**
     * Adds a finding to the holder and marks data as dirty for auto-save.
     */
    public void addFinding(TrafficFinding finding) {
        if (finding != null && !findings.contains(finding)) {
            findings.add(finding);
            VistaPersistenceManager.getInstance().markDirty();
        }
    }
    
    /**
     * Gets all findings (unmodifiable).
     */
    public List<TrafficFinding> getFindings() {
        return Collections.unmodifiableList(new ArrayList<>(findings));
    }
    
    /**
     * Sets the findings list (used during data load from disk).
     */
    public void setFindings(List<TrafficFinding> loadedFindings) {
        findings.clear();
        if (loadedFindings != null) {
            findings.addAll(loadedFindings);
        }
    }
    
    /**
     * Clears all findings.
     */
    public void clear() {
        findings.clear();
    }
    
    /**
     * Returns the count of findings.
     */
    public int size() {
        return findings.size();
    }
}
