package com.vista.security.ui;

import com.vista.security.model.TrafficFinding;
import com.vista.security.util.FindingGrouper;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * Hierarchical tree view for traffic findings.
 * Groups findings by: Type -> URL -> Parameter
 */
public class TrafficFindingsTreePanel extends JPanel {
    
    private final JTree findingsTree;
    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode rootNode;
    private FindingSelectionListener selectionListener;
    
    public TrafficFindingsTreePanel() {
        setLayout(new BorderLayout());
        
        // Create tree
        rootNode = new DefaultMutableTreeNode("Findings (0)");
        treeModel = new DefaultTreeModel(rootNode);
        findingsTree = new JTree(treeModel);
        findingsTree.setRootVisible(true);
        findingsTree.setShowsRootHandles(true);
        
        // Custom renderer for severity colors
        findingsTree.setCellRenderer(new FindingTreeCellRenderer());
        
        // Selection listener
        findingsTree.addTreeSelectionListener(e -> {
            TreePath path = e.getNewLeadSelectionPath();
            if (path != null && selectionListener != null) {
                DefaultMutableTreeNode node = 
                    (DefaultMutableTreeNode) path.getLastPathComponent();
                Object userObject = node.getUserObject();
                
                if (userObject instanceof TrafficFinding) {
                    selectionListener.onFindingSelected((TrafficFinding) userObject);
                }
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(findingsTree);
        add(scrollPane, BorderLayout.CENTER);
        
        // Toolbar
        add(createToolbar(), BorderLayout.NORTH);
    }
    
    /**
     * Create toolbar with filter and expand/collapse buttons.
     */
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton expandAllButton = new JButton("Expand All");
        expandAllButton.addActionListener(e -> expandAll());
        toolbar.add(expandAllButton);
        
        JButton collapseAllButton = new JButton("Collapse All");
        collapseAllButton.addActionListener(e -> collapseAll());
        toolbar.add(collapseAllButton);
        
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearFindings());
        toolbar.add(clearButton);
        
        return toolbar;
    }
    
    /**
     * Update tree with new findings.
     */
    public void updateFindings(List<TrafficFinding> findings) {
        System.out.println("[Findings Tree] ═══════════════════════════════════════");
        System.out.println("[Findings Tree] 🌳 Building Tree Structure");
        System.out.println("[Findings Tree]    Input findings: " + findings.size());
        
        // Save current expansion state by storing node labels (not TreePath objects)
        java.util.Set<String> expandedNodeLabels = new java.util.HashSet<>();
        for (int i = 0; i < findingsTree.getRowCount(); i++) {
            TreePath path = findingsTree.getPathForRow(i);
            if (path != null && findingsTree.isExpanded(path)) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                Object userObject = node.getUserObject();
                if (userObject != null && !(userObject instanceof TrafficFinding)) {
                    // Store the label (e.g., "SECRET (3)", "example.com/api (2)")
                    expandedNodeLabels.add(extractNodeKey(userObject.toString()));
                }
            }
        }
        
        // Clear existing tree
        rootNode.removeAllChildren();
        
        if (findings.isEmpty()) {
            rootNode.setUserObject("Findings (0)");
            treeModel.reload();
            System.out.println("[Findings Tree] ℹ️ No findings to display");
            System.out.println("[Findings Tree] ═══════════════════════════════════════");
            return;
        }
        
        // Update root label
        Map<String, Integer> severityCounts = FindingGrouper.countBySeverity(findings);
        String rootLabel = String.format("Findings (%d) - 🔴 %d 🟠 %d 🟡 %d 🔵 %d",
            findings.size(),
            severityCounts.get("CRITICAL"),
            severityCounts.get("HIGH"),
            severityCounts.get("MEDIUM"),
            severityCounts.get("LOW")
        );
        rootNode.setUserObject(rootLabel);
        
        // Create hierarchy: Type -> URL -> Parameter -> Finding
        Map<String, Map<String, Map<String, List<TrafficFinding>>>> hierarchy = 
            FindingGrouper.createHierarchy(findings);
        
        int typeNodeCount = 0;
        int urlNodeCount = 0;
        int paramNodeCount = 0;
        
        // Build tree
        for (Map.Entry<String, Map<String, Map<String, List<TrafficFinding>>>> typeEntry : 
                hierarchy.entrySet()) {
            String type = typeEntry.getKey();
            Map<String, Map<String, List<TrafficFinding>>> urlMap = typeEntry.getValue();
            
            // Count findings for this type
            int typeCount = urlMap.values().stream()
                .mapToInt(paramMap -> paramMap.values().stream()
                    .mapToInt(List::size)
                    .sum())
                .sum();
            
            // Create type node
            String typeLabel = String.format("%s (%d)", type, typeCount);
            DefaultMutableTreeNode typeNode = new DefaultMutableTreeNode(typeLabel);
            rootNode.add(typeNode);
            typeNodeCount++;
            
            // Add URLs under type
            for (Map.Entry<String, Map<String, List<TrafficFinding>>> urlEntry : 
                    urlMap.entrySet()) {
                String url = urlEntry.getKey();
                Map<String, List<TrafficFinding>> paramMap = urlEntry.getValue();
                
                // Count findings for this URL
                int urlCount = paramMap.values().stream()
                    .mapToInt(List::size)
                    .sum();
                
                // Shorten URL for display
                String displayUrl = shortenUrl(url);
                String urlLabel = String.format("%s (%d)", displayUrl, urlCount);
                DefaultMutableTreeNode urlNode = new DefaultMutableTreeNode(urlLabel);
                typeNode.add(urlNode);
                urlNodeCount++;
                
                // Add parameters under URL
                for (Map.Entry<String, List<TrafficFinding>> paramEntry : 
                        paramMap.entrySet()) {
                    String param = paramEntry.getKey();
                    List<TrafficFinding> paramFindings = paramEntry.getValue();
                    
                    if (paramFindings.size() == 1) {
                        // Single finding - add directly
                        TrafficFinding finding = paramFindings.get(0);
                        DefaultMutableTreeNode findingNode = new DefaultMutableTreeNode(finding);
                        urlNode.add(findingNode);
                    } else {
                        // Multiple findings - group by parameter
                        String paramLabel = String.format("%s (%d)", param, paramFindings.size());
                        DefaultMutableTreeNode paramNode = new DefaultMutableTreeNode(paramLabel);
                        urlNode.add(paramNode);
                        paramNodeCount++;
                        
                        // Add individual findings
                        for (TrafficFinding finding : paramFindings) {
                            DefaultMutableTreeNode findingNode = 
                                new DefaultMutableTreeNode(finding);
                            paramNode.add(findingNode);
                        }
                    }
                }
            }
        }
        
        // Reload tree
        treeModel.reload();
        
        // Restore expansion state by matching node labels
        if (!expandedNodeLabels.isEmpty()) {
            restoreExpansionState(rootNode, expandedNodeLabels);
        } else {
            // If no paths were expanded before, expand first level (types) by default
            for (int i = 0; i < rootNode.getChildCount(); i++) {
                findingsTree.expandRow(i + 1);
            }
        }
        
        System.out.println("[Findings Tree] ✅ Tree Build Complete");
        System.out.println("[Findings Tree]    Root label: " + rootLabel);
        System.out.println("[Findings Tree]    Type nodes: " + typeNodeCount);
        System.out.println("[Findings Tree]    URL nodes: " + urlNodeCount);
        System.out.println("[Findings Tree]    Parameter nodes: " + paramNodeCount);
        System.out.println("[Findings Tree]    Expanded nodes restored: " + expandedNodeLabels.size());
        System.out.println("[Findings Tree] ═══════════════════════════════════════");
    }
    
    /**
     * Extract key from node label (remove count suffix).
     * E.g., "SECRET (3)" -> "SECRET", "example.com/api (2)" -> "example.com/api"
     */
    private String extractNodeKey(String label) {
        int lastParen = label.lastIndexOf(" (");
        if (lastParen > 0) {
            return label.substring(0, lastParen);
        }
        return label;
    }
    
    /**
     * Recursively restore expansion state by matching node labels.
     */
    private void restoreExpansionState(DefaultMutableTreeNode node, java.util.Set<String> expandedNodeLabels) {
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
            Object userObject = child.getUserObject();
            
            if (userObject != null && !(userObject instanceof TrafficFinding)) {
                String nodeKey = extractNodeKey(userObject.toString());
                if (expandedNodeLabels.contains(nodeKey)) {
                    // Expand this node
                    TreePath path = new TreePath(child.getPath());
                    findingsTree.expandPath(path);
                    
                    // Recursively restore children
                    restoreExpansionState(child, expandedNodeLabels);
                }
            }
        }
    }
    
    /**
     * Shorten URL for display.
     */
    private String shortenUrl(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            String path = u.getPath();
            if (path.length() > 50) {
                path = "..." + path.substring(path.length() - 47);
            }
            return u.getHost() + path;
        } catch (Exception e) {
            return url.length() > 50 ? url.substring(0, 47) + "..." : url;
        }
    }
    
    /**
     * Expand all nodes.
     */
    private void expandAll() {
        for (int i = 0; i < findingsTree.getRowCount(); i++) {
            findingsTree.expandRow(i);
        }
    }
    
    /**
     * Collapse all nodes.
     */
    private void collapseAll() {
        for (int i = findingsTree.getRowCount() - 1; i >= 0; i--) {
            findingsTree.collapseRow(i);
        }
    }
    
    /**
     * Clear all findings.
     */
    private void clearFindings() {
        rootNode.removeAllChildren();
        rootNode.setUserObject("Findings (0)");
        treeModel.reload();
        
        if (selectionListener != null) {
            selectionListener.onFindingSelected(null);
        }
    }
    
    /**
     * Set selection listener.
     */
    public void setSelectionListener(FindingSelectionListener listener) {
        this.selectionListener = listener;
    }
    
    /**
     * Listener interface for finding selection.
     */
    public interface FindingSelectionListener {
        void onFindingSelected(TrafficFinding finding);
    }
    
    /**
     * Custom tree cell renderer for severity colors.
     */
    private static class FindingTreeCellRenderer extends DefaultTreeCellRenderer {
        
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value,
                boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            
            super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
            
            if (value instanceof DefaultMutableTreeNode) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
                Object userObject = node.getUserObject();
                
                if (userObject instanceof TrafficFinding) {
                    TrafficFinding finding = (TrafficFinding) userObject;
                    
                    // Set text with severity emoji
                    String severityEmoji = getSeverityEmoji(finding.getSeverity());
                    String param = finding.getAffectedParameter();
                    
                    // If parameter is null or empty, use finding type as label
                    if (param == null || param.trim().isEmpty()) {
                        param = finding.getType();
                    }
                    
                    setText(severityEmoji + " " + param);
                    
                    // Set color based on severity
                    if (!selected) {
                        setForeground(getSeverityColor(finding.getSeverity()));
                    }
                }
            }
            
            return this;
        }
        
        private String getSeverityEmoji(String severity) {
            return switch (severity.toUpperCase()) {
                case "CRITICAL" -> "🔴";
                case "HIGH" -> "🟠";
                case "MEDIUM" -> "🟡";
                case "LOW" -> "🔵";
                case "INFO" -> "⚪";
                default -> "⚫";
            };
        }
        
        private Color getSeverityColor(String severity) {
            return switch (severity.toUpperCase()) {
                case "CRITICAL" -> new Color(220, 20, 60);  // Crimson
                case "HIGH" -> new Color(255, 140, 0);      // Dark Orange
                case "MEDIUM" -> new Color(255, 215, 0);    // Gold
                case "LOW" -> new Color(70, 130, 180);      // Steel Blue
                case "INFO" -> new Color(128, 128, 128);    // Gray
                default -> Color.BLACK;
            };
        }
    }
}
