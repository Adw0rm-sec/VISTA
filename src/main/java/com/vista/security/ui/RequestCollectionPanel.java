package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.vista.security.core.RequestCollectionManager;
import com.vista.security.model.RequestCollection;
import com.vista.security.model.CollectionItem;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Request Collection Panel - Organize and analyze similar requests together.
 */
public class RequestCollectionPanel extends JPanel {
    
    private final IBurpExtenderCallbacks callbacks;
    private final RequestCollectionManager manager;
    
    // UI Components
    private JList<RequestCollection> collectionList;
    private DefaultListModel<RequestCollection> collectionListModel;
    private JTable requestsTable;
    private DefaultTableModel requestsTableModel;
    private JTextArea requestDetailsArea;
    private JTextArea responseDetailsArea;
    private JLabel statsLabel;
    
    // Current selection
    private RequestCollection selectedCollection;
    private CollectionItem selectedItem;
    private List<CollectionItem> currentItems;
    
    public RequestCollectionPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.manager = RequestCollectionManager.getInstance();
        
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));
        
        // Initialize manager
        if (!manager.isInitialized()) {
            manager.initialize();
        }
        
        // Build UI
        add(createHeaderPanel(), BorderLayout.NORTH);
        add(createMainPanel(), BorderLayout.CENTER);
        
        // Load initial data
        refreshCollectionList();
    }
    
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        
        // Title and stats
        JPanel titlePanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel("📁 Request Collections");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        titlePanel.add(titleLabel, BorderLayout.WEST);
        
        statsLabel = new JLabel(manager.getStatsSummary());
        statsLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        titlePanel.add(statsLabel, BorderLayout.EAST);
        
        panel.add(titlePanel, BorderLayout.NORTH);
        
        // Actions
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        JButton newCollectionBtn = new JButton("➕ New Collection");
        newCollectionBtn.setFont(new Font("Arial", Font.BOLD, 12));
        newCollectionBtn.addActionListener(e -> createNewCollection());
        actionsPanel.add(newCollectionBtn);
        
        JButton importBtn = new JButton("📥 Import");
        importBtn.addActionListener(e -> importCollection());
        actionsPanel.add(importBtn);
        
        JButton exportBtn = new JButton("📤 Export");
        exportBtn.addActionListener(e -> exportCollection());
        actionsPanel.add(exportBtn);
        
        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> {
            manager.initialize();
            refreshCollectionList();
        });
        actionsPanel.add(refreshBtn);
        
        panel.add(actionsPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMainPanel() {
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.25);
        
        // Left: Collection list
        mainSplit.setLeftComponent(createCollectionListPanel());
        
        // Right: Requests and details
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setResizeWeight(0.5);
        rightSplit.setTopComponent(createRequestsTablePanel());
        rightSplit.setBottomComponent(createDetailsPanel());
        
        mainSplit.setRightComponent(rightSplit);
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createCollectionListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Collections"));
        
        // List
        collectionListModel = new DefaultListModel<>();
        collectionList = new JList<>(collectionListModel);
        collectionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        collectionList.setCellRenderer(new CollectionListCellRenderer());
        collectionList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onCollectionSelected();
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(collectionList);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Actions
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        
        JButton deleteBtn = new JButton("🗑️ Delete");
        deleteBtn.addActionListener(e -> deleteCollection());
        actionsPanel.add(deleteBtn);
        
        JButton renameBtn = new JButton("✏️ Rename");
        renameBtn.addActionListener(e -> renameCollection());
        actionsPanel.add(renameBtn);
        
        panel.add(actionsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createRequestsTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Requests"));
        
        // Table
        String[] columns = {"Method", "URL", "Status", "Tested", "Success", "Notes"};
        requestsTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        requestsTable = new JTable(requestsTableModel);
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRequestSelected();
            }
        });
        
        // Double-click to view details
        requestsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    viewRequestDetails();
                }
            }
        });
        
        // Column widths
        requestsTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        requestsTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        requestsTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        requestsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        requestsTable.getColumnModel().getColumn(4).setPreferredWidth(60);
        requestsTable.getColumnModel().getColumn(5).setPreferredWidth(150);
        
        JScrollPane scrollPane = new JScrollPane(requestsTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Actions
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        
        JButton addRequestBtn = new JButton("➕ Add Request");
        addRequestBtn.setToolTipText("Use context menu on requests to add them");
        addRequestBtn.setEnabled(false);
        actionsPanel.add(addRequestBtn);
        
        JButton deleteRequestBtn = new JButton("🗑️ Delete");
        deleteRequestBtn.addActionListener(e -> deleteRequest());
        actionsPanel.add(deleteRequestBtn);
        
        JButton markTestedBtn = new JButton("✓ Mark Tested");
        markTestedBtn.addActionListener(e -> markRequestTested(true));
        actionsPanel.add(markTestedBtn);
        
        JButton markSuccessBtn = new JButton("✓ Success");
        markSuccessBtn.addActionListener(e -> markRequestSuccess(true));
        actionsPanel.add(markSuccessBtn);
        
        JButton addNotesBtn = new JButton("📝 Add Notes");
        addNotesBtn.addActionListener(e -> addNotes());
        actionsPanel.add(addNotesBtn);
        
        JButton compareBtn = new JButton("🔍 Compare");
        compareBtn.addActionListener(e -> compareRequests());
        actionsPanel.add(compareBtn);
        
        panel.add(actionsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request/Response Details"));
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        
        // Request
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestDetailsArea = new JTextArea();
        requestDetailsArea.setEditable(false);
        requestDetailsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        requestPanel.add(new JScrollPane(requestDetailsArea), BorderLayout.CENTER);
        splitPane.setLeftComponent(requestPanel);
        
        // Response
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responseDetailsArea = new JTextArea();
        responseDetailsArea.setEditable(false);
        responseDetailsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        responsePanel.add(new JScrollPane(responseDetailsArea), BorderLayout.CENTER);
        splitPane.setRightComponent(responsePanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    // ========== Actions ==========
    
    private void createNewCollection() {
        String name = JOptionPane.showInputDialog(this, "Collection Name:", "New Collection", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.trim().isEmpty()) return;
        
        String description = JOptionPane.showInputDialog(this, "Description (optional):", "New Collection", JOptionPane.PLAIN_MESSAGE);
        if (description == null) description = "";
        
        RequestCollection collection = manager.createCollection(name.trim(), description.trim());
        callbacks.printOutput("[Collections] Created: " + name);
        
        refreshCollectionList();
        collectionList.setSelectedValue(collection, true);
    }
    
    private void deleteCollection() {
        if (selectedCollection == null) {
            JOptionPane.showMessageDialog(this, "Please select a collection first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "Delete collection '" + selectedCollection.getName() + "'?\n\nThis will delete " + selectedCollection.getItemCount() + " request(s).",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            manager.deleteCollection(selectedCollection.getId());
            callbacks.printOutput("[Collections] Deleted: " + selectedCollection.getName());
            
            refreshCollectionList();
        }
    }
    
    private void renameCollection() {
        if (selectedCollection == null) {
            JOptionPane.showMessageDialog(this, "Please select a collection first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String newName = (String) JOptionPane.showInputDialog(this,
            "New name:",
            "Rename Collection",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            selectedCollection.getName());
        
        if (newName != null && !newName.trim().isEmpty()) {
            selectedCollection.setName(newName.trim());
            manager.saveCollection(selectedCollection);
            callbacks.printOutput("[Collections] Renamed to: " + newName);
            
            refreshCollectionList();
            collectionList.setSelectedValue(selectedCollection, true);
        }
    }
    
    private void deleteRequest() {
        if (selectedCollection == null || selectedItem == null) {
            JOptionPane.showMessageDialog(this, "Please select a request first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "Delete this request?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            manager.removeItem(selectedCollection.getId(), selectedItem.getId());
            callbacks.printOutput("[Collections] Deleted request");
            
            refreshRequestsTable();
            updateStats();
        }
    }
    
    private void markRequestTested(boolean tested) {
        if (selectedCollection == null || selectedItem == null) {
            JOptionPane.showMessageDialog(this, "Please select a request first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        manager.updateItem(selectedCollection.getId(), selectedItem.getId(), 
            selectedItem.getNotes(), tested, selectedItem.isSuccess());
        
        refreshRequestsTable();
        updateStats();
    }
    
    private void markRequestSuccess(boolean success) {
        if (selectedCollection == null || selectedItem == null) {
            JOptionPane.showMessageDialog(this, "Please select a request first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        manager.updateItem(selectedCollection.getId(), selectedItem.getId(), 
            selectedItem.getNotes(), true, success);
        
        refreshRequestsTable();
        updateStats();
    }
    
    private void addNotes() {
        if (selectedCollection == null || selectedItem == null) {
            JOptionPane.showMessageDialog(this, "Please select a request first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String notes = (String) JOptionPane.showInputDialog(this,
            "Notes:",
            "Add Notes",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            selectedItem.getNotes());
        
        if (notes != null) {
            manager.updateItem(selectedCollection.getId(), selectedItem.getId(), 
                notes, selectedItem.isTested(), selectedItem.isSuccess());
            
            refreshRequestsTable();
        }
    }
    
    private void viewRequestDetails() {
        if (selectedItem == null) return;
        
        // Already displayed in details panel
        callbacks.printOutput("[Collections] Viewing: " + selectedItem.getMethod() + " " + selectedItem.getUrl());
    }
    
    private void compareRequests() {
        if (selectedCollection == null || selectedCollection.getItemCount() < 2) {
            JOptionPane.showMessageDialog(this, 
                "Need at least 2 requests in collection to compare",
                "Not Enough Requests",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Show comparison dialog
        ComparisonDialog dialog = new ComparisonDialog(
            (Frame) SwingUtilities.getWindowAncestor(this),
            selectedCollection);
        dialog.setVisible(true);
    }
    
    private void importCollection() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Collection");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"));
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                RequestCollection collection = manager.importCollection(file);
                
                callbacks.printOutput("[Collections] Imported: " + collection.getName() + " (" + collection.getItemCount() + " requests)");
                
                JOptionPane.showMessageDialog(this,
                    "Collection imported successfully!\n\n" +
                    "Name: " + collection.getName() + "\n" +
                    "Requests: " + collection.getItemCount(),
                    "Import Success",
                    JOptionPane.INFORMATION_MESSAGE);
                
                refreshCollectionList();
                collectionList.setSelectedValue(collection, true);
            } catch (Exception e) {
                callbacks.printError("[Collections] Import failed: " + e.getMessage());
                JOptionPane.showMessageDialog(this,
                    "Failed to import collection:\n" + e.getMessage(),
                    "Import Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void exportCollection() {
        if (selectedCollection == null) {
            JOptionPane.showMessageDialog(this, "Please select a collection first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Collection");
        fileChooser.setSelectedFile(new File(selectedCollection.getName() + ".json"));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                if (!file.getName().endsWith(".json")) {
                    file = new File(file.getAbsolutePath() + ".json");
                }
                
                manager.exportCollection(selectedCollection.getId(), file);
                
                callbacks.printOutput("[Collections] Exported: " + selectedCollection.getName() + " to " + file.getName());
                
                JOptionPane.showMessageDialog(this,
                    "Collection exported successfully!",
                    "Export Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                callbacks.printError("[Collections] Export failed: " + e.getMessage());
                JOptionPane.showMessageDialog(this,
                    "Failed to export collection:\n" + e.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    // ========== UI Updates ==========
    
    private void refreshCollectionList() {
        collectionListModel.clear();
        List<RequestCollection> collections = manager.getAllCollections();
        for (RequestCollection collection : collections) {
            collectionListModel.addElement(collection);
        }
        updateStats();
    }
    
    private void onCollectionSelected() {
        selectedCollection = collectionList.getSelectedValue();
        refreshRequestsTable();
    }
    
    private void refreshRequestsTable() {
        requestsTableModel.setRowCount(0);
        
        if (selectedCollection == null) {
            currentItems = null;
            requestDetailsArea.setText("");
            responseDetailsArea.setText("");
            return;
        }
        
        currentItems = selectedCollection.getItems();
        
        for (CollectionItem item : currentItems) {
            requestsTableModel.addRow(new Object[]{
                item.getMethod(),
                truncate(item.getUrl(), 80),
                item.getStatusCode(),
                item.isTested() ? "✓" : "",
                item.isSuccess() ? "✓" : "",
                truncate(item.getNotes(), 30)
            });
        }
    }
    
    private void onRequestSelected() {
        int selectedRow = requestsTable.getSelectedRow();
        if (selectedRow < 0 || currentItems == null || selectedRow >= currentItems.size()) {
            selectedItem = null;
            requestDetailsArea.setText("");
            responseDetailsArea.setText("");
            return;
        }
        
        selectedItem = currentItems.get(selectedRow);
        displayRequestResponse(selectedItem);
    }
    
    private void displayRequestResponse(CollectionItem item) {
        // Display request
        if (item.getRequest() != null) {
            requestDetailsArea.setText(new String(item.getRequest()));
        } else {
            requestDetailsArea.setText("No request data");
        }
        
        // Display response
        if (item.getResponse() != null) {
            responseDetailsArea.setText(new String(item.getResponse()));
        } else {
            responseDetailsArea.setText("No response data");
        }
        
        requestDetailsArea.setCaretPosition(0);
        responseDetailsArea.setCaretPosition(0);
    }
    
    private void updateStats() {
        statsLabel.setText(manager.getStatsSummary());
    }
    
    // ========== Public API ==========
    
    /**
     * Add a request to a collection (called from context menu).
     */
    public void addRequestToCollection(IHttpRequestResponse requestResponse) {
        // Show dialog to select collection
        List<RequestCollection> collections = manager.getAllCollections();
        
        if (collections.isEmpty()) {
            // Create first collection
            String name = JOptionPane.showInputDialog(this, 
                "No collections exist. Create one?\n\nCollection Name:", 
                "New Collection", 
                JOptionPane.PLAIN_MESSAGE);
            
            if (name == null || name.trim().isEmpty()) return;
            
            RequestCollection collection = manager.createCollection(name.trim(), "");
            manager.addItem(collection.getId(), requestResponse);
            
            callbacks.printOutput("[Collections] Created collection and added request: " + name);
            
            refreshCollectionList();
            collectionList.setSelectedValue(collection, true);
        } else {
            // Select existing collection
            RequestCollection[] options = collections.toArray(new RequestCollection[0]);
            RequestCollection selected = (RequestCollection) JOptionPane.showInputDialog(this,
                "Select collection:",
                "Add to Collection",
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]);
            
            if (selected != null) {
                manager.addItem(selected.getId(), requestResponse);
                callbacks.printOutput("[Collections] Added request to: " + selected.getName());
                
                if (selected.equals(selectedCollection)) {
                    refreshRequestsTable();
                }
                updateStats();
            }
        }
    }
    
    // ========== Helper Classes ==========
    
    /**
     * Custom cell renderer for collection list.
     */
    private static class CollectionListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof RequestCollection) {
                RequestCollection collection = (RequestCollection) value;
                // Use plain text instead of HTML to avoid rendering issues
                setText(collection.getName() + " (" + collection.getItemCount() + " requests)");
            }
            
            return this;
        }
    }
    
    /**
     * Comparison dialog for side-by-side request comparison.
     */
    private static class ComparisonDialog extends JDialog {
        public ComparisonDialog(Frame owner, RequestCollection collection) {
            super(owner, "Compare Requests - " + collection.getName(), true);
            setSize(1000, 600);
            setLocationRelativeTo(owner);
            
            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(new EmptyBorder(15, 15, 15, 15));
            
            // Selection
            JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            selectionPanel.add(new JLabel("Select 2 requests to compare:"));
            
            JComboBox<CollectionItem> request1Combo = new JComboBox<>();
            JComboBox<CollectionItem> request2Combo = new JComboBox<>();
            
            for (CollectionItem item : collection.getItems()) {
                request1Combo.addItem(item);
                request2Combo.addItem(item);
            }
            
            selectionPanel.add(new JLabel("Request 1:"));
            selectionPanel.add(request1Combo);
            selectionPanel.add(new JLabel("Request 2:"));
            selectionPanel.add(request2Combo);
            
            JButton compareBtn = new JButton("Compare");
            selectionPanel.add(compareBtn);
            
            panel.add(selectionPanel, BorderLayout.NORTH);
            
            // Comparison view
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane.setResizeWeight(0.5);
            
            JTextArea leftArea = new JTextArea();
            leftArea.setEditable(false);
            leftArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            
            JTextArea rightArea = new JTextArea();
            rightArea.setEditable(false);
            rightArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            
            splitPane.setLeftComponent(new JScrollPane(leftArea));
            splitPane.setRightComponent(new JScrollPane(rightArea));
            
            panel.add(splitPane, BorderLayout.CENTER);
            
            // Compare action
            compareBtn.addActionListener(e -> {
                CollectionItem item1 = (CollectionItem) request1Combo.getSelectedItem();
                CollectionItem item2 = (CollectionItem) request2Combo.getSelectedItem();
                
                if (item1 != null && item2 != null) {
                    leftArea.setText(formatItemForComparison(item1));
                    rightArea.setText(formatItemForComparison(item2));
                }
            });
            
            add(panel);
        }
        
        private String formatItemForComparison(CollectionItem item) {
            StringBuilder sb = new StringBuilder();
            sb.append("═══ REQUEST ═══\n");
            sb.append(item.getMethod()).append(" ").append(item.getUrl()).append("\n");
            sb.append("Status: ").append(item.getStatusCode()).append("\n\n");
            
            if (item.getRequest() != null) {
                sb.append(new String(item.getRequest()));
            }
            
            sb.append("\n\n═══ RESPONSE ═══\n");
            if (item.getResponse() != null) {
                sb.append(new String(item.getResponse()));
            }
            
            return sb.toString();
        }
    }
    
    // ========== Helpers ==========
    
    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength - 3) + "...";
    }
}
