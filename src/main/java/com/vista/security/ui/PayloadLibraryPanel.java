package com.vista.security.ui;

import burp.IBurpExtenderCallbacks;
import com.vista.security.core.PayloadLibraryManager;
import com.vista.security.core.BuiltInPayloads;
import com.vista.security.model.Payload;
import com.vista.security.model.PayloadLibrary;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;

/**
 * Simplified Payload Library Panel - Easy to use, immediate value.
 */
public class PayloadLibraryPanel extends JPanel {
    
    private final IBurpExtenderCallbacks callbacks;
    private final PayloadLibraryManager manager;
    
    // UI Components
    private JComboBox<String> categoryFilter;
    private JTextField searchField;
    private JTable payloadsTable;
    private DefaultTableModel tableModel;
    private JTextArea payloadDetailsArea;
    private JLabel statsLabel;
    
    // Current selection
    private Payload selectedPayload;
    private List<Payload> currentPayloads;
    
    public PayloadLibraryPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.manager = PayloadLibraryManager.getInstance();
        
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));
        
        // Initialize manager
        initializeManager();
        
        // Build simplified UI
        add(createHeaderPanel(), BorderLayout.NORTH);
        add(createMainPanel(), BorderLayout.CENTER);
        
        // Load initial data
        refreshPayloadsTable();
    }
    
    private void initializeManager() {
        if (!manager.isInitialized()) {
            manager.initialize();
            
            if (manager.getTotalLibraryCount() == 0) {
                callbacks.printOutput("[Payload Library] Installing built-in libraries...");
                BuiltInPayloads.installBuiltInLibraries();
                manager.initialize();
                callbacks.printOutput("[Payload Library] Installed " + manager.getTotalLibraryCount() + " libraries with " + manager.getTotalPayloadCount() + " payloads");
            }
        }
    }
    
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        
        // Title and stats
        JPanel titlePanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel("🎯 Payload Library");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        titlePanel.add(titleLabel, BorderLayout.WEST);
        
        statsLabel = new JLabel(manager.getStatsSummary());
        statsLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        titlePanel.add(statsLabel, BorderLayout.EAST);
        
        panel.add(titlePanel, BorderLayout.NORTH);
        
        // Filters and actions
        JPanel controlsPanel = new JPanel(new BorderLayout(10, 5));
        
        // Left: Filters
        JPanel filtersPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        filtersPanel.add(new JLabel("Category:"));
        categoryFilter = new JComboBox<>();
        refreshCategoryFilter();
        categoryFilter.addActionListener(e -> refreshPayloadsTable());
        filtersPanel.add(categoryFilter);
        
        filtersPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.addActionListener(e -> refreshPayloadsTable());
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                refreshPayloadsTable();
            }
        });
        filtersPanel.add(searchField);
        
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            categoryFilter.setSelectedIndex(0);
            searchField.setText("");
            refreshPayloadsTable();
        });
        filtersPanel.add(clearBtn);
        
        controlsPanel.add(filtersPanel, BorderLayout.WEST);
        
        // Right: Quick actions
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        
        JButton addPayloadBtn = new JButton("➕ Add Payload");
        addPayloadBtn.setFont(new Font("Arial", Font.BOLD, 12));
        addPayloadBtn.setToolTipText("Add a single payload");
        addPayloadBtn.addActionListener(e -> addPayload());
        actionsPanel.add(addPayloadBtn);
        
        JButton bulkImportBtn = new JButton("📋 Bulk Import");
        bulkImportBtn.setFont(new Font("Arial", Font.BOLD, 12));
        bulkImportBtn.setToolTipText("Paste multiple payloads at once");
        bulkImportBtn.addActionListener(e -> bulkImportPayloads());
        actionsPanel.add(bulkImportBtn);
        
        JButton importBtn = new JButton("📥 Import File");
        importBtn.setToolTipText("Import from JSON file");
        importBtn.addActionListener(e -> importLibrary());
        actionsPanel.add(importBtn);
        
        JButton refreshBtn = new JButton("🔄");
        refreshBtn.setToolTipText("Refresh");
        refreshBtn.addActionListener(e -> {
            manager.initialize();
            refreshCategoryFilter();
            refreshPayloadsTable();
        });
        actionsPanel.add(refreshBtn);
        
        controlsPanel.add(actionsPanel, BorderLayout.EAST);
        
        panel.add(controlsPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMainPanel() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.7);
        
        // Top: Payloads table
        splitPane.setTopComponent(createPayloadsTablePanel());
        
        // Bottom: Details and actions
        splitPane.setBottomComponent(createDetailsPanel());
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createPayloadsTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Table
        String[] columns = {"Payload", "Description", "Category", "Success Rate", "Uses"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        payloadsTable = new JTable(tableModel);
        payloadsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        payloadsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onPayloadSelected();
            }
        });
        
        // Double-click to copy
        payloadsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    copySelectedPayload();
                }
            }
        });
        
        // Keyboard shortcuts
        payloadsTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_C) {
                    copySelectedPayload();
                } else if (e.getKeyCode() == KeyEvent.VK_DELETE) {
                    deleteSelectedPayload();
                }
            }
        });
        
        // Column widths
        payloadsTable.getColumnModel().getColumn(0).setPreferredWidth(250);
        payloadsTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        payloadsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        payloadsTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        payloadsTable.getColumnModel().getColumn(4).setPreferredWidth(60);
        
        JScrollPane scrollPane = new JScrollPane(payloadsTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Context menu
        JPopupMenu contextMenu = new JPopupMenu();
        
        JMenuItem copyItem = new JMenuItem("📋 Copy Payload (Ctrl+C)");
        copyItem.addActionListener(e -> copySelectedPayload());
        contextMenu.add(copyItem);
        
        contextMenu.addSeparator();
        
        JMenuItem markSuccessItem = new JMenuItem("✓ Mark as Success");
        markSuccessItem.addActionListener(e -> markPayloadResult(true));
        contextMenu.add(markSuccessItem);
        
        JMenuItem markFailureItem = new JMenuItem("✗ Mark as Failure");
        markFailureItem.addActionListener(e -> markPayloadResult(false));
        contextMenu.add(markFailureItem);
        
        contextMenu.addSeparator();
        
        JMenuItem deleteItem = new JMenuItem("🗑️ Delete Payload (Del)");
        deleteItem.addActionListener(e -> deleteSelectedPayload());
        contextMenu.add(deleteItem);
        
        payloadsTable.setComponentPopupMenu(contextMenu);
        
        return panel;
    }
    
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Payload Details"));
        
        // Details area
        payloadDetailsArea = new JTextArea();
        payloadDetailsArea.setEditable(false);
        payloadDetailsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        payloadDetailsArea.setLineWrap(true);
        payloadDetailsArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(payloadDetailsArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        
        JButton copyBtn = new JButton("📋 Copy");
        copyBtn.addActionListener(e -> copySelectedPayload());
        buttonPanel.add(copyBtn);
        
        JButton markSuccessBtn = new JButton("✓ Success");
        markSuccessBtn.addActionListener(e -> markPayloadResult(true));
        buttonPanel.add(markSuccessBtn);
        
        JButton markFailBtn = new JButton("✗ Failure");
        markFailBtn.addActionListener(e -> markPayloadResult(false));
        buttonPanel.add(markFailBtn);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    // ========== Actions ==========
    
    private void addPayload() {
        String[] categories = manager.getCategories().toArray(new String[0]);
        PayloadEditorDialog dialog = new PayloadEditorDialog((Frame) SwingUtilities.getWindowAncestor(this), categories);
        dialog.setVisible(true);
        
        if (dialog.isSaved()) {
            Payload payload = dialog.getPayload();
            String category = dialog.getSelectedCategory();
            
            // Find or create library for this category
            PayloadLibrary library = findOrCreateLibrary(category);
            library.addPayload(payload);
            manager.saveLibrary(library);
            
            callbacks.printOutput("[Payload Library] Added payload to category: " + category);
            
            // Refresh UI
            refreshCategoryFilter();
            refreshPayloadsTable();
            
            JOptionPane.showMessageDialog(this, 
                "Payload added successfully!\n\nCategory: " + category,
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void bulkImportPayloads() {
        String[] categories = manager.getCategories().toArray(new String[0]);
        BulkPayloadImportDialog dialog = new BulkPayloadImportDialog(
            (Frame) SwingUtilities.getWindowAncestor(this), categories);
        dialog.setVisible(true);
        
        if (dialog.isImported()) {
            List<Payload> payloads = dialog.getPayloads();
            String category = dialog.getSelectedCategory();
            
            // Find or create library for this category
            PayloadLibrary library = findOrCreateLibrary(category);
            
            // Add all payloads
            for (Payload payload : payloads) {
                library.addPayload(payload);
            }
            
            manager.saveLibrary(library);
            
            callbacks.printOutput(String.format("[Payload Library] Bulk imported %d payloads to category: %s", 
                payloads.size(), category));
            
            // Refresh UI
            refreshCategoryFilter();
            refreshPayloadsTable();
            
            JOptionPane.showMessageDialog(this, 
                String.format("Successfully imported %d payload%s!\n\nCategory: %s\n\nYou can now search and use them.",
                    payloads.size(),
                    payloads.size() == 1 ? "" : "s",
                    category),
                "Bulk Import Success",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private PayloadLibrary findOrCreateLibrary(String category) {
        // Try to find existing custom library for this category
        for (PayloadLibrary lib : manager.getAllLibraries()) {
            if (!lib.isBuiltIn() && lib.getCategory().equalsIgnoreCase(category)) {
                return lib;
            }
        }
        
        // Create new library
        return manager.createLibrary("Custom " + category, category, "Custom");
    }
    
    private void copySelectedPayload() {
        if (selectedPayload == null) {
            JOptionPane.showMessageDialog(this, "Please select a payload first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(selectedPayload.getValue()), null);
        
        callbacks.printOutput("[Payload Library] Copied: " + truncate(selectedPayload.getValue(), 100));
        
        // Show brief notification
        JOptionPane.showMessageDialog(this, 
            "Payload copied to clipboard!",
            "Copied",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void markPayloadResult(boolean success) {
        if (selectedPayload == null) {
            JOptionPane.showMessageDialog(this, "Please select a payload first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Simple success/failure tracking
        if (success) {
            selectedPayload.recordSuccess();
        } else {
            selectedPayload.recordFailure();
        }
        
        // Save the library
        for (PayloadLibrary library : manager.getAllLibraries()) {
            if (library.getPayload(selectedPayload.getId()) != null) {
                if (!library.isBuiltIn()) {
                    manager.saveLibrary(library);
                }
                break;
            }
        }
        
        // Refresh display
        refreshPayloadsTable();
        displayPayloadDetails(selectedPayload);
        
        String message = success ? "✓ Marked as successful!" : "✗ Marked as failed.";
        callbacks.printOutput("[Payload Library] " + message + " Success rate: " + selectedPayload.getSuccessRateDisplay());
    }
    
    private void deleteSelectedPayload() {
        if (selectedPayload == null) {
            JOptionPane.showMessageDialog(this, "Please select a payload first", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Find the library containing this payload
        PayloadLibrary containingLibrary = null;
        for (PayloadLibrary library : manager.getAllLibraries()) {
            if (library.getPayload(selectedPayload.getId()) != null) {
                containingLibrary = library;
                break;
            }
        }
        
        if (containingLibrary == null) {
            JOptionPane.showMessageDialog(this, "Cannot find library for this payload", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (containingLibrary.isBuiltIn()) {
            JOptionPane.showMessageDialog(this, "Cannot delete payloads from built-in libraries", "Not Allowed", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "Delete this payload?\n\n" + truncate(selectedPayload.getValue(), 100),
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            containingLibrary.removePayload(selectedPayload.getId());
            manager.saveLibrary(containingLibrary);
            
            callbacks.printOutput("[Payload Library] Deleted payload");
            
            refreshPayloadsTable();
        }
    }
    
    private void importLibrary() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Payload Library");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"));
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                PayloadLibrary library = manager.importFromFile(file);
                
                callbacks.printOutput("[Payload Library] Imported: " + library.getName() + " (" + library.getPayloadCount() + " payloads)");
                
                JOptionPane.showMessageDialog(this, 
                    "Library imported successfully!\n\n" +
                    "Name: " + library.getName() + "\n" +
                    "Payloads: " + library.getPayloadCount(),
                    "Import Success",
                    JOptionPane.INFORMATION_MESSAGE);
                
                refreshCategoryFilter();
                refreshPayloadsTable();
            } catch (Exception e) {
                callbacks.printError("[Payload Library] Import failed: " + e.getMessage());
                JOptionPane.showMessageDialog(this, 
                    "Failed to import library:\n" + e.getMessage(),
                    "Import Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    // ========== UI Updates ==========
    
    private void refreshCategoryFilter() {
        String selected = (String) categoryFilter.getSelectedItem();
        categoryFilter.removeAllItems();
        categoryFilter.addItem("All");
        
        List<String> categories = manager.getCategories();
        for (String category : categories) {
            int count = manager.getPayloadsByCategory(category).size();
            categoryFilter.addItem(category + " (" + count + ")");
        }
        
        if (selected != null) {
            // Try to restore selection
            for (int i = 0; i < categoryFilter.getItemCount(); i++) {
                String item = categoryFilter.getItemAt(i);
                if (item.startsWith(selected.split(" \\(")[0])) {
                    categoryFilter.setSelectedIndex(i);
                    break;
                }
            }
        }
    }
    
    private void refreshPayloadsTable() {
        tableModel.setRowCount(0);
        
        // Get payloads based on filters
        String categorySelection = (String) categoryFilter.getSelectedItem();
        String category = null;
        if (categorySelection != null && !categorySelection.equals("All")) {
            category = categorySelection.split(" \\(")[0]; // Remove count
        }
        
        String search = searchField.getText().trim();
        
        List<Payload> payloads;
        if (!search.isEmpty()) {
            payloads = manager.searchPayloads(search);
        } else if (category != null) {
            payloads = manager.getPayloadsByCategory(category);
        } else {
            payloads = manager.getAllPayloads();
        }
        
        currentPayloads = payloads;
        
        // Populate table
        for (Payload payload : payloads) {
            String payloadValue = truncate(payload.getValue(), 60);
            String description = truncate(payload.getDescription(), 50);
            String cat = getCategoryForPayload(payload);
            
            tableModel.addRow(new Object[]{
                payloadValue,
                description,
                cat,
                payload.getSuccessRateDisplay(),
                payload.getTotalUses()
            });
        }
        
        // Update stats
        statsLabel.setText(manager.getStatsSummary());
        
        // Show helpful message if empty
        if (payloads.isEmpty()) {
            if (!search.isEmpty()) {
                payloadDetailsArea.setText("No payloads found matching: " + search + "\n\nTry:\n- Different search terms\n- Clear filters\n- Add custom payloads");
            } else {
                payloadDetailsArea.setText("No payloads in this category.\n\nClick '➕ Add Payload' to add your own!");
            }
        }
    }
    
    private void onPayloadSelected() {
        int selectedRow = payloadsTable.getSelectedRow();
        if (selectedRow < 0 || currentPayloads == null || selectedRow >= currentPayloads.size()) {
            selectedPayload = null;
            payloadDetailsArea.setText("");
            return;
        }
        
        selectedPayload = currentPayloads.get(selectedRow);
        displayPayloadDetails(selectedPayload);
    }
    
    private void displayPayloadDetails(Payload payload) {
        StringBuilder details = new StringBuilder();
        details.append("═══ PAYLOAD ═══\n");
        details.append(payload.getValue()).append("\n\n");
        
        details.append("Description: ").append(payload.getDescription()).append("\n");
        details.append("Context: ").append(payload.getContext()).append("\n");
        details.append("Encoding: ").append(payload.getEncoding()).append("\n");
        
        if (!payload.getTags().isEmpty()) {
            details.append("Tags: ").append(String.join(", ", payload.getTags())).append("\n");
        }
        
        details.append("\n═══ STATISTICS ═══\n");
        details.append("Success Rate: ").append(payload.getSuccessRateDisplay()).append("\n");
        details.append("Total Uses: ").append(payload.getTotalUses()).append("\n");
        details.append("Successes: ").append(payload.getSuccessCount()).append("\n");
        details.append("Failures: ").append(payload.getFailureCount()).append("\n");
        
        if (payload.hasBeenUsed()) {
            details.append("Last Used: ").append(new java.util.Date(payload.getLastUsed())).append("\n");
        }
        
        if (!payload.getNotes().isEmpty()) {
            details.append("\n═══ NOTES ═══\n").append(payload.getNotes()).append("\n");
        }
        
        details.append("\n💡 TIP: Double-click or press Ctrl+C to copy");
        
        payloadDetailsArea.setText(details.toString());
        payloadDetailsArea.setCaretPosition(0);
    }
    
    // ========== Helpers ==========
    
    private String getCategoryForPayload(Payload payload) {
        for (PayloadLibrary library : manager.getAllLibraries()) {
            if (library.getPayload(payload.getId()) != null) {
                return library.getCategory();
            }
        }
        return "Unknown";
    }
    
    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength - 3) + "...";
    }
}
