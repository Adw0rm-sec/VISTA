package com.vista.security.ui;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import static com.vista.security.ui.VistaTheme.*;

/**
 * Professional HTTP message viewer with side-by-side Request/Response display
 * and syntax highlighting similar to Burp Suite.
 * 
 * Features:
 * - Side-by-side split pane layout
 * - Syntax highlighting for HTTP headers (blue/bold)
 * - Different colors for body content
 * - Status line coloring (green for 2xx, red for 4xx/5xx)
 * - Professional fonts (Consolas/Monaco/Courier New)
 * - Search functionality with highlighting
 * - Navigate between search results
 */
public class HttpMessageViewer extends JPanel {
    
    private final JTextPane requestPane;
    private final JTextPane responsePane;
    private final JSplitPane splitPane;
    
    // Search components
    private JTextField searchField;
    private JLabel searchResultLabel;
    private JButton prevButton;
    private JButton nextButton;
    private JCheckBox caseSensitiveCheckbox;
    private final JPanel searchPanel;
    
    // Search state
    private List<SearchResult> requestSearchResults = new ArrayList<>();
    private List<SearchResult> responseSearchResults = new ArrayList<>();
    private int currentRequestResultIndex = -1;
    private int currentResponseResultIndex = -1;
    private JTextPane currentSearchPane = null;
    
    // Color scheme (Burp Suite inspired)
    private static final Color HEADER_COLOR = new Color(0, 0, 200);        // Blue for headers
    private static final Color STATUS_SUCCESS_COLOR = new Color(0, 150, 0); // Green for 2xx
    private static final Color STATUS_ERROR_COLOR = new Color(200, 0, 0);   // Red for 4xx/5xx
    private static final Color BODY_COLOR = Color.BLACK;                    // Black for body
    private static final Color BACKGROUND_COLOR = new Color(250, 250, 250); // Light gray background
    private static final Color SEARCH_HIGHLIGHT_COLOR = new Color(255, 255, 0); // Yellow for search results
    private static final Color CURRENT_SEARCH_COLOR = new Color(255, 165, 0);   // Orange for current result
    
    /**
     * Inner class to store search result positions.
     */
    private static class SearchResult {
        int start;
        int end;
        
        SearchResult(int start, int end) {
            this.start = start;
            this.end = end;
        }
    }
    
    public HttpMessageViewer() {
        setLayout(new BorderLayout());
        
        // Create text panes with syntax highlighting
        requestPane = createStyledTextPane();
        responsePane = createStyledTextPane();
        
        // Create scroll panes
        JScrollPane requestScroll = new JScrollPane(requestPane);
        JScrollPane responseScroll = new JScrollPane(responsePane);
        
        // Add titles
        JPanel requestPanel = createTitledPanel("REQUEST", requestScroll);
        JPanel responsePanel = createTitledPanel("RESPONSE", responseScroll);
        
        // Create split pane (side-by-side)
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        splitPane.setDividerLocation(0.5);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerSize(5);
        
        // Create search panel
        searchPanel = createSearchPanel();
        searchPanel.setVisible(true); // Visible by default for easy access
        
        add(searchPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        
        // Add keyboard shortcut for search (Ctrl+F / Cmd+F)
        setupKeyboardShortcuts();
    }
    
    /**
     * Creates the search panel with search field and navigation buttons.
     */
    private JPanel createSearchPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        panel.setBackground(VistaTheme.BG_CARD);
        panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, VistaTheme.BORDER));
        
        // Search label
        JLabel searchLabel = new JLabel("Search:");
        searchLabel.setFont(VistaTheme.FONT_LABEL);
        searchLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        panel.add(searchLabel);
        
        // Search field
        searchField = new JTextField(20);
        VistaTheme.styleTextField(searchField);
        searchField.addActionListener(e -> performSearch());
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.getKeyCode() != KeyEvent.VK_ENTER) {
                    performSearch();
                }
            }
        });
        panel.add(searchField);
        
        // Case sensitive checkbox
        caseSensitiveCheckbox = new JCheckBox("Match case");
        caseSensitiveCheckbox.setFont(VistaTheme.FONT_SMALL);
        caseSensitiveCheckbox.setForeground(VistaTheme.TEXT_SECONDARY);
        caseSensitiveCheckbox.setBackground(panel.getBackground());
        caseSensitiveCheckbox.addActionListener(e -> performSearch());
        panel.add(caseSensitiveCheckbox);
        
        // Previous button
        prevButton = VistaTheme.compactButton("< Prev");
        prevButton.setFocusable(false);
        prevButton.addActionListener(e -> navigateToPrevious());
        panel.add(prevButton);
        
        // Next button
        nextButton = VistaTheme.compactButton("Next >");
        nextButton.setFocusable(false);
        nextButton.addActionListener(e -> navigateToNext());
        panel.add(nextButton);
        
        // Result label
        searchResultLabel = new JLabel("");
        searchResultLabel.setFont(VistaTheme.FONT_SMALL);
        searchResultLabel.setForeground(VistaTheme.TEXT_MUTED);
        panel.add(searchResultLabel);
        
        return panel;
    }
    
    /**
     * Sets up keyboard shortcuts for search.
     */
    private void setupKeyboardShortcuts() {
        // Ctrl+F (Windows/Linux) or Cmd+F (Mac) to show search
        int modifier = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        
        KeyStroke searchKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_F, modifier);
        
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(searchKeyStroke, "showSearch");
        getActionMap().put("showSearch", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showSearch();
            }
        });
        
        // F3 for next result
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), "nextResult");
        getActionMap().put("nextResult", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (searchPanel.isVisible()) {
                    navigateToNext();
                }
            }
        });
        
        // Shift+F3 for previous result
        getInputMap(WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_F3, InputEvent.SHIFT_DOWN_MASK), "prevResult");
        getActionMap().put("prevResult", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (searchPanel.isVisible()) {
                    navigateToPrevious();
                }
            }
        });
    }
    
    /**
     * Shows the search panel and focuses the search field.
     */
    public void showSearch() {
        searchPanel.setVisible(true);
        searchField.requestFocusInWindow();
        searchField.selectAll();
    }
    
    /**
     * Hides the search panel and clears highlights.
     */
    public void hideSearch() {
        searchPanel.setVisible(false);
        clearSearchHighlights();
        requestSearchResults.clear();
        responseSearchResults.clear();
        currentRequestResultIndex = -1;
        currentResponseResultIndex = -1;
        searchResultLabel.setText("");
    }
    
    /**
     * Performs search in both request and response panes.
     */
    private void performSearch() {
        String searchText = searchField.getText();
        
        if (searchText.isEmpty()) {
            clearSearchHighlights();
            requestSearchResults.clear();
            responseSearchResults.clear();
            searchResultLabel.setText("");
            return;
        }
        
        // Clear previous highlights
        clearSearchHighlights();
        
        // Search in request
        requestSearchResults = searchInPane(requestPane, searchText);
        
        // Search in response
        responseSearchResults = searchInPane(responsePane, searchText);
        
        // Highlight all results
        highlightSearchResults(requestPane, requestSearchResults, false);
        highlightSearchResults(responsePane, responseSearchResults, false);
        
        // Update result label
        int totalResults = requestSearchResults.size() + responseSearchResults.size();
        if (totalResults > 0) {
            searchResultLabel.setText(totalResults + " result" + (totalResults != 1 ? "s" : "") + " found");
            
            // Navigate to first result
            if (!requestSearchResults.isEmpty()) {
                currentSearchPane = requestPane;
                currentRequestResultIndex = 0;
                highlightCurrentResult();
            } else if (!responseSearchResults.isEmpty()) {
                currentSearchPane = responsePane;
                currentResponseResultIndex = 0;
                highlightCurrentResult();
            }
        } else {
            searchResultLabel.setText("No results found");
        }
    }
    
    /**
     * Searches for text in a pane and returns list of result positions.
     */
    private List<SearchResult> searchInPane(JTextPane pane, String searchText) {
        List<SearchResult> results = new ArrayList<>();
        
        try {
            String content = pane.getDocument().getText(0, pane.getDocument().getLength());
            String searchContent = content;
            String searchFor = searchText;
            
            if (!caseSensitiveCheckbox.isSelected()) {
                searchContent = content.toLowerCase();
                searchFor = searchText.toLowerCase();
            }
            
            int index = 0;
            while ((index = searchContent.indexOf(searchFor, index)) != -1) {
                results.add(new SearchResult(index, index + searchText.length()));
                index += searchText.length();
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
        
        return results;
    }
    
    /**
     * Highlights search results in a pane.
     */
    private void highlightSearchResults(JTextPane pane, List<SearchResult> results, boolean highlightCurrent) {
        Highlighter highlighter = pane.getHighlighter();
        
        try {
            for (int i = 0; i < results.size(); i++) {
                SearchResult result = results.get(i);
                
                // Use different color for current result
                boolean isCurrent = false;
                if (pane == requestPane && i == currentRequestResultIndex) {
                    isCurrent = true;
                } else if (pane == responsePane && i == currentResponseResultIndex) {
                    isCurrent = true;
                }
                
                Color highlightColor = (isCurrent && highlightCurrent) ? CURRENT_SEARCH_COLOR : SEARCH_HIGHLIGHT_COLOR;
                highlighter.addHighlight(result.start, result.end, 
                    new DefaultHighlighter.DefaultHighlightPainter(highlightColor));
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Clears all search highlights.
     */
    private void clearSearchHighlights() {
        requestPane.getHighlighter().removeAllHighlights();
        responsePane.getHighlighter().removeAllHighlights();
        
        // Re-apply syntax highlighting
        if (requestPane.getDocument().getLength() > 0) {
            try {
                String text = requestPane.getDocument().getText(0, requestPane.getDocument().getLength());
                displayRequest(text);
            } catch (BadLocationException e) {
                // Ignore
            }
        }
        
        if (responsePane.getDocument().getLength() > 0) {
            try {
                String text = responsePane.getDocument().getText(0, responsePane.getDocument().getLength());
                displayResponse(text);
            } catch (BadLocationException e) {
                // Ignore
            }
        }
    }
    
    /**
     * Highlights the current search result.
     */
    private void highlightCurrentResult() {
        clearSearchHighlights();
        highlightSearchResults(requestPane, requestSearchResults, true);
        highlightSearchResults(responsePane, responseSearchResults, true);
        
        // Scroll to current result
        if (currentSearchPane == requestPane && currentRequestResultIndex >= 0 && 
            currentRequestResultIndex < requestSearchResults.size()) {
            SearchResult result = requestSearchResults.get(currentRequestResultIndex);
            requestPane.setCaretPosition(result.start);
            requestPane.moveCaretPosition(result.end);
            
            int totalResults = requestSearchResults.size() + responseSearchResults.size();
            int currentPos = currentRequestResultIndex + 1;
            searchResultLabel.setText(currentPos + " of " + totalResults + " results");
            
        } else if (currentSearchPane == responsePane && currentResponseResultIndex >= 0 && 
                   currentResponseResultIndex < responseSearchResults.size()) {
            SearchResult result = responseSearchResults.get(currentResponseResultIndex);
            responsePane.setCaretPosition(result.start);
            responsePane.moveCaretPosition(result.end);
            
            int totalResults = requestSearchResults.size() + responseSearchResults.size();
            int currentPos = requestSearchResults.size() + currentResponseResultIndex + 1;
            searchResultLabel.setText(currentPos + " of " + totalResults + " results");
        }
    }
    
    /**
     * Navigates to the next search result.
     */
    private void navigateToNext() {
        if (requestSearchResults.isEmpty() && responseSearchResults.isEmpty()) {
            return;
        }
        
        if (currentSearchPane == requestPane) {
            if (currentRequestResultIndex < requestSearchResults.size() - 1) {
                currentRequestResultIndex++;
            } else if (!responseSearchResults.isEmpty()) {
                // Move to response pane
                currentSearchPane = responsePane;
                currentResponseResultIndex = 0;
            } else {
                // Wrap to beginning
                currentRequestResultIndex = 0;
            }
        } else if (currentSearchPane == responsePane) {
            if (currentResponseResultIndex < responseSearchResults.size() - 1) {
                currentResponseResultIndex++;
            } else if (!requestSearchResults.isEmpty()) {
                // Wrap to request pane
                currentSearchPane = requestPane;
                currentRequestResultIndex = 0;
            } else {
                // Wrap to beginning
                currentResponseResultIndex = 0;
            }
        }
        
        highlightCurrentResult();
    }
    
    /**
     * Navigates to the previous search result.
     */
    private void navigateToPrevious() {
        if (requestSearchResults.isEmpty() && responseSearchResults.isEmpty()) {
            return;
        }
        
        if (currentSearchPane == requestPane) {
            if (currentRequestResultIndex > 0) {
                currentRequestResultIndex--;
            } else if (!responseSearchResults.isEmpty()) {
                // Move to response pane (last result)
                currentSearchPane = responsePane;
                currentResponseResultIndex = responseSearchResults.size() - 1;
            } else {
                // Wrap to end
                currentRequestResultIndex = requestSearchResults.size() - 1;
            }
        } else if (currentSearchPane == responsePane) {
            if (currentResponseResultIndex > 0) {
                currentResponseResultIndex--;
            } else if (!requestSearchResults.isEmpty()) {
                // Wrap to request pane (last result)
                currentSearchPane = requestPane;
                currentRequestResultIndex = requestSearchResults.size() - 1;
            } else {
                // Wrap to end
                currentResponseResultIndex = responseSearchResults.size() - 1;
            }
        }
        
        highlightCurrentResult();
    }
    
    /**
     * Creates a styled text pane with professional font and background.
     */
    private JTextPane createStyledTextPane() {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setBackground(BACKGROUND_COLOR);
        pane.setFont(VistaTheme.FONT_MONO);
        pane.setMargin(new Insets(4, 6, 4, 6));
        
        return pane;
    }
    
    /**
     * Creates a panel with title label.
     */
    private JPanel createTitledPanel(String title, JComponent content) {
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("  " + title);
        titleLabel.setFont(VistaTheme.FONT_SMALL_BOLD);
        titleLabel.setForeground(VistaTheme.TEXT_SECONDARY);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(4, 5, 4, 5));
        titleLabel.setBackground(VistaTheme.BG_CARD);
        titleLabel.setOpaque(true);
        
        panel.add(titleLabel, BorderLayout.NORTH);
        panel.add(content, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Sets the HTTP request and response to display.
     * 
     * @param request Raw HTTP request bytes
     * @param response Raw HTTP response bytes
     */
    public void setHttpMessage(byte[] request, byte[] response) {
        if (request != null && request.length > 0) {
            String requestStr = new String(request);
            displayRequest(requestStr);
        } else {
            requestPane.setText("(No request data available)");
        }
        
        if (response != null && response.length > 0) {
            String responseStr = new String(response);
            // Truncate if too large
            if (responseStr.length() > 50000) {
                responseStr = responseStr.substring(0, 50000) + "\n\n... (Response truncated - showing first 50KB)";
            }
            displayResponse(responseStr);
        } else {
            responsePane.setText("(No response data available)");
        }
    }
    
    /**
     * Displays HTTP request with syntax highlighting.
     */
    private void displayRequest(String request) {
        StyledDocument doc = requestPane.getStyledDocument();
        
        try {
            doc.remove(0, doc.getLength());
            
            String[] lines = request.split("\n", -1);
            boolean inBody = false;
            
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                
                // Detect body start (empty line after headers)
                if (!inBody && line.trim().isEmpty() && i > 0) {
                    inBody = true;
                    doc.insertString(doc.getLength(), line + "\n", null);
                    continue;
                }
                
                if (!inBody) {
                    // First line (request line) - bold blue
                    if (i == 0) {
                        SimpleAttributeSet attrs = new SimpleAttributeSet();
                        StyleConstants.setForeground(attrs, HEADER_COLOR);
                        StyleConstants.setBold(attrs, true);
                        doc.insertString(doc.getLength(), line + "\n", attrs);
                    } else {
                        // Header lines - blue
                        SimpleAttributeSet attrs = new SimpleAttributeSet();
                        StyleConstants.setForeground(attrs, HEADER_COLOR);
                        doc.insertString(doc.getLength(), line + "\n", attrs);
                    }
                } else {
                    // Body - black
                    SimpleAttributeSet attrs = new SimpleAttributeSet();
                    StyleConstants.setForeground(attrs, BODY_COLOR);
                    doc.insertString(doc.getLength(), line + "\n", attrs);
                }
            }
            
            requestPane.setCaretPosition(0);
            
        } catch (BadLocationException e) {
            requestPane.setText(request);
        }
    }
    
    /**
     * Displays HTTP response with syntax highlighting.
     */
    private void displayResponse(String response) {
        StyledDocument doc = responsePane.getStyledDocument();
        
        try {
            doc.remove(0, doc.getLength());
            
            String[] lines = response.split("\n", -1);
            boolean inBody = false;
            
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                
                // Detect body start (empty line after headers)
                if (!inBody && line.trim().isEmpty() && i > 0) {
                    inBody = true;
                    doc.insertString(doc.getLength(), line + "\n", null);
                    continue;
                }
                
                if (!inBody) {
                    // First line (status line) - colored based on status code
                    if (i == 0) {
                        SimpleAttributeSet attrs = new SimpleAttributeSet();
                        
                        // Extract status code
                        int statusCode = extractStatusCode(line);
                        if (statusCode >= 200 && statusCode < 300) {
                            StyleConstants.setForeground(attrs, STATUS_SUCCESS_COLOR);
                        } else if (statusCode >= 400) {
                            StyleConstants.setForeground(attrs, STATUS_ERROR_COLOR);
                        } else {
                            StyleConstants.setForeground(attrs, HEADER_COLOR);
                        }
                        StyleConstants.setBold(attrs, true);
                        doc.insertString(doc.getLength(), line + "\n", attrs);
                    } else {
                        // Header lines - blue
                        SimpleAttributeSet attrs = new SimpleAttributeSet();
                        StyleConstants.setForeground(attrs, HEADER_COLOR);
                        doc.insertString(doc.getLength(), line + "\n", attrs);
                    }
                } else {
                    // Body - black
                    SimpleAttributeSet attrs = new SimpleAttributeSet();
                    StyleConstants.setForeground(attrs, BODY_COLOR);
                    doc.insertString(doc.getLength(), line + "\n", attrs);
                }
            }
            
            responsePane.setCaretPosition(0);
            
        } catch (BadLocationException e) {
            responsePane.setText(response);
        }
    }
    
    /**
     * Extracts status code from HTTP status line.
     */
    private int extractStatusCode(String statusLine) {
        try {
            String[] parts = statusLine.split(" ");
            if (parts.length >= 2) {
                return Integer.parseInt(parts[1]);
            }
        } catch (Exception e) {
            // Ignore
        }
        return 0;
    }
    
    /**
     * Clears both request and response panes.
     */
    public void clear() {
        requestPane.setText("");
        responsePane.setText("");
    }
    
    /**
     * Sets the divider location (0.0 to 1.0).
     */
    public void setDividerLocation(double proportion) {
        splitPane.setDividerLocation(proportion);
    }
}
