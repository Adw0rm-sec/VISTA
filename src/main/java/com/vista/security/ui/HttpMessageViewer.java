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
    
    // Color scheme (Burp Suite inspired — professional HTTP display)
    private static final Color HTTP_METHOD_COLOR     = new Color(59, 130, 246);    // Blue — GET, POST, PUT
    private static final Color HTTP_PATH_COLOR       = new Color(15, 23, 42);      // Dark — /api/users
    private static final Color HTTP_VERSION_COLOR    = new Color(100, 116, 139);   // Gray — HTTP/1.1
    private static final Color HEADER_NAME_COLOR     = new Color(147, 51, 234);    // Purple — header names
    private static final Color HEADER_VALUE_COLOR    = new Color(15, 23, 42);      // Dark — header values
    private static final Color HEADER_COLON_COLOR    = new Color(100, 116, 139);   // Gray — colon separator
    private static final Color PARAM_NAME_COLOR      = new Color(234, 88, 12);     // Orange — parameter names
    private static final Color PARAM_VALUE_COLOR     = new Color(22, 163, 74);     // Green — parameter values
    private static final Color PARAM_SEPARATOR_COLOR = new Color(148, 163, 184);   // Gray — &, =
    private static final Color STATUS_SUCCESS_COLOR  = new Color(22, 163, 74);     // Green for 2xx
    private static final Color STATUS_REDIRECT_COLOR = new Color(202, 138, 4);     // Yellow for 3xx
    private static final Color STATUS_CLIENT_COLOR   = new Color(234, 88, 12);     // Orange for 4xx
    private static final Color STATUS_ERROR_COLOR    = new Color(220, 38, 38);     // Red for 5xx
    private static final Color BODY_COLOR            = new Color(15, 23, 42);      // Dark — body text
    private static final Color BACKGROUND_COLOR      = new Color(250, 250, 250);   // Light gray background
    private static final Color SEARCH_HIGHLIGHT_COLOR = new Color(255, 255, 0);    // Yellow for search results
    private static final Color CURRENT_SEARCH_COLOR   = new Color(255, 165, 0);    // Orange for current result
    
    // JSON/XML pretty-print colors
    private static final Color JSON_KEY_COLOR        = new Color(147, 51, 234);    // Purple — JSON keys
    private static final Color JSON_STRING_COLOR     = new Color(22, 163, 74);     // Green — string values
    private static final Color JSON_NUMBER_COLOR     = new Color(59, 130, 246);    // Blue — numbers
    private static final Color JSON_BOOL_COLOR       = new Color(234, 88, 12);     // Orange — true/false/null
    private static final Color JSON_BRACE_COLOR      = new Color(100, 116, 139);   // Gray — { } [ ]
    private static final Color XML_TAG_COLOR         = new Color(59, 130, 246);    // Blue — <tag>
    private static final Color XML_ATTR_NAME_COLOR   = new Color(234, 88, 12);     // Orange — attribute names
    private static final Color XML_ATTR_VALUE_COLOR  = new Color(22, 163, 74);     // Green — attribute values
    private static final Color XML_CONTENT_COLOR     = new Color(15, 23, 42);      // Dark — text content
    private static final Color HTML_TAG_COLOR        = new Color(59, 130, 246);    // Blue — HTML tags
    
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
        
        // CRITICAL: Set caret update policy to NEVER_UPDATE so that
        // document changes (insertString) don't auto-scroll the viewport.
        // Without this, the caret chases every insertString call during
        // displayRequest()/displayResponse(), causing the pane to jump
        // to the end and then snap back to 0 — making user scroll impossible.
        javax.swing.text.DefaultCaret caret = (javax.swing.text.DefaultCaret) pane.getCaret();
        caret.setUpdatePolicy(javax.swing.text.DefaultCaret.NEVER_UPDATE);
        
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
    
    // Track currently displayed message to avoid redundant re-renders
    // (which cause scroll position reset when table selection is restored)
    private int currentMessageHash = 0;
    
    /**
     * Sets the HTTP request and response to display.
     * Skips re-rendering if the same message is already displayed (prevents scroll reset).
     * 
     * @param request Raw HTTP request bytes
     * @param response Raw HTTP response bytes
     */
    public void setHttpMessage(byte[] request, byte[] response) {
        // Compute hash to detect if this is the same message already displayed
        int newHash = java.util.Arrays.hashCode(request) * 31 + java.util.Arrays.hashCode(response);
        if (newHash == currentMessageHash && currentMessageHash != 0) {
            return; // Same message — don't re-render, preserve scroll position
        }
        currentMessageHash = newHash;
        
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
     * Displays HTTP request with Burp-style syntax highlighting.
     * Colors: method (blue), path (dark), version (gray), header names (purple),
     * header values (dark), parameters (orange/green), body (dark).
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
                    if (i == 0) {
                        // Request line: GET /path?a=b HTTP/1.1
                        renderRequestLine(doc, line);
                    } else {
                        // Header lines: Name: Value
                        renderHeaderLine(doc, line);
                    }
                } else {
                    // Body — check for form-encoded parameters
                    if (line.contains("=") && !line.contains("<") && !line.contains("{")) {
                        renderQueryString(doc, line);
                        doc.insertString(doc.getLength(), "\n", null);
                    } else {
                        // Regular body text
                        SimpleAttributeSet attrs = new SimpleAttributeSet();
                        StyleConstants.setForeground(attrs, BODY_COLOR);
                        doc.insertString(doc.getLength(), line + "\n", attrs);
                    }
                }
            }
            
            // Scroll to top after document is fully built
            SwingUtilities.invokeLater(() -> requestPane.setCaretPosition(0));
            
        } catch (BadLocationException e) {
            requestPane.setText(request);
        }
    }
    
    /**
     * Renders the HTTP request line with color-coded method, path, query params, and version.
     * Example: GET /api/users?id=123&name=test HTTP/1.1
     */
    private void renderRequestLine(StyledDocument doc, String line) throws BadLocationException {
        String[] parts = line.split(" ", 3);
        
        // Method (blue, bold)
        SimpleAttributeSet methodAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(methodAttrs, HTTP_METHOD_COLOR);
        StyleConstants.setBold(methodAttrs, true);
        doc.insertString(doc.getLength(), parts.length > 0 ? parts[0] : "", methodAttrs);
        doc.insertString(doc.getLength(), " ", null);
        
        // Path + query string
        if (parts.length > 1) {
            String pathPart = parts[1];
            int queryIdx = pathPart.indexOf('?');
            
            if (queryIdx >= 0) {
                // Path before query
                SimpleAttributeSet pathAttrs = new SimpleAttributeSet();
                StyleConstants.setForeground(pathAttrs, HTTP_PATH_COLOR);
                StyleConstants.setBold(pathAttrs, true);
                doc.insertString(doc.getLength(), pathPart.substring(0, queryIdx), pathAttrs);
                
                // "?" separator
                SimpleAttributeSet sepAttrs = new SimpleAttributeSet();
                StyleConstants.setForeground(sepAttrs, PARAM_SEPARATOR_COLOR);
                doc.insertString(doc.getLength(), "?", sepAttrs);
                
                // Query parameters
                renderQueryString(doc, pathPart.substring(queryIdx + 1));
            } else {
                // Just path, no query
                SimpleAttributeSet pathAttrs = new SimpleAttributeSet();
                StyleConstants.setForeground(pathAttrs, HTTP_PATH_COLOR);
                StyleConstants.setBold(pathAttrs, true);
                doc.insertString(doc.getLength(), pathPart, pathAttrs);
            }
            doc.insertString(doc.getLength(), " ", null);
        }
        
        // HTTP version (gray)
        if (parts.length > 2) {
            SimpleAttributeSet verAttrs = new SimpleAttributeSet();
            StyleConstants.setForeground(verAttrs, HTTP_VERSION_COLOR);
            doc.insertString(doc.getLength(), parts[2].trim(), verAttrs);
        }
        
        doc.insertString(doc.getLength(), "\n", null);
    }
    
    /**
     * Renders a query string with color-coded parameter names and values.
     * Example: id=123&name=test → id (orange) = (gray) 123 (green) & (gray) name (orange) = (gray) test (green)
     */
    private void renderQueryString(StyledDocument doc, String queryString) throws BadLocationException {
        SimpleAttributeSet nameAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(nameAttrs, PARAM_NAME_COLOR);
        StyleConstants.setBold(nameAttrs, true);
        
        SimpleAttributeSet valueAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(valueAttrs, PARAM_VALUE_COLOR);
        
        SimpleAttributeSet sepAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(sepAttrs, PARAM_SEPARATOR_COLOR);
        
        String[] params = queryString.split("&");
        for (int p = 0; p < params.length; p++) {
            if (p > 0) {
                doc.insertString(doc.getLength(), "&", sepAttrs);
            }
            
            int eqIdx = params[p].indexOf('=');
            if (eqIdx >= 0) {
                doc.insertString(doc.getLength(), params[p].substring(0, eqIdx), nameAttrs);
                doc.insertString(doc.getLength(), "=", sepAttrs);
                doc.insertString(doc.getLength(), params[p].substring(eqIdx + 1), valueAttrs);
            } else {
                doc.insertString(doc.getLength(), params[p], nameAttrs);
            }
        }
    }
    
    /**
     * Renders a header line with color-coded name and value.
     * Example: Content-Type: application/json → Content-Type (purple) : (gray) application/json (dark)
     */
    private void renderHeaderLine(StyledDocument doc, String line) throws BadLocationException {
        int colonIdx = line.indexOf(':');
        
        if (colonIdx > 0) {
            // Header name (purple, bold)
            SimpleAttributeSet nameAttrs = new SimpleAttributeSet();
            StyleConstants.setForeground(nameAttrs, HEADER_NAME_COLOR);
            StyleConstants.setBold(nameAttrs, true);
            doc.insertString(doc.getLength(), line.substring(0, colonIdx), nameAttrs);
            
            // Colon (gray)
            SimpleAttributeSet colonAttrs = new SimpleAttributeSet();
            StyleConstants.setForeground(colonAttrs, HEADER_COLON_COLOR);
            doc.insertString(doc.getLength(), ":", colonAttrs);
            
            // Value (dark)
            SimpleAttributeSet valueAttrs = new SimpleAttributeSet();
            StyleConstants.setForeground(valueAttrs, HEADER_VALUE_COLOR);
            doc.insertString(doc.getLength(), line.substring(colonIdx + 1) + "\n", valueAttrs);
        } else {
            // Fallback — plain header
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, HEADER_NAME_COLOR);
            doc.insertString(doc.getLength(), line + "\n", attrs);
        }
    }
    
    /**
     * Displays HTTP response with Burp-style syntax highlighting and pretty-formatted body.
     * Status line: green (2xx), yellow (3xx), orange (4xx), red (5xx).
     * Headers: purple names, dark values.
     * Body: Pretty-formatted JSON/HTML/XML with syntax coloring.
     */
    private void displayResponse(String response) {
        StyledDocument doc = responsePane.getStyledDocument();
        
        try {
            doc.remove(0, doc.getLength());
            
            String[] lines = response.split("\n", -1);
            boolean inBody = false;
            int bodyStartIdx = 0;
            String contentType = "";
            
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                
                // Detect body start (empty line after headers)
                if (!inBody && line.trim().isEmpty() && i > 0) {
                    inBody = true;
                    bodyStartIdx = i + 1;
                    doc.insertString(doc.getLength(), line + "\n", null);
                    continue;
                }
                
                if (!inBody) {
                    // First line (status line) - colored based on status code
                    if (i == 0) {
                        renderStatusLine(doc, line);
                    } else {
                        // Header lines — extract Content-Type for pretty formatting
                        String lowerLine = line.toLowerCase();
                        if (lowerLine.startsWith("content-type:")) {
                            contentType = line.substring(13).trim().toLowerCase();
                        }
                        renderHeaderLine(doc, line);
                    }
                } else {
                    // Body — we hit the first body line, now render entire body at once
                    // Collect remaining body
                    StringBuilder bodyBuilder = new StringBuilder();
                    for (int j = i; j < lines.length; j++) {
                        if (j > i) bodyBuilder.append("\n");
                        bodyBuilder.append(lines[j]);
                    }
                    String body = bodyBuilder.toString();
                    
                    renderBody(doc, body, contentType);
                    break; // We processed all remaining lines
                }
            }
            
            // Scroll to top after document is fully built
            SwingUtilities.invokeLater(() -> responsePane.setCaretPosition(0));
            
        } catch (BadLocationException e) {
            responsePane.setText(response);
        }
    }
    
    /**
     * Renders the HTTP status line with color based on status code.
     * Example: HTTP/1.1 200 OK → version (gray) + status (green, bold)
     */
    private void renderStatusLine(StyledDocument doc, String line) throws BadLocationException {
        int statusCode = extractStatusCode(line);
        
        Color statusColor;
        if (statusCode >= 200 && statusCode < 300) {
            statusColor = STATUS_SUCCESS_COLOR;
        } else if (statusCode >= 300 && statusCode < 400) {
            statusColor = STATUS_REDIRECT_COLOR;
        } else if (statusCode >= 400 && statusCode < 500) {
            statusColor = STATUS_CLIENT_COLOR;
        } else if (statusCode >= 500) {
            statusColor = STATUS_ERROR_COLOR;
        } else {
            statusColor = HTTP_VERSION_COLOR;
        }
        
        // Find where version ends and status begins
        String[] parts = line.split(" ", 3);
        
        // HTTP version (gray)
        SimpleAttributeSet verAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(verAttrs, HTTP_VERSION_COLOR);
        doc.insertString(doc.getLength(), parts.length > 0 ? parts[0] : "", verAttrs);
        doc.insertString(doc.getLength(), " ", null);
        
        // Status code + reason (colored, bold)
        SimpleAttributeSet statusAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(statusAttrs, statusColor);
        StyleConstants.setBold(statusAttrs, true);
        String statusPart = parts.length > 1 ? parts[1] : "";
        if (parts.length > 2) statusPart += " " + parts[2].trim();
        doc.insertString(doc.getLength(), statusPart + "\n", statusAttrs);
    }
    
    /**
     * Renders the response body with pretty formatting based on content type.
     * Supports: JSON (indented + colored), HTML/XML (indented + tag coloring), plain text.
     */
    private void renderBody(StyledDocument doc, String body, String contentType) throws BadLocationException {
        String trimmedBody = body.trim();
        
        if (trimmedBody.isEmpty()) {
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, VistaTheme.TEXT_MUTED);
            StyleConstants.setItalic(attrs, true);
            doc.insertString(doc.getLength(), "(empty body)\n", attrs);
            return;
        }
        
        // Auto-detect format from content or content-type
        boolean isJson = contentType.contains("json") || 
                         (trimmedBody.startsWith("{") || trimmedBody.startsWith("["));
        boolean isXml = contentType.contains("xml") && !contentType.contains("html");
        boolean isHtml = contentType.contains("html") || 
                         trimmedBody.toLowerCase().startsWith("<!doctype") ||
                         trimmedBody.toLowerCase().startsWith("<html");
        
        if (isJson) {
            renderJsonBody(doc, trimmedBody);
        } else if (isXml) {
            renderXmlHtmlBody(doc, trimmedBody, false);
        } else if (isHtml) {
            renderXmlHtmlBody(doc, trimmedBody, true);
        } else {
            // Plain text body
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setForeground(attrs, BODY_COLOR);
            doc.insertString(doc.getLength(), body + "\n", attrs);
        }
    }
    
    /**
     * Pretty-prints and syntax-highlights a JSON body.
     * Colors: keys (purple), strings (green), numbers (blue), booleans (orange), braces (gray).
     */
    private void renderJsonBody(StyledDocument doc, String json) throws BadLocationException {
        // Pretty-format first
        String pretty = prettyFormatJson(json);
        
        // Now render with syntax highlighting
        SimpleAttributeSet keyAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(keyAttrs, JSON_KEY_COLOR);
        StyleConstants.setBold(keyAttrs, true);
        
        SimpleAttributeSet stringAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(stringAttrs, JSON_STRING_COLOR);
        
        SimpleAttributeSet numberAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(numberAttrs, JSON_NUMBER_COLOR);
        
        SimpleAttributeSet boolAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(boolAttrs, JSON_BOOL_COLOR);
        StyleConstants.setBold(boolAttrs, true);
        
        SimpleAttributeSet braceAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(braceAttrs, JSON_BRACE_COLOR);
        
        SimpleAttributeSet defaultAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(defaultAttrs, BODY_COLOR);
        
        // Simple state machine to color JSON tokens
        int i = 0;
        int len = pretty.length();
        boolean inString = false;
        boolean isKey = false;
        boolean afterColon = false;
        
        while (i < len) {
            char c = pretty.charAt(i);
            
            if (c == '"' && !isEscaped(pretty, i)) {
                if (!inString) {
                    // Start of string — determine if key or value
                    inString = true;
                    isKey = !afterColon;
                    
                    // Find end of string
                    int end = findStringEnd(pretty, i + 1);
                    String str = pretty.substring(i, end + 1);
                    
                    doc.insertString(doc.getLength(), str, isKey ? keyAttrs : stringAttrs);
                    i = end + 1;
                    inString = false;
                    afterColon = false;
                    continue;
                }
            } else if (c == ':') {
                afterColon = true;
                doc.insertString(doc.getLength(), ": ", braceAttrs);
                i++;
                // Skip whitespace after colon
                while (i < len && pretty.charAt(i) == ' ') i++;
                continue;
            } else if (c == '{' || c == '}' || c == '[' || c == ']') {
                afterColon = false;
                doc.insertString(doc.getLength(), String.valueOf(c), braceAttrs);
                i++;
                continue;
            } else if (c == ',') {
                afterColon = false;
                doc.insertString(doc.getLength(), ",", braceAttrs);
                i++;
                continue;
            } else if (Character.isDigit(c) || (c == '-' && i + 1 < len && Character.isDigit(pretty.charAt(i + 1)))) {
                // Number
                int end = i + 1;
                while (end < len && (Character.isDigit(pretty.charAt(end)) || pretty.charAt(end) == '.' || pretty.charAt(end) == 'e' || pretty.charAt(end) == 'E' || pretty.charAt(end) == '+' || pretty.charAt(end) == '-')) {
                    end++;
                }
                doc.insertString(doc.getLength(), pretty.substring(i, end), numberAttrs);
                afterColon = false;
                i = end;
                continue;
            } else if (i + 4 <= len && pretty.substring(i, i + 4).equals("true")) {
                doc.insertString(doc.getLength(), "true", boolAttrs);
                afterColon = false;
                i += 4;
                continue;
            } else if (i + 5 <= len && pretty.substring(i, i + 5).equals("false")) {
                doc.insertString(doc.getLength(), "false", boolAttrs);
                afterColon = false;
                i += 5;
                continue;
            } else if (i + 4 <= len && pretty.substring(i, i + 4).equals("null")) {
                doc.insertString(doc.getLength(), "null", boolAttrs);
                afterColon = false;
                i += 4;
                continue;
            }
            
            // Default character (whitespace, newlines)
            doc.insertString(doc.getLength(), String.valueOf(c), defaultAttrs);
            if (c == '\n') afterColon = false;
            i++;
        }
    }
    
    /**
     * Pretty-prints and syntax-highlights HTML/XML body.
     * Tags in blue, attribute names in orange, attribute values in green, content in dark.
     */
    private void renderXmlHtmlBody(StyledDocument doc, String body, boolean isHtml) throws BadLocationException {
        // Pretty-format first
        String pretty = prettyFormatXmlHtml(body);
        
        SimpleAttributeSet tagAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(tagAttrs, isHtml ? HTML_TAG_COLOR : XML_TAG_COLOR);
        StyleConstants.setBold(tagAttrs, true);
        
        SimpleAttributeSet attrNameAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrNameAttrs, XML_ATTR_NAME_COLOR);
        
        SimpleAttributeSet attrValueAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(attrValueAttrs, XML_ATTR_VALUE_COLOR);
        
        SimpleAttributeSet contentAttrs = new SimpleAttributeSet();
        StyleConstants.setForeground(contentAttrs, XML_CONTENT_COLOR);
        
        // Simple parser: split on < and > to identify tags vs content
        int i = 0;
        int len = pretty.length();
        
        while (i < len) {
            char c = pretty.charAt(i);
            
            if (c == '<') {
                // Find end of tag
                int end = pretty.indexOf('>', i);
                if (end < 0) end = len - 1;
                
                String tag = pretty.substring(i, end + 1);
                renderTag(doc, tag, tagAttrs, attrNameAttrs, attrValueAttrs);
                i = end + 1;
            } else {
                // Content between tags
                int nextTag = pretty.indexOf('<', i);
                if (nextTag < 0) nextTag = len;
                
                String content = pretty.substring(i, nextTag);
                if (!content.isBlank()) {
                    doc.insertString(doc.getLength(), content, contentAttrs);
                } else {
                    doc.insertString(doc.getLength(), content, null);
                }
                i = nextTag;
            }
        }
    }
    
    /**
     * Renders a single HTML/XML tag with colored attributes.
     */
    private void renderTag(StyledDocument doc, String tag, 
                          SimpleAttributeSet tagAttrs, SimpleAttributeSet attrNameAttrs,
                          SimpleAttributeSet attrValueAttrs) throws BadLocationException {
        // Simple approach: find first space (tag name end), then parse attributes
        int spaceIdx = -1;
        for (int i = 1; i < tag.length(); i++) {
            if (Character.isWhitespace(tag.charAt(i))) {
                spaceIdx = i;
                break;
            }
        }
        
        if (spaceIdx < 0 || tag.startsWith("<!") || tag.startsWith("<?")) {
            // No attributes — render whole tag
            doc.insertString(doc.getLength(), tag, tagAttrs);
            return;
        }
        
        // Tag name (e.g., <div)
        doc.insertString(doc.getLength(), tag.substring(0, spaceIdx), tagAttrs);
        
        // Attributes part
        String attrPart = tag.substring(spaceIdx, tag.length() - (tag.endsWith("/>") ? 2 : 1));
        
        // Simple attribute parser
        int i = 0;
        int attrLen = attrPart.length();
        while (i < attrLen) {
            char c = attrPart.charAt(i);
            
            if (Character.isWhitespace(c)) {
                doc.insertString(doc.getLength(), " ", null);
                i++;
            } else if (c == '=') {
                doc.insertString(doc.getLength(), "=", tagAttrs);
                i++;
            } else if (c == '"' || c == '\'') {
                // Attribute value
                char quote = c;
                int end = attrPart.indexOf(quote, i + 1);
                if (end < 0) end = attrLen - 1;
                doc.insertString(doc.getLength(), attrPart.substring(i, end + 1), attrValueAttrs);
                i = end + 1;
            } else {
                // Attribute name
                int end = i;
                while (end < attrLen && !Character.isWhitespace(attrPart.charAt(end)) && attrPart.charAt(end) != '=') {
                    end++;
                }
                doc.insertString(doc.getLength(), attrPart.substring(i, end), attrNameAttrs);
                i = end;
            }
        }
        
        // Closing bracket
        doc.insertString(doc.getLength(), tag.endsWith("/>") ? "/>" : ">", tagAttrs);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Pretty-Format Helpers
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Pretty-formats a JSON string with proper indentation.
     */
    private String prettyFormatJson(String json) {
        if (json == null || json.isEmpty()) return json;
        
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            
            if (c == '"' && !isEscaped(json, i)) {
                inString = !inString;
                sb.append(c);
            } else if (inString) {
                sb.append(c);
            } else if (c == '{' || c == '[') {
                sb.append(c);
                // Check if empty object/array
                int next = skipWhitespace(json, i + 1);
                if (next < json.length() && (json.charAt(next) == '}' || json.charAt(next) == ']')) {
                    sb.append(json.charAt(next));
                    i = next;
                    continue;
                }
                indent++;
                sb.append('\n');
                appendIndent(sb, indent);
            } else if (c == '}' || c == ']') {
                indent--;
                sb.append('\n');
                appendIndent(sb, indent);
                sb.append(c);
            } else if (c == ',') {
                sb.append(",\n");
                appendIndent(sb, indent);
            } else if (c == ':') {
                sb.append(": ");
            } else if (!Character.isWhitespace(c)) {
                sb.append(c);
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Pretty-formats HTML/XML with proper indentation.
     * Handles &lt;style&gt; and &lt;script&gt; blocks as raw content
     * (does not try to parse CSS/JS as HTML tags).
     */
    private String prettyFormatXmlHtml(String xml) {
        if (xml == null || xml.isEmpty()) return xml;
        
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        int i = 0;
        
        // Track whether we're inside a <style> or <script> raw block
        boolean inRawBlock = false;
        String rawClosingTag = "";
        
        while (i < xml.length()) {
            if (inRawBlock) {
                // Inside <style> or <script>: find the matching closing tag
                int closeIdx = xml.toLowerCase().indexOf(rawClosingTag, i);
                if (closeIdx < 0) {
                    // No closing tag found — dump the rest as raw content
                    String remaining = xml.substring(i).trim();
                    if (!remaining.isEmpty()) {
                        // Indent each line of the raw content
                        for (String rawLine : remaining.split("\n")) {
                            String trimmedRaw = rawLine.trim();
                            if (!trimmedRaw.isEmpty()) {
                                sb.append('\n');
                                appendIndent(sb, indent);
                                sb.append(trimmedRaw);
                            }
                        }
                    }
                    break;
                }
                
                // Extract raw content between opening and closing tag
                String rawContent = xml.substring(i, closeIdx);
                
                // Output each non-empty line with proper indentation
                for (String rawLine : rawContent.split("\n")) {
                    String trimmedRaw = rawLine.trim();
                    if (!trimmedRaw.isEmpty()) {
                        sb.append('\n');
                        appendIndent(sb, indent);
                        sb.append(trimmedRaw);
                    }
                }
                
                // Output the closing tag
                indent = Math.max(0, indent - 1);
                int closeEnd = xml.indexOf('>', closeIdx);
                if (closeEnd < 0) closeEnd = xml.length() - 1;
                String closeTag = xml.substring(closeIdx, closeEnd + 1);
                sb.append('\n');
                appendIndent(sb, indent);
                sb.append(closeTag);
                
                i = closeEnd + 1;
                inRawBlock = false;
                continue;
            }
            
            if (xml.charAt(i) == '<') {
                int end = xml.indexOf('>', i);
                if (end < 0) {
                    sb.append(xml.substring(i));
                    break;
                }
                
                String tag = xml.substring(i, end + 1);
                String trimmedTag = tag.trim();
                String lowerTag = trimmedTag.toLowerCase();
                
                boolean isClosing = trimmedTag.startsWith("</");
                boolean isSelfClosing = trimmedTag.endsWith("/>");
                boolean isComment = trimmedTag.startsWith("<!--");
                boolean isDoctype = trimmedTag.startsWith("<!");
                boolean isProcessing = trimmedTag.startsWith("<?");
                
                if (isClosing) {
                    indent = Math.max(0, indent - 1);
                }
                
                sb.append('\n');
                appendIndent(sb, indent);
                sb.append(tag);
                
                if (!isClosing && !isSelfClosing && !isComment && !isDoctype && !isProcessing) {
                    indent++;
                }
                
                // Check if this is a <style> or <script> opening tag
                // → treat everything until closing tag as raw content
                if (!isClosing && !isSelfClosing) {
                    if (lowerTag.startsWith("<style") || lowerTag.startsWith("<script")) {
                        inRawBlock = true;
                        rawClosingTag = lowerTag.startsWith("<style") ? "</style" : "</script";
                    }
                }
                
                i = end + 1;
            } else {
                // Text content
                int nextTag = xml.indexOf('<', i);
                if (nextTag < 0) nextTag = xml.length();
                
                String content = xml.substring(i, nextTag).trim();
                if (!content.isEmpty()) {
                    sb.append(content);
                }
                i = nextTag;
            }
        }
        
        // Remove leading newline
        String result = sb.toString();
        if (result.startsWith("\n")) result = result.substring(1);
        return result;
    }
    
    private boolean isEscaped(String s, int index) {
        int backslashes = 0;
        int i = index - 1;
        while (i >= 0 && s.charAt(i) == '\\') {
            backslashes++;
            i--;
        }
        return backslashes % 2 != 0;
    }
    
    private int findStringEnd(String s, int start) {
        for (int i = start; i < s.length(); i++) {
            if (s.charAt(i) == '"' && !isEscaped(s, i)) {
                return i;
            }
        }
        return s.length() - 1;
    }
    
    private int skipWhitespace(String s, int start) {
        while (start < s.length() && Character.isWhitespace(s.charAt(start))) {
            start++;
        }
        return start;
    }
    
    private void appendIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
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
