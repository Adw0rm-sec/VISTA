package com.vista.security.core;

import com.vista.security.model.ContentTypeCategory;
import com.vista.security.model.HttpTransaction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based and unit tests for TrafficFilterEngine.
 * 
 * Property 5: Content-Type Filter Correctness
 * Property 6: Multiple Content-Type Filter OR Logic
 * Property 7: Custom Pattern Filter Correctness
 * Property 8: HTTP Method Filter Correctness
 * Property 9: Multiple Method Filter OR Logic
 * Property 10: No Filter Shows All Transactions
 * 
 * Validates: Requirements 2.1-2.6, 3.1-3.8, 10.5
 */
public class TrafficFilterEngineTest {
    
    private TrafficFilterEngine filterEngine;
    
    @BeforeEach
    public void setUp() {
        filterEngine = new TrafficFilterEngine();
    }
    
    /**
     * Property Test: Content-Type Filter Correctness
     * 
     * For any transaction with content-type matching an enabled category,
     * the filter should include that transaction in results.
     * 
     * Validates: Requirements 2.1, 2.2, 2.3, 2.4
     */
    @Test
    public void testContentTypeFilterCorrectness() {
        // Arrange - Create transactions with different content types
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/app.js", 
                                          "application/javascript", 200));
        transactions.add(createTransaction("tx2", "GET", "https://example.com/data.json", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx3", "GET", "https://example.com/data.xml", 
                                          "application/xml", 200));
        transactions.add(createTransaction("tx4", "GET", "https://example.com/style.css", 
                                          "text/css", 200));
        transactions.add(createTransaction("tx5", "GET", "https://example.com/image.png", 
                                          "image/png", 200));
        transactions.add(createTransaction("tx6", "GET", "https://example.com/font.woff", 
                                          "font/woff", 200));
        transactions.add(createTransaction("tx7", "GET", "https://example.com/page.html", 
                                          "text/html", 200));
        
        // Test JavaScript filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.JAVASCRIPT, true);
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx1", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test JSON filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.JSON, true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx2", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test XML filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.XML, true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx3", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test CSS filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.CSS, true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx4", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test Images filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.IMAGES, true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx5", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test Fonts filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.FONTS, true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx6", filtered.get(0).getId());
    }
    
    /**
     * Property Test: Multiple Content-Type Filter OR Logic
     * 
     * For any set of enabled content-type filters, a transaction matching
     * ANY of the enabled filters should be included (OR logic).
     * 
     * Validates: Requirements 2.5
     */
    @Test
    public void testMultipleContentTypeFilterORLogic() {
        // Arrange - Create transactions with different content types
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/app.js", 
                                          "application/javascript", 200));
        transactions.add(createTransaction("tx2", "GET", "https://example.com/data.json", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx3", "GET", "https://example.com/data.xml", 
                                          "application/xml", 200));
        transactions.add(createTransaction("tx4", "GET", "https://example.com/page.html", 
                                          "text/html", 200));
        
        // Act - Enable JavaScript and JSON filters
        filterEngine.setContentTypeFilter(ContentTypeCategory.JAVASCRIPT, true);
        filterEngine.setContentTypeFilter(ContentTypeCategory.JSON, true);
        
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should get both JavaScript and JSON transactions
        assertEquals(2, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
        
        // Act - Add XML filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.XML, true);
        filtered = filterEngine.filter(transactions);
        
        // Assert - Should get JavaScript, JSON, and XML transactions
        assertEquals(3, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx3")));
    }
    
    /**
     * Property Test: HTTP Method Filter Correctness
     * 
     * For any transaction with HTTP method matching an enabled filter,
     * the filter should include that transaction in results.
     * 
     * Validates: Requirements 3.1-3.6
     */
    @Test
    public void testHTTPMethodFilterCorrectness() {
        // Arrange - Create transactions with different methods
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          "text/html", 200));
        transactions.add(createTransaction("tx2", "POST", "https://example.com/api", 
                                          "application/json", 201));
        transactions.add(createTransaction("tx3", "PUT", "https://example.com/api/1", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx4", "DELETE", "https://example.com/api/1", 
                                          "application/json", 204));
        transactions.add(createTransaction("tx5", "PATCH", "https://example.com/api/1", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx6", "OPTIONS", "https://example.com/api", 
                                          "text/plain", 200));
        
        // Test GET filter
        filterEngine.setMethodFilter("GET", true);
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx1", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test POST filter
        filterEngine.setMethodFilter("POST", true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx2", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test PUT filter
        filterEngine.setMethodFilter("PUT", true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx3", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test DELETE filter
        filterEngine.setMethodFilter("DELETE", true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx4", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test PATCH filter
        filterEngine.setMethodFilter("PATCH", true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx5", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test OPTIONS filter
        filterEngine.setMethodFilter("OPTIONS", true);
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx6", filtered.get(0).getId());
    }
    
    /**
     * Property Test: Multiple Method Filter OR Logic
     * 
     * For any set of enabled method filters, a transaction matching
     * ANY of the enabled methods should be included (OR logic).
     * 
     * Validates: Requirements 3.7
     */
    @Test
    public void testMultipleMethodFilterORLogic() {
        // Arrange - Create transactions with different methods
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          "text/html", 200));
        transactions.add(createTransaction("tx2", "POST", "https://example.com/api", 
                                          "application/json", 201));
        transactions.add(createTransaction("tx3", "PUT", "https://example.com/api/1", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx4", "DELETE", "https://example.com/api/1", 
                                          "application/json", 204));
        
        // Act - Enable GET and POST filters
        filterEngine.setMethodFilter("GET", true);
        filterEngine.setMethodFilter("POST", true);
        
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should get both GET and POST transactions
        assertEquals(2, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
        
        // Act - Add PUT filter
        filterEngine.setMethodFilter("PUT", true);
        filtered = filterEngine.filter(transactions);
        
        // Assert - Should get GET, POST, and PUT transactions
        assertEquals(3, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx3")));
    }
    
    /**
     * Property Test: No Filter Shows All Transactions
     * 
     * When no filters are enabled, all transactions should be shown.
     * 
     * Validates: Requirements 3.8
     */
    @Test
    public void testNoFilterShowsAllTransactions() {
        // Arrange - Create diverse transactions
        List<HttpTransaction> transactions = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            String method = (i % 2 == 0) ? "GET" : "POST";
            String contentType = (i % 3 == 0) ? "application/json" : "text/html";
            transactions.add(createTransaction("tx" + i, method, 
                                             "https://example.com/" + i, 
                                             contentType, 200));
        }
        
        // Act - Filter with no filters enabled
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should get all transactions
        assertEquals(100, filtered.size());
        assertEquals(transactions.size(), filtered.size());
    }
    
    /**
     * Property Test: Custom Pattern Filter Correctness
     * 
     * For any transaction with URL matching the custom regex pattern,
     * the filter should include that transaction in results.
     * 
     * Validates: Requirements 2.6
     */
    @Test
    public void testCustomPatternFilterCorrectness() throws PatternSyntaxException {
        // Arrange - Create transactions with different URLs
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/api/users", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx2", "GET", "https://example.com/api/products", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx3", "GET", "https://example.com/admin/settings", 
                                          "text/html", 200));
        transactions.add(createTransaction("tx4", "GET", "https://example.com/page.html", 
                                          "text/html", 200));
        
        // Test pattern matching "/api/"
        filterEngine.setCustomPattern("/api/");
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        assertEquals(2, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
        
        // Reset
        filterEngine.clearFilters();
        
        // Test pattern matching "/admin/"
        filterEngine.setCustomPattern("/admin/");
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx3", filtered.get(0).getId());
        
        // Reset
        filterEngine.clearFilters();
        
        // Test pattern matching ".html$"
        filterEngine.setCustomPattern("\\.html$");
        filtered = filterEngine.filter(transactions);
        assertEquals(1, filtered.size());
        assertEquals("tx4", filtered.get(0).getId());
    }
    
    /**
     * Test: Invalid regex pattern throws exception
     */
    @Test
    public void testInvalidRegexPatternThrowsException() {
        // Act & Assert
        assertThrows(PatternSyntaxException.class, () -> {
            filterEngine.setCustomPattern("[invalid(regex");
        });
    }
    
    /**
     * Test: Empty transaction list
     */
    @Test
    public void testEmptyTransactionList() {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        filterEngine.setMethodFilter("GET", true);
        
        // Act
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert
        assertTrue(filtered.isEmpty());
    }
    
    /**
     * Test: Missing Content-Type header
     */
    @Test
    public void testMissingContentTypeHeader() {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          null, 200)); // null content-type
        transactions.add(createTransaction("tx2", "GET", "https://example.com/data.json", 
                                          "application/json", 200));
        
        // Act - Enable JSON filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.JSON, true);
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should only get tx2
        assertEquals(1, filtered.size());
        assertEquals("tx2", filtered.get(0).getId());
    }
    
    /**
     * Test: Null transaction handling
     */
    @Test
    public void testNullTransactionHandling() {
        // Act
        boolean matches = filterEngine.matches(null);
        
        // Assert
        assertFalse(matches);
    }
    
    /**
     * Test: Null transaction list handling
     */
    @Test
    public void testNullTransactionListHandling() {
        // Act
        List<HttpTransaction> filtered = filterEngine.filter(null);
        
        // Assert
        assertNotNull(filtered);
        assertTrue(filtered.isEmpty());
    }
    
    /**
     * Test: Combined filters (content-type + method)
     */
    @Test
    public void testCombinedFilters() {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/data.json", 
                                          "application/json", 200));
        transactions.add(createTransaction("tx2", "POST", "https://example.com/api", 
                                          "application/json", 201));
        transactions.add(createTransaction("tx3", "GET", "https://example.com/page.html", 
                                          "text/html", 200));
        
        // Act - Enable JSON filter and POST filter
        filterEngine.setContentTypeFilter(ContentTypeCategory.JSON, true);
        filterEngine.setMethodFilter("POST", true);
        
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should get tx1 (JSON) and tx2 (POST) - OR logic
        assertEquals(2, filtered.size());
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx1")));
        assertTrue(filtered.stream().anyMatch(tx -> tx.getId().equals("tx2")));
    }
    
    /**
     * Test: Disable filter
     */
    @Test
    public void testDisableFilter() {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          "text/html", 200));
        transactions.add(createTransaction("tx2", "POST", "https://example.com/api", 
                                          "application/json", 201));
        
        // Act - Enable then disable GET filter
        filterEngine.setMethodFilter("GET", true);
        filterEngine.setMethodFilter("GET", false);
        
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - No filters enabled, should get all
        assertEquals(2, filtered.size());
    }
    
    /**
     * Test: Case-insensitive method matching
     */
    @Test
    public void testCaseInsensitiveMethodMatching() {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          "text/html", 200));
        
        // Act - Enable filter with lowercase
        filterEngine.setMethodFilter("get", true);
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Should match
        assertEquals(1, filtered.size());
        assertEquals("tx1", filtered.get(0).getId());
    }
    
    /**
     * Test: Clear custom pattern
     */
    @Test
    public void testClearCustomPattern() throws PatternSyntaxException {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/api/users", 
                                          "application/json", 200));
        
        // Act - Set then clear pattern
        filterEngine.setCustomPattern("/api/");
        filterEngine.setCustomPattern(null);
        
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - No filters, should get all
        assertEquals(1, filtered.size());
    }
    
    /**
     * Test: Empty string pattern
     */
    @Test
    public void testEmptyStringPattern() throws PatternSyntaxException {
        // Arrange
        List<HttpTransaction> transactions = new ArrayList<>();
        transactions.add(createTransaction("tx1", "GET", "https://example.com/page", 
                                          "text/html", 200));
        
        // Act - Set empty pattern
        filterEngine.setCustomPattern("");
        List<HttpTransaction> filtered = filterEngine.filter(transactions);
        
        // Assert - Empty pattern treated as null, no filters
        assertEquals(1, filtered.size());
    }
    
    // Helper methods
    
    private HttpTransaction createTransaction(String id, String method, String url, 
                                              String contentType, int statusCode) {
        return new HttpTransaction(
            id,
            System.currentTimeMillis(),
            method,
            url,
            contentType,
            statusCode,
            1024,
            new byte[0],
            new byte[0],
            null
        );
    }
}
