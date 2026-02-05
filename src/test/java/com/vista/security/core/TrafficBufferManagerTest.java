package com.vista.security.core;

import com.vista.security.model.HttpTransaction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based and unit tests for TrafficBufferManager.
 * 
 * Property 3: Circular Buffer FIFO Behavior
 * Property 21: Clear Empties Buffer
 * Validates: Requirements 1.3, 1.5, 7.3
 */
public class TrafficBufferManagerTest {
    
    private TrafficBufferManager bufferManager;
    
    @BeforeEach
    public void setUp() {
        bufferManager = new TrafficBufferManager(100);
    }
    
    /**
     * Property Test: Circular Buffer FIFO Behavior
     * 
     * For any Traffic_Buffer at maximum capacity, adding a new transaction
     * should result in the oldest transaction being removed, maintaining FIFO ordering.
     * 
     * Validates: Requirements 1.3
     */
    @Test
    public void testCircularBufferFIFOBehavior() {
        // Arrange - Create buffer with small capacity
        TrafficBufferManager smallBuffer = new TrafficBufferManager(3);
        
        HttpTransaction tx1 = createTransaction("tx1", "https://example.com/1");
        HttpTransaction tx2 = createTransaction("tx2", "https://example.com/2");
        HttpTransaction tx3 = createTransaction("tx3", "https://example.com/3");
        HttpTransaction tx4 = createTransaction("tx4", "https://example.com/4");
        
        // Act - Add transactions up to capacity
        smallBuffer.addTransaction(tx1);
        smallBuffer.addTransaction(tx2);
        smallBuffer.addTransaction(tx3);
        
        // Assert - Buffer should contain all 3
        assertEquals(3, smallBuffer.size());
        List<HttpTransaction> transactions = smallBuffer.getAllTransactions();
        assertEquals(tx1.getId(), transactions.get(0).getId());
        assertEquals(tx2.getId(), transactions.get(1).getId());
        assertEquals(tx3.getId(), transactions.get(2).getId());
        
        // Act - Add one more (should evict oldest)
        smallBuffer.addTransaction(tx4);
        
        // Assert - Buffer should still have 3, but tx1 should be gone
        assertEquals(3, smallBuffer.size());
        transactions = smallBuffer.getAllTransactions();
        assertEquals(tx2.getId(), transactions.get(0).getId()); // tx1 evicted
        assertEquals(tx3.getId(), transactions.get(1).getId());
        assertEquals(tx4.getId(), transactions.get(2).getId());
    }
    
    /**
     * Property Test: Clear Empties Buffer
     * 
     * For any state of the Traffic_Buffer, clicking the clear button
     * should result in an empty buffer with zero transactions.
     * 
     * Validates: Requirements 7.3
     */
    @Test
    public void testClearEmptiesBuffer() {
        // Arrange - Add multiple transactions
        for (int i = 0; i < 50; i++) {
            bufferManager.addTransaction(createTransaction("tx" + i, "https://example.com/" + i));
        }
        
        // Assert - Buffer should have transactions
        assertEquals(50, bufferManager.size());
        assertTrue(bufferManager.getTotalDataVolume() > 0);
        
        // Act - Clear buffer
        bufferManager.clear();
        
        // Assert - Buffer should be empty
        assertEquals(0, bufferManager.size());
        assertEquals(0, bufferManager.getTotalDataVolume());
        assertTrue(bufferManager.getAllTransactions().isEmpty());
    }
    
    /**
     * Test: Buffer at exactly max capacity
     */
    @Test
    public void testBufferAtMaxCapacity() {
        // Arrange
        TrafficBufferManager smallBuffer = new TrafficBufferManager(5);
        
        // Act - Add exactly max capacity
        for (int i = 0; i < 5; i++) {
            smallBuffer.addTransaction(createTransaction("tx" + i, "https://example.com/" + i));
        }
        
        // Assert
        assertEquals(5, smallBuffer.size());
        assertEquals(5, smallBuffer.getMaxCapacity());
    }
    
    /**
     * Test: Buffer with zero capacity (error case)
     */
    @Test
    public void testBufferWithZeroCapacity() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            new TrafficBufferManager(0);
        });
    }
    
    /**
     * Test: Concurrent access from multiple threads
     */
    @Test
    public void testConcurrentAccess() throws InterruptedException {
        // Arrange
        int numThreads = 10;
        int transactionsPerThread = 100;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(numThreads);
        
        // Act - Multiple threads adding transactions concurrently
        for (int i = 0; i < numThreads; i++) {
            final int threadId = i;
            new Thread(() -> {
                try {
                    startLatch.await(); // Wait for all threads to be ready
                    for (int j = 0; j < transactionsPerThread; j++) {
                        bufferManager.addTransaction(
                            createTransaction("thread" + threadId + "-tx" + j, 
                                            "https://example.com/" + threadId + "/" + j)
                        );
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            }).start();
        }
        
        // Start all threads at once
        startLatch.countDown();
        
        // Wait for all threads to complete
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS));
        
        // Assert - Buffer should be at max capacity (100)
        assertEquals(100, bufferManager.size());
        
        // Assert - No exceptions should have occurred (test passes if we get here)
        // Assert - All transactions should be retrievable
        List<HttpTransaction> transactions = bufferManager.getAllTransactions();
        assertEquals(100, transactions.size());
    }
    
    /**
     * Test: Listener notification on add
     */
    @Test
    public void testListenerNotificationOnAdd() throws InterruptedException {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger notificationCount = new AtomicInteger(0);
        
        bufferManager.addListener(new TrafficBufferListener() {
            @Override
            public void onTransactionAdded(HttpTransaction transaction) {
                notificationCount.incrementAndGet();
                latch.countDown();
            }
            
            @Override
            public void onBufferCleared() {
                // Not tested here
            }
        });
        
        // Act
        bufferManager.addTransaction(createTransaction("tx1", "https://example.com/1"));
        
        // Assert
        assertTrue(latch.await(1, TimeUnit.SECONDS));
        assertEquals(1, notificationCount.get());
    }
    
    /**
     * Test: Listener notification on clear
     */
    @Test
    public void testListenerNotificationOnClear() throws InterruptedException {
        // Arrange
        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger clearCount = new AtomicInteger(0);
        
        bufferManager.addListener(new TrafficBufferListener() {
            @Override
            public void onTransactionAdded(HttpTransaction transaction) {
                // Not tested here
            }
            
            @Override
            public void onBufferCleared() {
                clearCount.incrementAndGet();
                latch.countDown();
            }
        });
        
        // Add some transactions
        bufferManager.addTransaction(createTransaction("tx1", "https://example.com/1"));
        
        // Act
        bufferManager.clear();
        
        // Assert
        assertTrue(latch.await(1, TimeUnit.SECONDS));
        assertEquals(1, clearCount.get());
    }
    
    /**
     * Test: Get transactions with limit
     */
    @Test
    public void testGetTransactionsWithLimit() {
        // Arrange - Add 10 transactions
        for (int i = 0; i < 10; i++) {
            bufferManager.addTransaction(createTransaction("tx" + i, "https://example.com/" + i));
        }
        
        // Act
        List<HttpTransaction> recent = bufferManager.getTransactions(5);
        
        // Assert - Should get last 5
        assertEquals(5, recent.size());
        assertEquals("tx5", recent.get(0).getId());
        assertEquals("tx9", recent.get(4).getId());
    }
    
    /**
     * Test: Get transactions with limit larger than buffer
     */
    @Test
    public void testGetTransactionsWithLargeLimitReturnsAll() {
        // Arrange - Add 5 transactions
        for (int i = 0; i < 5; i++) {
            bufferManager.addTransaction(createTransaction("tx" + i, "https://example.com/" + i));
        }
        
        // Act
        List<HttpTransaction> all = bufferManager.getTransactions(100);
        
        // Assert - Should get all 5
        assertEquals(5, all.size());
    }
    
    /**
     * Test: Total data volume tracking
     */
    @Test
    public void testTotalDataVolumeTracking() {
        // Arrange
        HttpTransaction tx1 = createTransactionWithSize("tx1", 1024);
        HttpTransaction tx2 = createTransactionWithSize("tx2", 2048);
        HttpTransaction tx3 = createTransactionWithSize("tx3", 512);
        
        // Act
        bufferManager.addTransaction(tx1);
        bufferManager.addTransaction(tx2);
        bufferManager.addTransaction(tx3);
        
        // Assert
        assertEquals(1024 + 2048 + 512, bufferManager.getTotalDataVolume());
    }
    
    /**
     * Test: Total data volume after eviction
     */
    @Test
    public void testTotalDataVolumeAfterEviction() {
        // Arrange
        TrafficBufferManager smallBuffer = new TrafficBufferManager(2);
        HttpTransaction tx1 = createTransactionWithSize("tx1", 1000);
        HttpTransaction tx2 = createTransactionWithSize("tx2", 2000);
        HttpTransaction tx3 = createTransactionWithSize("tx3", 3000);
        
        // Act
        smallBuffer.addTransaction(tx1);
        smallBuffer.addTransaction(tx2);
        assertEquals(3000, smallBuffer.getTotalDataVolume()); // 1000 + 2000
        
        smallBuffer.addTransaction(tx3); // Should evict tx1
        
        // Assert
        assertEquals(5000, smallBuffer.getTotalDataVolume()); // 2000 + 3000 (tx1 evicted)
    }
    
    /**
     * Test: Null transaction handling
     */
    @Test
    public void testNullTransactionHandling() {
        // Act
        bufferManager.addTransaction(null);
        
        // Assert - Should not throw, buffer should remain empty
        assertEquals(0, bufferManager.size());
    }
    
    /**
     * Test: Remove listener
     */
    @Test
    public void testRemoveListener() throws InterruptedException {
        // Arrange
        AtomicInteger count = new AtomicInteger(0);
        TrafficBufferListener listener = new TrafficBufferListener() {
            @Override
            public void onTransactionAdded(HttpTransaction transaction) {
                count.incrementAndGet();
            }
            
            @Override
            public void onBufferCleared() {
            }
        };
        
        bufferManager.addListener(listener);
        bufferManager.addTransaction(createTransaction("tx1", "https://example.com/1"));
        Thread.sleep(100); // Give time for notification
        assertEquals(1, count.get());
        
        // Act - Remove listener
        bufferManager.removeListener(listener);
        bufferManager.addTransaction(createTransaction("tx2", "https://example.com/2"));
        Thread.sleep(100);
        
        // Assert - Count should still be 1 (no new notification)
        assertEquals(1, count.get());
    }
    
    // Helper methods
    
    private HttpTransaction createTransaction(String id, String url) {
        return new HttpTransaction(
            id,
            System.currentTimeMillis(),
            "GET",
            url,
            "application/json",
            200,
            1024,
            new byte[0],
            new byte[0],
            null
        );
    }
    
    private HttpTransaction createTransactionWithSize(String id, long size) {
        return new HttpTransaction(
            id,
            System.currentTimeMillis(),
            "GET",
            "https://example.com/",
            "application/json",
            200,
            size,
            new byte[0],
            new byte[0],
            null
        );
    }
}
