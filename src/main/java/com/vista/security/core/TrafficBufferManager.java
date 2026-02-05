package com.vista.security.core;

import com.vista.security.model.HttpTransaction;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe circular buffer for storing HTTP transactions.
 * Automatically evicts oldest transactions when capacity is reached (FIFO).
 * Notifies registered listeners of buffer changes.
 */
public class TrafficBufferManager {
    private final int maxCapacity;
    private final Deque<HttpTransaction> buffer;
    private final ReadWriteLock lock;
    private final List<TrafficBufferListener> listeners;
    private long totalDataVolume;
    
    /**
     * Creates a new traffic buffer with the specified maximum capacity.
     * 
     * @param maxCapacity Maximum number of transactions to store (1000-5000 recommended)
     * @throws IllegalArgumentException if maxCapacity is less than 1
     */
    public TrafficBufferManager(int maxCapacity) {
        if (maxCapacity < 1) {
            throw new IllegalArgumentException("Max capacity must be at least 1");
        }
        this.maxCapacity = maxCapacity;
        this.buffer = new ArrayDeque<>(maxCapacity);
        this.lock = new ReentrantReadWriteLock();
        this.listeners = new CopyOnWriteArrayList<>();
        this.totalDataVolume = 0;
    }
    
    /**
     * Adds a transaction to the buffer.
     * If the buffer is at capacity, the oldest transaction is removed first (FIFO).
     * Notifies all registered listeners after adding.
     * 
     * @param transaction The transaction to add
     */
    public void addTransaction(HttpTransaction transaction) {
        if (transaction == null) {
            return;
        }
        
        lock.writeLock().lock();
        try {
            // Remove oldest if at capacity
            if (buffer.size() >= maxCapacity) {
                HttpTransaction removed = buffer.removeFirst();
                if (removed != null) {
                    totalDataVolume -= removed.getResponseSize();
                }
            }
            
            // Add new transaction
            buffer.addLast(transaction);
            totalDataVolume += transaction.getResponseSize();
            
        } finally {
            lock.writeLock().unlock();
        }
        
        // Notify listeners outside of lock
        notifyListeners(transaction);
    }
    
    /**
     * Returns all transactions in the buffer as a defensive copy.
     * 
     * @return List of all transactions (newest last)
     */
    public List<HttpTransaction> getAllTransactions() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(buffer);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Returns the most recent N transactions.
     * 
     * @param limit Maximum number of transactions to return
     * @return List of recent transactions (newest last)
     */
    public List<HttpTransaction> getTransactions(int limit) {
        lock.readLock().lock();
        try {
            List<HttpTransaction> all = new ArrayList<>(buffer);
            if (all.size() <= limit) {
                return all;
            }
            return all.subList(all.size() - limit, all.size());
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clears all transactions from the buffer.
     * Notifies all registered listeners after clearing.
     */
    public void clear() {
        lock.writeLock().lock();
        try {
            buffer.clear();
            totalDataVolume = 0;
        } finally {
            lock.writeLock().unlock();
        }
        
        // Notify listeners outside of lock
        notifyListenersCleared();
    }
    
    /**
     * Returns the current number of transactions in the buffer.
     * 
     * @return Current buffer size
     */
    public int size() {
        lock.readLock().lock();
        try {
            return buffer.size();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Returns the total data volume of all transactions in the buffer.
     * 
     * @return Total response size in bytes
     */
    public long getTotalDataVolume() {
        lock.readLock().lock();
        try {
            return totalDataVolume;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Returns the maximum capacity of this buffer.
     * 
     * @return Maximum number of transactions
     */
    public int getMaxCapacity() {
        return maxCapacity;
    }
    
    /**
     * Registers a listener to receive buffer change notifications.
     * 
     * @param listener The listener to register
     */
    public void addListener(TrafficBufferListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
    
    /**
     * Unregisters a listener from receiving notifications.
     * 
     * @param listener The listener to unregister
     */
    public void removeListener(TrafficBufferListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * Notifies all listeners that a transaction was added.
     */
    private void notifyListeners(HttpTransaction transaction) {
        for (TrafficBufferListener listener : listeners) {
            try {
                listener.onTransactionAdded(transaction);
            } catch (Exception e) {
                // Ignore listener exceptions to prevent one bad listener from affecting others
                System.err.println("Error notifying listener: " + e.getMessage());
            }
        }
    }
    
    /**
     * Notifies all listeners that the buffer was cleared.
     */
    private void notifyListenersCleared() {
        for (TrafficBufferListener listener : listeners) {
            try {
                listener.onBufferCleared();
            } catch (Exception e) {
                // Ignore listener exceptions
                System.err.println("Error notifying listener: " + e.getMessage());
            }
        }
    }
}
