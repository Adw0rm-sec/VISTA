package com.vista.security.core;

import com.vista.security.model.HttpTransaction;

/**
 * Listener interface for receiving notifications about traffic buffer changes.
 * Implementations can react to new transactions or buffer clearing events.
 */
public interface TrafficBufferListener {
    
    /**
     * Called when a new transaction is added to the buffer.
     * 
     * @param transaction The newly added transaction
     */
    void onTransactionAdded(HttpTransaction transaction);
    
    /**
     * Called when the buffer is cleared.
     */
    void onBufferCleared();
}
