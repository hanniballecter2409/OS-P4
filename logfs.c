/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include "device.h"
#include "logfs.h"

#define WCACHE_BLOCKS 32
#define RCACHE_BLOCKS 256

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */


struct logfs {
    struct device *dev;         // Block device handle
    void *buffer;              // Circular buffer
    size_t head;              // Write pointer
    size_t tail;              // Read/flush pointer
    size_t BS;                // Buffer size
    size_t block;             // Block size
    size_t capacity;          // Total device capacity
    pthread_t worker;         // Worker thread
    pthread_mutex_t lock;     // Mutex for synchronization
    pthread_cond_t data_avail; // Condition for data availability
    pthread_cond_t space_avail; // Condition for space availability
    int done;                 // Flag to mark completion
};

static void *worker_thread(void *arg) {
    struct logfs *fs = (struct logfs *)arg;
    size_t size;
    
    pthread_mutex_lock(&fs->lock);
    
    while (!fs->done) {
        // Calculate available data size
        size = fs->head - fs->tail;
        
        // Assert conditions
        assert(fs->tail <= fs->head);
        assert(0 <= (fs->tail % fs->block));
        assert(fs->capacity >= fs->head);
        
        // Wait if not enough data
        if (size < fs->block) {
            pthread_cond_wait(&fs->data_avail, &fs->lock);
            continue;
        }
        
        // Write block to device block storage
        void *src = (char *)fs->buffer + (fs->tail % fs->BS);
        if (device_write(fs->dev, src, fs->tail, fs->block)) {
            // Handle error - in this case we'll just continue
            continue;
        }
        
        // Update tail and available size
        fs->tail += fs->block;
        size -= fs->block;
        
        // Signal that space is available
        pthread_cond_signal(&fs->space_avail);
    }
    
    pthread_mutex_unlock(&fs->lock);
    return NULL;
}

struct logfs *logfs_open(const char *pathname) {
    struct logfs *fs;
    
    if (!(fs = calloc(1, sizeof(struct logfs)))) {
        return NULL;
    }
    
    // Open device
    if (!(fs->dev = device_open(pathname))) {
        FREE(fs);
        return NULL;
    }
    
    // Initialize sizes
    fs->block = device_block(fs->dev);
    fs->capacity = device_size(fs->dev);
    fs->BS = fs->block * WCACHE_BLOCKS;  // Buffer size is multiple of block size
    
    // Allocate and align buffer
    void *raw_buffer = malloc(fs->BS + fs->block); // Extra space for alignment
    if (!raw_buffer) {
        device_close(fs->dev);
        FREE(fs);
        return NULL;
    }
    fs->buffer = memory_align(raw_buffer, fs->block);
    
    // Initialize synchronization primitives
    if (pthread_mutex_init(&fs->lock, NULL) ||
        pthread_cond_init(&fs->data_avail, NULL) ||
        pthread_cond_init(&fs->space_avail, NULL)) {
        FREE(raw_buffer);
        device_close(fs->dev);
        FREE(fs);
        return NULL;
    }
    
    // Initialize pointers
    fs->head = 0;
    fs->tail = 0;
    fs->done = 0;
    
    // Start worker thread
    if (pthread_create(&fs->worker, NULL, worker_thread, fs)) {
        pthread_mutex_destroy(&fs->lock);
        pthread_cond_destroy(&fs->data_avail);
        pthread_cond_destroy(&fs->space_avail);
        FREE(raw_buffer);
        device_close(fs->dev);
        FREE(fs);
        return NULL;
    }
    
    return fs;
}

void logfs_close(struct logfs *fs) {
    if (!fs) {
        return;
    }
    
    // Signal worker to finish
    pthread_mutex_lock(&fs->lock);
    fs->done = 1;
    pthread_cond_signal(&fs->data_avail);
    pthread_mutex_unlock(&fs->lock);
    
    // Wait for worker to complete
    pthread_join(fs->worker, NULL);
    
    // Cleanup
    pthread_mutex_destroy(&fs->lock);
    pthread_cond_destroy(&fs->data_avail);
    pthread_cond_destroy(&fs->space_avail);
    FREE(fs->buffer);
    device_close(fs->dev);
    FREE(fs);
}

int logfs_read(struct logfs *fs, void *buf, uint64_t off, size_t len) {
    if (!fs || !buf || len == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&fs->lock);
    
    // Verify offset is within written range
    if (off >= fs->head) {
        pthread_mutex_unlock(&fs->lock);
        return -1;
    }
    
    // Read from device
    if (device_read(fs->dev, buf, off, len)) {
        pthread_mutex_unlock(&fs->lock);
        return -1;
    }
    
    pthread_mutex_unlock(&fs->lock);
    return 0;
}

int logfs_read(struct logfs *fs, void *buf, uint64_t off, size_t len) {
    if (!fs || !buf || len == 0 || off >= fs->capacity) {
        return -1;
    }

    pthread_mutex_lock(&fs->lock);

    size_t block_size = fs->block_size;
    size_t blocks_to_read = (len + block_size - 1) / block_size; // Round up to nearest block
    uint64_t start_block = off / block_size;
    uint64_t end_block = start_block + blocks_to_read;

    for (uint64_t block = start_block; block < end_block; block++) {
        // Check if block is in cache
        int cache_index = block % fs->rblocks; // Cache index (modulo buffer size)
        struct cache_block *meta = &fs->rmeta[cache_index];
        void *cache_data = (char *)fs->rbuffer + cache_index * block_size;

        if (meta->valid && meta->tag == block) {
            // Cache hit: copy data from cache
            size_t offset_in_block = (block == start_block) ? off % block_size : 0;
            size_t bytes_to_copy = (block == end_block - 1) 
                                   ? (off + len) % block_size 
                                   : block_size - offset_in_block;

            memcpy(buf, (char *)cache_data + offset_in_block, bytes_to_copy);
            buf = (char *)buf + bytes_to_copy;
            len -= bytes_to_copy;
        } else {
            // Cache miss: read block from device
            if (device_read(fs->dev, cache_data, block * block_size, block_size)) {
                pthread_mutex_unlock(&fs->lock);
                return -1; // Device read error
            }

            // Update cache metadata
            meta->tag = block;
            meta->valid = 1;

            // Copy data from cache
            size_t offset_in_block = (block == start_block) ? off % block_size : 0;
            size_t bytes_to_copy = (block == end_block - 1) 
                                   ? (off + len) % block_size 
                                   : block_size - offset_in_block;

            memcpy(buf, (char *)cache_data + offset_in_block, bytes_to_copy);
            buf = (char *)buf + bytes_to_copy;
            len -= bytes_to_copy;
        }
    }

    pthread_mutex_unlock(&fs->lock);
    return 0;
}

int logfs_append(struct logfs *fs, const void *buf, uint64_t len) {
    if (!fs || (!buf && len)) {
        return -1;
    }
    
    pthread_mutex_lock(&fs->lock);
    
    while (len > 0) {
        // Wait if buffer is full
        while ((fs->head - fs->tail) >= fs->BS) {
            pthread_cond_wait(&fs->space_avail, &fs->lock);
        }
        
        // Calculate how much we can write
        size_t available = fs->BS - (fs->head - fs->tail);
        size_t write_size = MIN(len, available);
        size_t buffer_pos = fs->head % fs->BS;
        
        // Copy data to buffer
        memcpy((char *)fs->buffer + buffer_pos, buf, write_size);
        
        // Update pointers
        fs->head += write_size;
        buf = (const char *)buf + write_size;
        len -= write_size;
        
        // Assert conditions
        assert(fs->tail <= fs->head);
        assert(fs->capacity >= fs->head);
        
        // Signal worker that data is available
        pthread_cond_signal(&fs->data_avail);
    }
    
    pthread_mutex_unlock(&fs->lock);
    return 0;
}