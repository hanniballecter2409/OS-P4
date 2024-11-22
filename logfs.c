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

struct cache_block {
    char *data;         
    uint64_t tag;       
    short valid;
};


struct logfs {
    struct device *dev;         
    void *buffer;             
    size_t head;              
    size_t tail;              
    size_t BS;                
    size_t block;             
    size_t capacity;          
    pthread_t worker;         
    pthread_mutex_t lock;     
    pthread_cond_t data_avail;
    pthread_cond_t space_avail; 
    int done;          
    struct cache_block read_cache[RCACHE_BLOCKS];
};

static void *worker_thread(void *arg) {
    struct logfs *fs = (struct logfs *)arg;
    size_t size;
    
    pthread_mutex_lock(&fs->lock);
    
    while (!fs->done) {
        
        size = fs->head - fs->tail;
        
        
        assert(fs->tail <= fs->head);
        assert(0 <= (fs->tail % fs->block));
        assert(fs->capacity >= fs->head);
        
        
        if (size < fs->block) {
            pthread_cond_wait(&fs->data_avail, &fs->lock);
            continue;
        }
        
        
        void *src = (char *)fs->buffer + (fs->tail % fs->BS);
        if (device_write(fs->dev, src, fs->tail, fs->block)) {
            continue;
        }
        
        fs->tail += fs->block;
        size -= fs->block;
        
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
    
    if (!(fs->dev = device_open(pathname))) {
        FREE(fs);
        return NULL;
    }
    
    fs->block = device_block(fs->dev);
    fs->capacity = device_size(fs->dev);
    fs->BS = fs->block * WCACHE_BLOCKS;  
    
    void *raw_buffer = malloc(fs->BS + fs->block); 
    if (!raw_buffer) {
        device_close(fs->dev);
        FREE(fs);
        return NULL;
    }
    fs->buffer = memory_align(raw_buffer, fs->block);
    
   
    if (pthread_mutex_init(&fs->lock, NULL) ||
        pthread_cond_init(&fs->data_avail, NULL) ||
        pthread_cond_init(&fs->space_avail, NULL)) {
        FREE(raw_buffer);
        device_close(fs->dev);
        FREE(fs);
        return NULL;
    }
    
    fs->head = 0;
    fs->tail = 0;
    fs->done = 0;
    
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
    
    pthread_mutex_lock(&fs->lock);
    fs->done = 1;
    pthread_cond_signal(&fs->data_avail);
    pthread_mutex_unlock(&fs->lock);
    
    pthread_join(fs->worker, NULL);
    
    pthread_mutex_destroy(&fs->lock);
    pthread_cond_destroy(&fs->data_avail);
    pthread_cond_destroy(&fs->space_avail);
    FREE(fs->buffer);
    device_close(fs->dev);
    FREE(fs);
}

int logfs_read(struct logfs *fs, void *buf, uint64_t off, size_t len) {
    if (!fs || (!buf && len) || (off + len) > fs->capacity) {
        return -1;
    }

    uint64_t start_block = off / fs->block;
    uint64_t end_block = (off + len + fs->block - 1) / fs->block;
    uint64_t block_count = end_block - start_block;
    
    size_t start_offset = off % fs->block;
    size_t end_offset = (off + len) % fs->block;
    if (end_offset == 0) end_offset = fs->block;

    pthread_mutex_lock(&fs->lock);

    for (uint64_t i = 0; i < block_count; i++) {
        uint64_t current_block = start_block + i;
        uint64_t cache_index = current_block % RCACHE_BLOCKS;
        struct cache_block *cache = &fs->read_cache[cache_index];
        
        if (!cache->valid || cache->tag != current_block) {
            if (!cache->data) {
                cache->data = malloc(fs->block);
                if (!cache->data) {
                    pthread_mutex_unlock(&fs->lock);
                    return -1;
                }
            }
            
            int found_in_buffer = 0;
            if (current_block * fs->block >= fs->tail && 
                current_block * fs->block < fs->head) {
                size_t buffer_offset = (current_block * fs->block - fs->tail) % fs->BS;
                memcpy(cache->data, 
                       (char *)fs->buffer + buffer_offset, 
                       fs->block);
                found_in_buffer = 1;
            }
            
            if (!found_in_buffer) {
                if (device_read(fs->dev, 
                              cache->data, 
                              current_block * fs->block, 
                              fs->block)) {
                    pthread_mutex_unlock(&fs->lock);
                    return -1;
                }
            }
            
            cache->tag = current_block;  
            cache->valid = 1;
        }
        
        size_t copy_start = (i == 0) ? start_offset : 0;
        size_t copy_end = (i == block_count - 1) ? end_offset : fs->block;
        size_t copy_size = copy_end - copy_start;
        size_t buf_offset = (i == 0) ? 0 : (i * fs->block - start_offset);
        
        memcpy((char *)buf + buf_offset,
               cache->data + copy_start,
               copy_size);
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
        while ((fs->head - fs->tail) >= fs->BS) {
            pthread_cond_wait(&fs->space_avail, &fs->lock);
        }
        
        size_t available = fs->BS - (fs->head - fs->tail);
        size_t write_size = MIN(len, available);
        size_t buffer_pos = fs->head % fs->BS;
        
        memcpy((char *)fs->buffer + buffer_pos, buf, write_size);
        
        fs->head += write_size;
        buf = (const char *)buf + write_size;
        len -= write_size;
        
        assert(fs->tail <= fs->head);
        assert(fs->capacity >= fs->head);
        
        pthread_cond_signal(&fs->data_avail);
    }
    
    pthread_mutex_unlock(&fs->lock);
    return 0;
}