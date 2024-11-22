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

#define WCACHE_BLOCKS 33
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

struct queue {
    char *data;
    uint64_t head, tail;
    uint64_t capacity;
    uint64_t utilized;
};

struct worker {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int stop_thread;
    int force_write;
};

struct cache_block {
    char *data;
    uint64_t offset;
    short valid;
    uint64_t idx;
};

struct logfs {
    struct device *device;
    uint64_t utilized;
    uint64_t capacity;
    struct queue *write_queue;
    struct worker *worker;
    struct cache_block read_cache[RCACHE_BLOCKS];
};

struct logfs_metadata {
    uint64_t utilized;
};

uint64_t normalize_block(struct logfs *logfs, uint64_t i) {
    return i / device_block(logfs->device) * device_block(logfs->device);
}

void mark_cache_invalid(struct logfs *logfs, uint64_t offset) {
    int i;
    for (i = 0; i < RCACHE_BLOCKS; i++) {
        if (logfs->read_cache[i].valid && logfs->read_cache[i].offset == offset) {
            logfs->read_cache[i].valid = 0;
        }
    }
}

void write_to_disk(struct logfs *logfs) {
    char *buf = logfs->write_queue->data + logfs->write_queue->head;
    uint64_t normalized_tail = normalize_block(logfs, logfs->write_queue->tail);
    uint64_t normalized_utilized = normalize_block(logfs, logfs->utilized);
    uint64_t normalized_device_offset = normalized_utilized + RESTORE_FROM_FILE * device_block(logfs->device);
    uint64_t to_write, utilized, i;

    if (logfs->write_queue->head == normalized_tail) {
        if (device_write(logfs->device, buf, normalized_device_offset, device_block(logfs->device))) {
            TRACE("device_write()");
            return;
        }

        mark_cache_invalid(logfs, normalized_utilized);
        logfs->utilized += logfs->write_queue->utilized;
        logfs->write_queue->utilized = 0;
    } else {
        if (logfs->write_queue->head < normalized_tail) {
            if (logfs->write_queue->tail == normalized_tail) {
                to_write = logfs->write_queue->tail - logfs->write_queue->head;
            } else {
                to_write = normalized_tail + device_block(logfs->device) - logfs->write_queue->head;
            }
            utilized = logfs->write_queue->utilized;
            logfs->write_queue->head = normalized_tail % logfs->write_queue->capacity;
        } else {
            to_write = logfs->write_queue->capacity - logfs->write_queue->head;
            utilized = logfs->write_queue->capacity - logfs->write_queue->head;
            logfs->write_queue->head = 0;
        }

        if (device_write(logfs->device, buf, normalized_device_offset, to_write)) {
            TRACE("device_write()");
            return;
        }

        for (i = 0; i < to_write / device_block(logfs->device); i++) {
            mark_cache_invalid(logfs, normalized_utilized + i * device_block(logfs->device));
        }
        logfs->utilized += utilized;
        logfs->write_queue->utilized -= utilized;
    }
}

void *worker(void *arg) {
    struct logfs *logfs = arg;

    while (1) {
        if (pthread_mutex_lock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_lock()");
            return NULL;
        }

        while (logfs->write_queue->utilized == 0 && !logfs->worker->stop_thread) {
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex)) {
                TRACE("pthread_cond_wait()");
                return NULL;
            }
        }

        if (logfs->write_queue->utilized >= device_block(logfs->device) || logfs->worker->force_write) {
            write_to_disk(logfs);

            logfs->worker->force_write = 0;

            if (pthread_cond_signal(&logfs->worker->cond)) {
                TRACE("pthread_cond_signal()");
                return NULL;
            }
        }

        if (pthread_mutex_unlock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_unlock()");
            return NULL;
        }

        if (logfs->worker->stop_thread) {
            return NULL;
        }
    }
}

uint64_t get_metadata(struct logfs *logfs) {
    uint64_t utilized;

    char *metadata = malloc(device_block(logfs->device));
    if (!metadata) {
        TRACE("out of memory");
        return -1;
    }

    if (device_read(logfs->device, metadata, 0, device_block(logfs->device))) {
        TRACE("device_read()");
        free(metadata);
        return -1;
    }

    utilized = ((struct logfs_metadata *) metadata)->utilized;

    free(metadata);

    return utilized;
}

void set_metadata(struct logfs *logfs, uint64_t utilized) {
    char *metadata = malloc(device_block(logfs->device));
    if (!metadata) {
        TRACE("out of memory");
        return;
    }

    ((struct logfs_metadata *) metadata)->utilized = utilized;

    if (device_write(logfs->device, metadata, 0, device_block(logfs->device))) {
        TRACE("device_write()");
        free(metadata);
        return;
    }

    free(metadata);
}

int setup_device(struct logfs *logfs, const char *pathname) {
    if (!(logfs->device = device_open(pathname))) {
        return -1;
    }

    logfs->capacity = device_size(logfs->device);
    logfs->utilized = RESTORE_FROM_FILE * get_metadata(logfs);

    return 0;
}

int setup_queue(struct logfs *logfs) {
    if (!(logfs->write_queue = malloc(sizeof(struct queue)))) {
        return -1;
    }
    memset(logfs->write_queue, 0, sizeof(struct queue));

    logfs->write_queue->head = 0;
    logfs->write_queue->tail = 0;
    logfs->write_queue->capacity = device_block(logfs->device) * WCACHE_BLOCKS;
    logfs->write_queue->utilized = 0;

    if (!(logfs->write_queue->data = malloc(logfs->write_queue->capacity))) {
        return -1;
    }
    memset(logfs->write_queue->data, 0, logfs->write_queue->capacity);

    return 0;
}

int setup_cache(struct logfs *logfs) {
    int i;

    for (i = 0; i < RCACHE_BLOCKS; i++) {
        if (!(logfs->read_cache[i].data = malloc(device_block(logfs->device)))) {
            return -1;
        }
        memset(logfs->read_cache[i].data, 0, device_block(logfs->device));

        logfs->read_cache[i].valid = 0;
        logfs->read_cache[i].idx = i;
    }

    return 0;
}

int setup_worker(struct logfs *logfs) {
    if (!(logfs->worker = malloc(sizeof(struct worker)))) {
        return -1;
    }
    memset(logfs->worker, 0, sizeof(struct worker));

    if (pthread_mutex_init(&logfs->worker->mutex, NULL) ||
        pthread_cond_init(&logfs->worker->cond, NULL) ||
        pthread_create(&logfs->worker->thread, NULL, worker, logfs)) {
        return -1;
    }

    return 0;
}

struct logfs *logfs_open(const char *pathname) {
    struct logfs *logfs;

    assert(safe_strlen(pathname));

    if (!(logfs = malloc(sizeof(struct logfs)))) {
        TRACE("out of memory");
        return NULL;
    }
    memset(logfs, 0, sizeof(struct logfs));

    if (setup_device(logfs, pathname) || setup_queue(logfs) || setup_cache(logfs) || setup_worker(logfs)) {
        logfs_close(logfs);
        TRACE(0);
        return NULL;
    }

    return logfs;
}

void logfs_close(struct logfs *logfs) {
    int i;

    assert(logfs);

    if (RESTORE_FROM_FILE) {
        set_metadata(logfs, logfs->utilized);
    }

    if (logfs) {
        if (logfs->worker) {
            if (pthread_mutex_lock(&logfs->worker->mutex)) {
                TRACE("pthread_mutex_lock()");
            }
            logfs->worker->stop_thread = 1;
            if (pthread_cond_signal(&logfs->worker->cond)) {
                TRACE("pthread_cond_signal()");
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex)) {
                TRACE("pthread_mutex_unlock()");
            }
            if (pthread_join(logfs->worker->thread, NULL)) {
                TRACE("pthread_join()");
            }
            if (pthread_mutex_destroy(&logfs->worker->mutex)) {
                TRACE("pthread_mutex_destroy()");
            }
            if (pthread_cond_destroy(&logfs->worker->cond)) {
                TRACE("pthread_cond_destroy()");
            }
        }
        if (logfs->write_queue) {
            FREE(logfs->write_queue->data);
            FREE(logfs->write_queue);
        }
        for (i = 0; i < RCACHE_BLOCKS; ++i) {
            if (logfs->read_cache[i].data) {
                FREE(logfs->read_cache[i].data);
            }
        }
        if (logfs->worker) {
            FREE(logfs->worker);
        }
        if (logfs->write_queue) {
            FREE(logfs->write_queue);
        }
        if (logfs->device) {
            device_close(logfs->device);
        }
        memset(logfs, 0, sizeof(struct logfs));
    }
    FREE(logfs);
}

int get_from_cache(struct logfs *logfs, void *buf, uint64_t block_offset, uint64_t data_offset, uint64_t to_read) {
    int i;
    for (i = 0; i < RCACHE_BLOCKS; i++) {
        if (logfs->read_cache[i].valid &&
            logfs->read_cache[i].offset == block_offset - RESTORE_FROM_FILE * device_block(logfs->device)) {
            memcpy(buf, logfs->read_cache[i].data + data_offset, to_read);
            return 0;
        }
    }
    return -1;
}

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len) {
    uint64_t written, start_block_offset, end_block_offset;
    int num_blocks, i;
    char *result;

    if (!buf || !len) {
        return 0;
    }

    off += RESTORE_FROM_FILE * device_block(logfs->device);

    while (1) {
        if (pthread_mutex_lock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_lock()");
            return -1;
        }

        while (logfs->write_queue->utilized > 0) {
            if (logfs->write_queue->utilized < device_block(logfs->device)) {
                logfs->worker->force_write = 1;
            }
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex)) {
                TRACE("pthread_cond_wait()");
                return -1;
            }
        }

        if (logfs->write_queue->utilized == 0) {
            if (pthread_cond_signal(&logfs->worker->cond)) {
                TRACE("pthread_cond_signal()");
                return -1;
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex)) {
                TRACE("pthread_mutex_unlock()");
                return -1;
            }
            break;
        }


        if (pthread_mutex_unlock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_unlock()");
            return -1;
        }
    }

    written = 0;
    start_block_offset = normalize_block(logfs, off);
    end_block_offset = normalize_block(logfs, off + len);
    num_blocks = (int) ((end_block_offset - start_block_offset) / device_block(logfs->device)) + 1;

    result = malloc(len);

    for (i = 0; i < num_blocks; i++) {
        uint64_t block_offset = start_block_offset + i * device_block(logfs->device);
        uint64_t data_offset, to_read;

        if (i == 0) {
            data_offset = off - start_block_offset;
            to_read = MIN(device_block(logfs->device) - data_offset, len);
        } else if (i == num_blocks - 1) {
            data_offset = 0;
            to_read = off + len - end_block_offset;
        } else {
            data_offset = 0;
            to_read = device_block(logfs->device);
        }

        if (get_from_cache(logfs, result + written, block_offset, data_offset, to_read) != 0) {
            int min_idx = 0, max_idx = 0, j;
            char *data;

            for (j = 0; j < RCACHE_BLOCKS; j++) {
                if (logfs->read_cache[j].idx < logfs->read_cache[min_idx].idx) {
                    min_idx = j;
                }
                if (logfs->read_cache[j].idx > logfs->read_cache[max_idx].idx) {
                    max_idx = j;
                }
            }

            data = malloc(device_block(logfs->device));
            if (!data) {
                TRACE("out of memory");
                return -1;
            }

            if (device_read(logfs->device, data, block_offset, device_block(logfs->device))) {
                TRACE("device_read()");
                return -1;
            }

            memcpy(logfs->read_cache[min_idx].data, data, device_block(logfs->device));
            logfs->read_cache[min_idx].offset = block_offset - RESTORE_FROM_FILE * device_block(logfs->device);
            logfs->read_cache[min_idx].valid = 1;
            logfs->read_cache[min_idx].idx = logfs->read_cache[max_idx].idx + 1;

            free(data);

            memcpy(result + written, logfs->read_cache[min_idx].data + data_offset, to_read);
        }

        written += to_read;
    }

    memcpy(buf, result, len);

    free(result);

    return 0;
}

void queue_add(struct logfs *logfs, const void *buf, uint64_t len) {
    if (logfs->write_queue->tail + len <= logfs->write_queue->capacity) {
        memcpy(logfs->write_queue->data + logfs->write_queue->tail, buf, len);
        logfs->write_queue->tail += len;
    } else {
        uint64_t space_at_end = logfs->write_queue->capacity - logfs->write_queue->tail;
        uint64_t leftover = len - space_at_end;
        if (space_at_end) {
            memcpy(logfs->write_queue->data + logfs->write_queue->tail, buf, space_at_end);
        }
        if (leftover) {
            memcpy(logfs->write_queue->data, (char *) buf + space_at_end, leftover);
        }
        logfs->write_queue->tail = leftover % logfs->write_queue->capacity;
    }

    logfs->write_queue->utilized += len;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len) {
    assert(logfs);
    assert(buf || !len);

    if (logfs->utilized + len > logfs->capacity) {
        TRACE("out of space");
        return -1;
    }

    while (1) {
        if (pthread_mutex_lock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_lock()");
            return -1;
        }

        while (logfs->write_queue->utilized + len > logfs->write_queue->capacity) {
            if (pthread_cond_wait(&logfs->worker->cond, &logfs->worker->mutex)) {
                TRACE("pthread_cond_wait()");
                return -1;
            }
        }

        if (logfs->write_queue->utilized + len <= logfs->write_queue->capacity) {
            queue_add(logfs, buf, len);

            if (pthread_cond_signal(&logfs->worker->cond)) {
                TRACE("pthread_cond_signal()");
                return -1;
            }
            if (pthread_mutex_unlock(&logfs->worker->mutex)) {
                TRACE("pthread_mutex_unlock()");
                return -1;
            }
            return 0;
        }

        if (pthread_mutex_unlock(&logfs->worker->mutex)) {
            TRACE("pthread_mutex_unlock()");
            return -1;
        }
    }

    return 0;
}

uint64_t logfs_size(struct logfs *logfs) {
    assert(logfs);

    return logfs->utilized;
}
