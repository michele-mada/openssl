#ifndef ALIGNED_MEM_MANAGEMENT_H
#define ALIGNED_MEM_MANAGEMENT_H

#define AOCL_ALIGNMENT 64


static inline void *crypto_malloc_aligned_64(size_t num, const char *file, int line) {
    void *ret = NULL;

    if (num == 0)
        return NULL;

    printf("Aligned malloc\n");

    ret = aligned_alloc(AOCL_ALIGNMENT, num);

    return ret;
}


#endif
