#ifndef ALTERA_STUB_UTILS_H
#define ALTERA_STUB_UTILS_H


// This depends on gcc specific language extensions
#define GUARD_DECORATOR(guardmutex, body) \
{ \
    /*fprintf(stderr, "Acquiring lock %s at %s:%d\n", #guardmutex, __FILE__, __LINE__);*/ \
    pthread_mutex_lock(&(guardmutex)); \
 \
    int wrapped() body; \
    int ret = wrapped(); \
 \
    pthread_mutex_unlock(&(guardmutex)); \
    /*fprintf(stderr, "Released lock %s at %s:%d\n", #guardmutex, __FILE__, __LINE__);*/ \
    return ret; \
} \



#endif
