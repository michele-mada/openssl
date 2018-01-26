#ifndef PERF_COUNTER_H
#define PERF_COUNTER_H


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>


#define PERF_AMOUNT_DIVIDER 1048576.0   // B -> MB conversion
#define DEFAULT_PERF_TICK 2000

#define DEFAULT_PERF_FILENAME_ENV "M2DC_PERF_FILE"
#define DEFAULT_PERF_TICK_ENV "M2DC_PERF_TICK"


typedef struct PerfCounter {
    volatile struct timespec time_start;
    volatile struct timespec time_last_sample;
    volatile size_t accumulator;
    volatile size_t accumulator_latch;  // avoid hitting 0 when restarting between consecutive separate runs
    pthread_t save_thread;
    pthread_mutex_t save_mutex;
    volatile int running;   // Assumed atomic
    unsigned long refresh_time;  // In milliseconds
    char *filename;
} PerfCounter;


#ifndef HAS_TIMESPEC_DIFF
#define HAS_TIMESPEC_DIFF
static inline void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result) {
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
}
#endif

static void savefile_worker(void *owner) {
    PerfCounter *perf_counter = (PerfCounter*) owner;
    while (perf_counter->running) {
        usleep(perf_counter->refresh_time * 1000);
        pthread_mutex_lock(&(perf_counter->save_mutex));

        struct timespec difference;
        double perf_measurement;

        if ((perf_counter->time_start.tv_sec == perf_counter->time_last_sample.tv_sec) &&
            (perf_counter->time_start.tv_nsec == perf_counter->time_last_sample.tv_nsec)) {

            perf_measurement = 0.0;
        } else {
            timespec_diff(&(perf_counter->time_start), &(perf_counter->time_last_sample), &difference);

            double delta_time = ((double)difference.tv_sec) +
                                (((double)difference.tv_nsec) / 1000000000.0);

            perf_measurement = (((double)perf_counter->accumulator_latch) / PERF_AMOUNT_DIVIDER) /
                               delta_time;
        }

        FILE *fp = fopen(perf_counter->filename, "w");
        if (fp != NULL) {
            fprintf(fp, "%.0lf", perf_measurement);
            fclose(fp);
        }
        pthread_mutex_unlock(&(perf_counter->save_mutex));
    }
}

static void PerfCounter_start(PerfCounter* perf_counter) {
    pthread_mutex_lock(&(perf_counter->save_mutex));
    perf_counter->accumulator = 0;
    clock_gettime(CLOCK_MONOTONIC, &(perf_counter->time_start));
    perf_counter->time_last_sample = perf_counter->time_start;
    pthread_mutex_unlock(&(perf_counter->save_mutex));
}

static void PerfCounter_mark(PerfCounter* perf_counter, size_t quantity_amount) {
    // Careful here.
    // If samples are taken too often, this could starve the save_thread
    pthread_mutex_lock(&(perf_counter->save_mutex));
    perf_counter->accumulator += quantity_amount;
    perf_counter->accumulator_latch = perf_counter->accumulator;
    clock_gettime(CLOCK_MONOTONIC, &(perf_counter->time_last_sample));
    pthread_mutex_unlock(&(perf_counter->save_mutex));
}

static PerfCounter* PerfCounter_init(char *filename, unsigned long refresh_time) {
    PerfCounter* new_perfc = (PerfCounter*) malloc(sizeof(PerfCounter));

    asprintf(&(new_perfc->filename), "%s", filename);
    new_perfc->refresh_time = refresh_time;
    new_perfc->accumulator = 0;
    new_perfc->accumulator_latch = 0;
    new_perfc->running = 1;
    pthread_mutex_init(&(new_perfc->save_mutex), NULL);

    FILE *test = fopen(new_perfc->filename, "r+");
    if (test == NULL) {
        fprintf(stderr, "Could not open save_file \"%s\" in mode w\n", new_perfc->filename);
        free(new_perfc);
        return NULL;
    }
    fclose(test);

    int error = pthread_create(&(new_perfc->save_thread),
                               NULL,
                               savefile_worker, (void*) new_perfc);
    if (error) {
        fprintf(stderr, "Could not spawn savefile_worker: error %d\n", error);
        free(new_perfc);
        return NULL;
    }

    PerfCounter_start(new_perfc);
    fprintf(stderr, "performance counter enabled (file %s)\n", new_perfc->filename);
    return new_perfc;
}

static PerfCounter* PerfCounter_create_auto() {
    PerfCounter *perf_counter = NULL;
    char *custom_perf_file = getenv(DEFAULT_PERF_FILENAME_ENV);

    unsigned long refresh_time = DEFAULT_PERF_TICK;
    char *custom_perf_refresh_time = getenv(DEFAULT_PERF_TICK_ENV);
    if (custom_perf_refresh_time != NULL) {
        refresh_time = atol(custom_perf_refresh_time);
    }

    if (custom_perf_file != NULL) {
        perf_counter = PerfCounter_init(custom_perf_file, refresh_time);
    }

    return perf_counter;
}

static void PerfCounter_destroy(PerfCounter* perf_counter) {
    perf_counter->running = 0;
    pthread_join(perf_counter->save_thread, NULL);

    free(perf_counter->filename);
    free(perf_counter);
}


#define PERF_CTR_START(obj) {if ((obj) != NULL) PerfCounter_start((obj));}
#define PERF_CTR_MARK(obj, value) {if ((obj) != NULL) PerfCounter_mark((obj), (value));}
#define PERF_CTR_DESTROY(obj) {if ((obj) != NULL) PerfCounter_destroy((obj));}



#endif
