/*
 *
 * This file is deprecated! Use benchmark/main.cpp
 *
 */
#include <iostream>
#include <unordered_map>
#include <cassert>
#include <stdlib.h>
#include <pthread.h>

#include "hash_map.h"
#include "common/hash.h"
#include "segment_hash_map.h"
#include "cuckoo_hash_map.h"
#include "better_cuckoo_hash_map.h"
#include "optimistic_cuckoo_hash_map.h"
#include "common/CycleTimer.h"

#define NUM_THREADS 12
#define NUM_READERS 6
#define NUM_WRITERS 2

// #define NUM_BUCKETS 10 * 1000 * 1000
// #define NUM_OPS 20 * 1000 * 1000

#define NUM_BUCKETS 1 * 1000 * 1000
#define NUM_OPS 2 * 1000 * 1000

// #define NUM_BUCKETS 500
// #define NUM_OPS 1000

struct WorkerArgs {
    void* my_map;
    int thread_id;
    int num_readers;
    int num_writers;
    std::string member_function;
    std::string* keys;
};

template<typename T>
void* thread_send_requests(void* threadArgs) {
    WorkerArgs* args = static_cast<WorkerArgs*>(threadArgs);

    int thread_ID = args->thread_id;
    std::string member_function = args->member_function;
    std::string* keys = args->keys;

    T* my_map = (T*)args->my_map;
    if (member_function.compare("put") == 0) {
        for (int i = thread_ID; i < NUM_OPS; i += args->num_writers) {
            my_map->put(keys[i], "value" + keys[i]);
        }
    } else if (member_function.compare("get") == 0) {
       for (int i = thread_ID; i < NUM_OPS; i += args->num_readers) {
            my_map->get(keys[i]);
        }
    }

    return NULL;
}

void benchmark_builtin_unorderedmap() {

    std::cout << "\nBenchmarking built-in unordered map..." << std::endl;

    double start_time, end_time, best_put_time, best_get_time;

    best_put_time = 1e30;
    best_get_time = 1e30;
    for (int i = 0; i < 3; i++) {
        std::unordered_map<std::string,std::string> ref_map;

        // INSERT
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            ref_map.insert(std::pair<std::string,std::string>(std::to_string(j), "value" + std::to_string(j)));
        }
        end_time = CycleTimer::currentSeconds();
        best_put_time = std::min(best_put_time, end_time-start_time);

        // GET
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            ref_map.find(std::to_string(j));
        }
        end_time = CycleTimer::currentSeconds();
        best_get_time = std::min(best_get_time, end_time-start_time);

    }
    std::cout << "Built-in put: " << best_put_time << std::endl;
    std::cout << "Built-in get: " << best_get_time << std::endl;

}


void benchmark_hashmap() {

    std::cout << "\nBenchmarking sequential hashmap..." << std::endl;

    std::string* keys = new std::string[NUM_OPS];
    for (int i = 0 ; i < NUM_OPS; i++)
        keys[i] = std::to_string(i);

    double start_time, end_time, best_put_time, best_get_time;

    // Time my sequential implementation. Output the best of three times.
    best_put_time = 1e30;
    best_get_time = 1e30;
    for (int i = 0; i < 3; i++) {
        HashMap<std::string, std::string> my_map(NUM_BUCKETS);

        // PUT
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            my_map.put(keys[j], "value" + keys[j]);
        }
        end_time = CycleTimer::currentSeconds();
        best_put_time = std::min(best_put_time, end_time-start_time);


        // GET
        start_time = CycleTimer::currentSeconds();https://github.com/BensonQiu/ParaCuckooHash.git
        for (int j = 0; j < NUM_OPS; j++) {
            my_map.get(keys[j]);
        }
        end_time = CycleTimer::currentSeconds();
        best_get_time = std::min(best_get_time, end_time-start_time);
    }
    std::cout << "Sequential put: " << best_put_time << std::endl;
    std::cout << "Sequential get: " << best_get_time << std::endl;

}


void benchmark_cuckoo_hashmap() {

    std::cout << "\nBenchmarking cuckoo hashmap..." << std::endl;

    std::string* keys = new std::string[NUM_OPS];
    for (int i = 0 ; i < NUM_OPS; i++)
        keys[i] = std::to_string(i);

    double start_time, end_time, best_put_time, best_get_time;

    best_put_time = 1e30;
    best_get_time = 1e30;
    for (int i = 0; i < 3; i++) {
        CuckooHashMap<std::string> my_map(0.55 * NUM_BUCKETS);

        // PUT
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            my_map.put(keys[i], "value" + keys[i]);
        }
        end_time = CycleTimer::currentSeconds();
        best_put_time = std::min(best_put_time, end_time-start_time);


        // GET
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            my_map.get(keys[i]);
        }
        end_time = CycleTimer::currentSeconds();
        best_get_time = std::min(best_get_time, end_time-start_time);
    }
    std::cout << "Cuckoo put: " << best_put_time << std::endl;
    std::cout << "Cuckoo get: " << best_get_time << std::endl;
}


// void benchmark_better_cuckoo_hashmap() {

//     std::cout << "\nBenchmarking better cuckoo hashmap..." << std::endl;

//     std::string* keys = new std::string[NUM_OPS];
//     for (int i = 0 ; i < NUM_OPS; i++)
//         keys[i] = std::to_string(i);

//     double start_time, end_time, best_put_time, best_get_time;

//     best_put_time = 1e30;
//     best_get_time = 1e30;
//     for (int i = 0; i < 3; i++) {
//         BetterCuckooHashMap<std::string> my_map(0.55 * NUM_BUCKETS);

//         // PUT
//         start_time = CycleTimer::currentSeconds();
//         for (int j = 0; j < NUM_OPS; j++) {
//             my_map.put(keys[i], "value" + keys[i]);
//         }
//         end_time = CycleTimer::currentSeconds();
//         best_put_time = std::min(best_put_time, end_time-start_time);


//         // GET
//         start_time = CycleTimer::currentSeconds();
//         for (int j = 0; j < NUM_OPS; j++) {
//             my_map.get(keys[i]);
//         }
//         end_time = CycleTimer::currentSeconds();
//         best_get_time = std::min(best_get_time, end_time-start_time);
//     }
//     std::cout << "BetterCuckoo put: " << best_put_time << std::endl;
//     std::cout << "BetterCuckoo get: " << best_get_time << std::endl;
// }


void benchmark_optimistic_cuckoo_hashmap() {

    std::cout << "\nBenchmarking optimistic cuckoo hashmap..." << std::endl;

    double start_time, end_time, best_put_time, best_get_time;

    // Test separate reads and writes.
    best_put_time = 1e30;
    best_get_time = 1e30;
    for (int i = 0; i < 3; i++) {
        OptimisticCuckooHashMap<std::string> my_map(1.11f*NUM_OPS/4.0f);

        std::string* keys = new std::string[NUM_OPS];
        for (int i = 0 ; i < NUM_OPS; i++)
            keys[i] = std::to_string(i);

        // PUT
        start_time = CycleTimer::currentSeconds();
        for (int j = 0; j < NUM_OPS; j++) {
            my_map.put(keys[j], "value" + keys[j]);
        }
        end_time = CycleTimer::currentSeconds();
        best_put_time = std::min(best_put_time, end_time-start_time);

        // GET
        start_time = CycleTimer::currentSeconds();

        // for (int j = 0; j < NUM_OPS; j++) {
        //     my_map.get(std::to_string(j));
        //     // my_map.get(keys[j]);
        // }

        pthread_t workers[NUM_THREADS];
        WorkerArgs args[NUM_THREADS];

        for (int j = 0; j < NUM_THREADS; j++) {
            args[j].my_map = (void*)&my_map;
            args[j].thread_id = (long int)j;
            args[j].member_function = "get";
            args[j].keys = keys;
        }
        for (int j = 0; j < NUM_THREADS; j++) {
            pthread_create(&workers[j], NULL, thread_send_requests<OptimisticCuckooHashMap<std::string>>, &args[j]);
        }
        for (int j = 0; j < NUM_THREADS; j++) {
            pthread_join(workers[j], NULL);
        }

        end_time = CycleTimer::currentSeconds();
        best_get_time = std::min(best_get_time, end_time-start_time);

        // std::cout << best_put_time << std::endl;
        // std::cout << best_get_time << std::endl;
    }
    std::cout << "Optimistic Cuckoo (" << NUM_THREADS << " threads): put: " << best_put_time << std::endl;
    std::cout << "Optimistic Cuckoo (" << NUM_THREADS << " threads): get: " << best_get_time << std::endl;


    // Test interleaved reads and writes.
    best_put_time = 1e30;
    best_get_time = 1e30;
    for (int i = 0; i < 3; i++) {
        OptimisticCuckooHashMap<std::string> my_map(2*NUM_BUCKETS);

        std::string* keys = new std::string[NUM_OPS];
        for (int i = 0 ; i < NUM_OPS; i++)
            keys[i] = std::to_string(i);

        // Sequentially put NUM_OPS elements to warm up the hashmap.
        // Do not include this when timing performance.
        for (int j = 0; j < NUM_OPS; j++) {
            std::string key = std::to_string(j);
            my_map.put(key, "value" + key);
        }

        start_time = CycleTimer::currentSeconds();

        pthread_t workers[NUM_THREADS];
        WorkerArgs args[NUM_THREADS];

        for (int j = 0; j < NUM_READERS+NUM_WRITERS; j++) {
            args[j].my_map = (void*)&my_map;
            args[j].thread_id = (long int)j;
            args[j].keys = keys;
            if (j < NUM_READERS)
                args[j].member_function = "get";
            else
                args[j].member_function = "put";
        }

        for (int j = 0; j < NUM_READERS + NUM_WRITERS; j++) {
            pthread_create(&workers[j], NULL, thread_send_requests<OptimisticCuckooHashMap<std::string>>, &args[j]);
        }

        // Only wait for the reader threads to complete before
        // calculating the end time.
        for (int j = 0; j < NUM_READERS; j++) {
            pthread_join(workers[j], NULL);
        }

        end_time = CycleTimer::currentSeconds();
        best_get_time = std::min(best_get_time, end_time-start_time);

        // Now wait for the writer threads to complete.
        for (int j = NUM_READERS; j < NUM_READERS + NUM_WRITERS; j++) {
            pthread_join(workers[j], NULL);
        }

        // std::cout << best_put_time << std::endl;
        std::cout << best_get_time << std::endl << std::endl;
    }
    // std::cout << "Optimistic Cuckoo Interleaved (" << NUM_THREADS << " threads): put: " << best_put_time << std::endl;
    std::cout << "Optimistic Cuckoo Interleaved (" << NUM_THREADS << " threads): get: " << best_get_time << std::endl;

}


// void benchmark_segment_hashmap() {

//     std::cout << "\nBenchmarking segment hashmap..." << std::endl;

//     std::string* keys = new std::string[NUM_OPS];
//     for (int i = 0 ; i < NUM_OPS; i++)
//         keys[i] = std::to_string(i);

//     double start_time, end_time, best_put_time, best_get_time;

//     best_put_time = 1e30;
//     best_get_time = 1e30;
//     for (int i = 0; i < 3; i++) {
//         SegmentHashMap<std::string> my_map(40*NUM_BUCKETS, 64);

//         pthread_t workers[NUM_THREADS];
//         WorkerArgs args[NUM_THREADS];

//         // PUT
//         start_time = CycleTimer::currentSeconds();
//         // for (int j = 0; j < NUM_OPS; j++) {
//         //     std::string key = std::to_string(j);
//         //     my_map.put(key, "value" + key);
//         // }
//         for (int j = 0; j < NUM_THREADS; j++) {
//             args[j].my_map = (void*)&my_map;
//             args[j].thread_id = (long int)j;
//             args[j].member_function = "put";
//             args[j].keys = keys;
//         }
//         for (int j = 0; j < NUM_THREADS; j++) {
//             pthread_create(&workers[j], NULL, thread_send_requests<SegmentHashMap<std::string>>, &args[j]);
//         }
//         for (int j = 0; j < NUM_THREADS; j++) {
//             pthread_join(workers[j], NULL);
//         }
//         end_time = CycleTimer::currentSeconds();
//         best_put_time = std::min(best_put_time, end_time-start_time);


//         // GET
//         start_time = CycleTimer::currentSeconds();
//         for (int j = 0; j < NUM_THREADS; j++) {
//             args[j].my_map = (void*)&my_map;
//             args[j].thread_id = (long int)j;
//             args[j].member_function = "get";
//             args[j].keys = keys;
//         }
//         for (int j = 0; j < NUM_THREADS; j++) {
//             pthread_create(&workers[j], NULL, thread_send_requests<SegmentHashMap<std::string>>, &args[j]);
//         }
//         for (int j = 0; j < NUM_THREADS; j++) {
//             pthread_join(workers[j], NULL);
//         }
//         end_time = CycleTimer::currentSeconds();
//         best_get_time = std::min(best_get_time, end_time-start_time);

//         // std::cout << best_put_time << std::endl;
//         // std::cout << best_get_time << std::endl << std::endl;
//     }
//     std::cout << "Segment Cuckoo (" << NUM_THREADS << " threads): put: " << best_put_time << std::endl;
//     std::cout << "Segment Cuckoo (" << NUM_THREADS << " threads): get: " << best_get_time << std::endl;
// }


void benchmark_hash_functions(){

  std::cout << "\nBenchmarking hash functions..." << std::endl;

  double start_time, end_time, best_time;

  std::string* keys = new std::string[NUM_OPS];


  for (int i = 0 ; i < NUM_OPS ; i++){
      std::string key = std::to_string(i);
      keys[i] = key;
  }

  best_time = 1e30;
  for (int i = 0; i < 3; i++) {
    start_time = CycleTimer::currentSeconds();
    for (int j = 0; j < NUM_OPS; j++) {
      uint32_t h1, h2;
      h1 = 0;
      h2 = 0;

      std::string key = keys[j];
      hashlittle2(key.c_str(), key.length(), &h1, &h2);

      //uint32_t h3 = hashlittle(key.c_str(), key.length(),0);
      //std::cout << "Key: " << key << " h1: " << h1 << " h2: " << h2 << "h3: " << h3 << std::endl;

    }
    end_time = CycleTimer::currentSeconds();
    best_time = std::min(best_time, end_time-start_time);
  }
  std::cout << "hash function time: " << best_time << std::endl;


}

void benchmark_atomic_operations() {

    std::cout << "\nBenchmarking atomic operations..." << std::endl;

    double start_time, end_time, best_time;

    best_time = 1e30;
    for (int i = 0; i < 3; i++) {
        start_time = CycleTimer::currentSeconds();
        int x = 0;
        for (int j = 0; j < NUM_OPS; j++) {
            __sync_fetch_and_add(&x, 0);
        }
        end_time = CycleTimer::currentSeconds();
        best_time = std::min(best_time, end_time-start_time);
    }
    std::cout << "__sync_fetch_and_add time: " << best_time << std::endl;
}


int main() {

    std::cout << "Starting benchmark with NUM_BUCKETS: " << NUM_BUCKETS
              << " and NUM_OPS: " << NUM_OPS << std::endl;

     benchmark_builtin_unorderedmap();
    // benchmark_hashmap();
    // benchmark_cuckoo_hashmap();
    // benchmark_better_cuckoo_hashmap();
    // benchmark_optimistic_cuckoo_hashmap();
    // benchmark_segment_hashmap();

    // benchmark_hash_functions();
    // benchmark_atomic_operations();

    return 0;
}
