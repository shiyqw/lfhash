#ifndef LF_HASHMAP_H
#define LF_HASHMAP_H

#include <atomic>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

using namespace std;

struct KVS {
    int size;
    atomic<void*> * data;
    
    KVS(int _size) {
        size = _size;
        int real_size = (_size << 1) + 2;
        data = new atomic<void*> [real_size];
        int * hashes = new int[size];
        for(int i = 0; i < size; ++i) {
            hashes[i] = 0;
        }

        for(int i = 2; i < real_size; ++i) {
            data[i].store(NULL, memory_order_relaxed);
        }

        data[1].store(hashes, memory_order_relaxed);
        //printf(" data24 %d\n", data[2]==NULL);
    }

    ~KVS() {
        int * hashes = (int*) data[1].load(memory_order_relaxed);

        delete hashes;
        delete [] data;
    }
};

struct Slot {
    bool prime;
    void *ptr;

    Slot(bool _prime, void * p) {
        prime = _prime;
        ptr = p;
    }
};


template <typename T, typename U>
class LFHashMap {


    friend class CHM;
    //friend class LFHashMap<T, U>;
    
    private:
        class CHM {
            friend class LFHashMap;

            private:
                atomic<KVS*> newkvs;

                atomic_int size;

                atomic_int slots;

                atomic_int copy_index;

                atomic_int copy_done;
            
            public:
                CHM(int _size) {
                    newkvs.store(NULL, memory_order_relaxed);
                    size.store(_size, memory_order_relaxed);
                    slots.store(_size, memory_order_relaxed);
                    copy_index.store(_size, memory_order_relaxed);
                    copy_done.store(_size, memory_order_relaxed);

                }

            private:
                bool table_full(int reprobe_count, int len);

                KVS * resize(KVS * kvs);

                void help_copy(LFHashMap * topmap, KVS * oldkvs);

                KVS * check_slot_and_copy(LFHashMap * topmap, KVS * oldkvs, int index, void * should_help);

                void check_slot_and_promote(LFHashMap * topmap, KVS * oldkvs, int workdone);

                bool copy_slot(LFHashMap * topmap, int index, KVS * oldkvs, KVS * newkvs);

        };

	public:
		LFHashMap(int table_size=64); // imp

		~LFHashMap(); // imp

		U get(T key); // imp

		void put(T key, U val); // imp

        void put_if_absent(T key, U val); // imp

		bool remove(T key); // imp

        bool replace(T key, U oldval, U newval); // imp

		float get_load_factor(); // imp

		int get_size(); // imp

	private:

        static Slot* const match_any;
        static Slot* const no_match_old;

        static Slot* const tomb_prime;
        static Slot* const tomb_stone;

        static const int reprobe_limit = 10;

        static const int init_size = 64;

        atomic<KVS*> mapkvs;

		void resize();

        static CHM * get_chm(KVS * kvs) {
            CHM * ret = (CHM*) (kvs->data[0].load(memory_order_relaxed));
            return ret;
        }

        static int * get_hashes(KVS * kvs);

        static inline Slot* key(KVS * kvs, int index);
        
        static inline Slot * val(KVS * kvs, int index);
        
        static int hash(Slot * key_slot);

        static inline bool is_prime(Slot * slot);

        static int get_reprobe_limit(int len);
        
        static bool same_key(Slot * key_slot1, Slot * key_slot2, int * hashes, int hash, int fullhash);
        
        static bool same_val(Slot * val_slot1, Slot * val_slot2);
        
        static inline bool CAS_key(KVS * kvs, int index, void * oldval, void * newval);
        
        static inline bool CAS_val(KVS * kvs, int index, void * oldval, void * newval);
        
        Slot * get_slot(LFHashMap * topmap, KVS * kvs, Slot * key_slot, int fullhash); // imp
        U* put_if_match(T* key, U* val, Slot * oldval_slot); // imp

        static Slot* put_if_match(LFHashMap* topmap, KVS * kvs, Slot * key_slot, Slot * val_slot, Slot * newval_slot);

        KVS * help_copy(KVS * helper);

};

#include "lf_hash_map.cpp"

#endif
