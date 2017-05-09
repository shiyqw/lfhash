#include <iostream>
#include <mutex>

#include "common/CycleTimer.h"
#include "common/errors.h"

template <typename T, typename U>
bool LFHashMap<T,U>::CHM::table_full(int reprobe_count, int len) {
    //printf("in reprobe %d %d\n", reprobe_count, len);
    if (reprobe_count >= reprobe_limit) {
        //printf("ret t\n");
        return true;
    } 
    if (slots.load(memory_order_relaxed) >= get_reprobe_limit(len)) {
        //printf("ret t\n");
        return true;
    }
    //printf("ret f\n");

    return false;
}


template <typename T, typename U>
Slot* const LFHashMap<T,U>::match_any(new Slot(false, NULL));
template <typename T, typename U>
Slot* const LFHashMap<T,U>::no_match_old(new Slot(false, NULL));
template <typename T, typename U>
Slot* const LFHashMap<T,U>::tomb_prime(new Slot(true, NULL));
template <typename T, typename U>
Slot* const LFHashMap<T,U>::tomb_stone(new Slot(false, NULL));

template <typename T, typename U>
KVS * LFHashMap<T,U>::CHM::resize(KVS * kvs) {
    KVS * newkvs = this->newkvs.load(memory_order_acquire);
    if (newkvs != NULL) {
        return newkvs;
    }

    int oldlen = kvs->size;
    int size = this->size.load(memory_order_relaxed);
    int newsize = size;

    if (size >= (oldlen>>2) ) {
        newsize = oldlen << 1;
        if (size >= (oldlen>>1)) {
            newsize = oldlen << 2;
        }
    }

    if (newsize <= oldlen) {
        newsize = oldlen << 1;
    }
    if (newsize < oldlen) {
        newsize = oldlen;
    }

    newkvs = this->newkvs.load(memory_order_acquire);
    if(newkvs != NULL) {
        return newkvs;
    }

    newkvs = new KVS(newsize);
    void * chm = (void*) new CHM(size);
    newkvs->data[0].store(chm, memory_order_relaxed);

    KVS * curkvs = this->newkvs.load(memory_order_acquire);
    if (curkvs != NULL) {
        return curkvs;
    } 

    KVS * desired = (KVS*) NULL;
    KVS * old = (KVS*) newkvs;
    //printf("exchange in help\n");
    if(!this->newkvs.compare_exchange_strong(desired, old, memory_order_release, memory_order_relaxed)) {
        //printf(" inside exchange \n");
        delete newkvs;
        newkvs = this->newkvs.load(memory_order_acquire);
    }
    //cout << "after exchange" << newkvs << endl;
    return newkvs;

}

template <typename T, typename U>
void LFHashMap<T,U>::CHM::help_copy(LFHashMap * topmap, KVS * oldkvs) {
    assert (get_chm(oldkvs) == this);
    KVS * newkvs = this->newkvs.load(memory_order_relaxed);
    //for(int i = 0; i < 8; ++i) {
    //    printf("SELN %d\n", val(newkvs, i)==NULL);
    //}
    int oldlen = oldkvs->size;
    int min_copy_work = oldlen>1024?1024:oldlen;
    
    int panic_start = -1;
    int copy_index = 0;

    while (this->copy_done.load(memory_order_relaxed) < oldlen) {
        copy_index = this->copy_index.load(memory_order_relaxed);
        if (panic_start == -1) {
            copy_index = this->copy_index.load(memory_order_relaxed);
            while (copy_index < (oldlen << 1) &&
                        !this->copy_index.compare_exchange_strong(
                            copy_index, copy_index+min_copy_work,
                            memory_order_relaxed, memory_order_relaxed)) {
                copy_index = this->copy_index.load(memory_order_relaxed);
            }
            if (!(copy_index) < (oldlen << 1)) {
                panic_start = copy_index;
            }
        }

        int workdone = 0;

        for(int i = 0; i < min_copy_work; ++i) {
            //printf(" this to copy \n");
            if (copy_slot(topmap, (copy_index+i)&(oldlen-1), oldkvs, newkvs)) {
                ++workdone;
            }
        }
        if (workdone > 0) {
            copy_check_promote(topmap, oldkvs, workdone);
        }

        copy_index += min_copy_work;
        if(panic_start == -1) {
            return;
        }
    }

    copy_check_promote(topmap, oldkvs, 0);
}

template <typename T, typename U>
KVS * LFHashMap<T,U>::CHM::check_slot(LFHashMap * topmap, KVS * oldkvs, int index, void * should_help) {
    //printf("incheckslot0\n");
    KVS * newkvs = this->newkvs.load(memory_order_acquire);
    //printf("incheckslot1\n");
    if (copy_slot(topmap, index, oldkvs, newkvs)) {
        copy_check_promote(topmap, oldkvs, 1);
    }
    //printf("incheckslot\n");

    // Should help copy?
    return (should_help == NULL) ? newkvs : topmap->help_copy(newkvs);
}

template <typename T, typename U>
void LFHashMap<T,U>::CHM::copy_check_promote(LFHashMap * topmap, KVS * oldkvs, int workdone) {
    int oldlen = oldkvs->size;
    int copy_done = this->copy_done.load(memory_order_relaxed);

    if (workdone > 0) {
        while(true) {
            copy_done = this->copy_done.load(memory_order_relaxed);
            if( this->copy_done.compare_exchange_weak(
                            copy_done, copy_done+workdone,
                            memory_order_relaxed, memory_order_relaxed)) {
                break;
            }
        }
    }

    if (copy_done + workdone == oldlen && topmap->mapkvs.load(memory_order_relaxed) == oldkvs) {
        KVS * newkvs = this->newkvs.load(memory_order_acquire);
        //printf("exchange kvs\n");
        topmap->mapkvs.compare_exchange_strong(oldkvs, newkvs, memory_order_release, memory_order_relaxed);
    }
    return;
}

template <typename T, typename U>
bool LFHashMap<T,U>::CHM::copy_slot(LFHashMap * topmap, int index, KVS * oldkvs, KVS * newkvs) {
    //printf(" this to copy in copy %d index \n", index);
    //for(int i = 0; i < 8; ++i) {
    //    if(key(oldkvs, i)!=NULL) cout << i << " " << *((T*) key(oldkvs, i)->ptr) << endl;
    //}
    //cout << "toherehere\n";
    //for(int i = 0; i < 8; ++i) {
    //    if(key(newkvs, i)!=NULL) cout << i << " " << *((T*) key(newkvs, i)->ptr) << endl;
    //    else cout << "NULLHA" << endl;
    //}
    Slot * key_slot;
    while ((key_slot = key(oldkvs, index)) == NULL) {
        CAS_key(oldkvs, index, NULL, tomb_stone);
    }

    Slot * oldval = val(oldkvs, index);
    while (!is_prime(oldval)) {
        Slot * box = (oldval == NULL || oldval == tomb_stone) 
            ? tomb_prime : new Slot(true, oldval->ptr);
        if (CAS_val(oldkvs, index, oldval, box)) {
            if (box == tomb_prime) {
                return true;
            }
            oldval = box;
            break;
        }
        oldval = val(oldkvs, index);
    }

    if (oldval == tomb_prime) {
        return false;
    }

    Slot * old_unboxed = new Slot(false, oldval->ptr);

    //printf("here to pim aha\n");
    bool copied_into_new = put_if_match(topmap, newkvs, key_slot, old_unboxed, NULL) == NULL;

    //printf("copi?%d\n", copied_into_new);

    while (!CAS_val(oldkvs, index, oldval, tomb_prime)) {
        oldval = val(oldkvs, index);
    }

    return copied_into_new;
}


template <typename T, typename U>
LFHashMap<T,U>::LFHashMap(int init_size) {
    //printf("here1\n");
    KVS * kvs = new KVS(init_size);
    void * chm = (void*) new CHM(0);
    //printf("here1 for k0 null %d\n", key(kvs, 0)==NULL);
    kvs->data[0].store(chm, memory_order_relaxed);
    mapkvs.store(kvs, memory_order_relaxed);
    //printf("here2\n");
}

template <typename T, typename U>
LFHashMap<T,U>::~LFHashMap() {
    return;
}

template <typename T, typename U>
U LFHashMap<T,U>::get(T key) {
    //printf("in top get \n");
    //cout << key << endl;
    Slot * key_slot = new Slot(false, &key);
    int fullhash = hash(key_slot);
    KVS * kvs = mapkvs.load(memory_order_acquire);
    Slot * val_slot = get_slot(this, kvs, key_slot, fullhash);
    //Slot * val_slot = NULL;
    //cout << key_slot << fullhash << kvs << val_slot << endl;
    if (val_slot == NULL) {
        //printf("in 1 of getget\n");
        return NULL;
    }
    if (val_slot == tomb_prime) {
        //printf("in 2 of getget\n");
        return NULL;
    }
    //assert (!is_prime(val_slot));
    //return *((U*) (val_slot->ptr));
    return U("0");
}

template <typename T, typename U>
void LFHashMap<T,U>::put(T kkey, U val) {
    //KVS * kvs = this->mapkvs.load(memory_order_acquire);
    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check imm" << endl;
    //    //if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //}
    //cout << kkey << "X" << val << endl;
    T* k = new T(kkey);
    U* v = new U(val);
    //printf("here3\n");
    put_if_match(k, v, no_match_old);
    //printf("here4\n");
    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check imn" << endl;
    //    //if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //}
    return;
}

template <typename T, typename U>
bool LFHashMap<T,U>::remove(T key) {
    return put_if_match(&key, tomb_stone, no_match_old);
}

template <typename T, typename U>
bool LFHashMap<T,U>::replace(T key, U oldval, U newval) {
    return put_if_match(&key, newval, oldval) == oldval;
}

template <typename T, typename U>
int LFHashMap<T,U>::get_size() {
    return 0;
}

template <typename T, typename U>
void LFHashMap<T,U>::resize() {
    return;
}


template <typename T, typename U>
int * LFHashMap<T,U>::get_hashes(KVS * kvs) {
    return (int*) kvs->data[1].load(memory_order_relaxed);
}

template <typename T, typename U>
inline Slot * LFHashMap<T,U>::val(KVS * kvs, int index) {
    //printf(" in find val %d %d\n", index, kvs->size);
    assert (index >= 0 && index < kvs->size);
    Slot * ret = (Slot*) kvs->data[(index*2)+3].load(memory_order_acquire);
    return ret;
}

template <typename T, typename U>
inline Slot* LFHashMap<T,U>::key(KVS * kvs, int index) {
    assert (index >= 0 && index < kvs->size);
    Slot * ret = (Slot*) kvs->data[(index*2)+2].load(memory_order_relaxed);
    return ret;
}

template <typename T, typename U>
int LFHashMap<T,U>::hash(Slot * key_slot) {
    assert (key_slot != NULL);
    //cout << "tohere 1 " << endl;
    T* key = (T*) key_slot->ptr;
    //cout << "key " << *key << endl;
    assert (key != NULL);
    std::hash<T> hasher;
    int h = hasher(*key);
    //printf("tohere %d\n", h);
    h += (h << 15) ^ 0xffffcd7d;
    h ^= (h >> 10);
    h += (h << 3);
    h ^= (h >> 6);
    h += (h << 2) + (h << 14);
    //printf("tohere REt %d\n", h^(h>>16));
    return h ^ (h >> 16);
}

template <typename T, typename U>
inline bool LFHashMap<T,U>::is_prime(Slot * slot) {
    //printf("%d\n", slot == NULL);
    //printf("in isprime \n");
    return (slot != NULL) && slot->prime;
}

template <typename T, typename U>
int LFHashMap<T,U>::get_reprobe_limit(int len) {
    return reprobe_limit + (len>>2);
}

template <typename T, typename U>
bool LFHashMap<T,U>::same_key(Slot * key_slot1, Slot * key_slot2, int * hashes, int hash, int fullhash) {
    assert (key_slot1 != NULL && key_slot2 != NULL);

    //printf("in 10in samekey\n");

    //cout << key_slot1 << " " << key_slot2 << endl;
    //cout << hashes[hash] << endl;
    //cout << *(T*)key_slot1->ptr << endl;
    if (key_slot1 == key_slot2) {
        //printf("in 1 in samekey\n");
        return true;
    } else if ((hashes[hash] == 0 || hashes[hash] == fullhash)  &&
                key_slot1 != tomb_stone && 
                *((T*)key_slot1->ptr) == *((T*)key_slot2->ptr)) {
        //printf("in 1 in samekey\n");
        return true;
    }

    //printf("in 2 in samekey\n");
    return false;

}

template <typename T, typename U>
bool LFHashMap<T,U>::same_val(Slot * val_slot1, Slot * val_slot2) {
    //printf(" in sameval\n");
    assert(val_slot1 != NULL && val_slot2 != NULL);

    if(val_slot1->ptr == NULL) {
        return false;
    }

    if(*((U*)val_slot1->ptr) == *((U*)val_slot2->ptr)) {
        return true;
    }

    return false;
}

template <typename T, typename U>
inline bool LFHashMap<T,U>::CAS_key(KVS * kvs, int index, void * oldval, void * newval) {
    //cout << *((T*) ((Slot*)newval)->ptr) << " " << index << endl;
        //for(int i = 0; i < 8; ++i) {
        //    //if(key(kvs, i)!=NULL) cout << "check i11" << i << " " << *((T*) key(kvs, i)->ptr) << endl;
        //}
   
    //cout << " in cas key " << &(kvs->data[index*2+2]) << endl;
    bool ret = kvs->data[index*2+2].compare_exchange_strong(oldval, newval, memory_order_relaxed, memory_order_relaxed);
        //for(int i = 0; i < 8; ++i) {
        //    //if(key(kvs, i)!=NULL) cout << "check i2 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
        //}
    return ret;
}

template <typename T, typename U>
inline bool LFHashMap<T,U>::CAS_val(KVS * kvs, int index, void * oldval, void * newval) {
    bool ret = kvs->data[index*2+3].compare_exchange_strong(oldval, newval, memory_order_acq_rel, memory_order_relaxed);
    return ret;
}

template <typename T, typename U>
Slot * LFHashMap<T,U>::get_slot(LFHashMap * topmap, KVS * kvs, Slot * key_slot, int fullhash) {
    //printf ("in get\n");
    int len = kvs->size;
    CHM * chm = get_chm(kvs);
    int * hashes = get_hashes(kvs);

    int index = fullhash & (len-1);
    //cout << "indexinget is" << index << endl;
    int reprobe_cnt = 0;
    while (true) {
        Slot * k_slot = key(kvs, index);
        //printf("kisnullingethaha %d\n", k_slot == NULL);
        //cout << *((T*) k_slot->ptr) << endl;
        Slot * v_slot = val(kvs, index);
        //printf("visnullingethaha %d\n", v_slot == NULL);

        if (k_slot == NULL) {
            return NULL;
        } 

        //printf("get here to 1\n");
        if (same_key(k_slot, key_slot, hashes, index, fullhash)) {
            //printf("get to this slot\n");
            if (!is_prime(v_slot)) {
                //printf("get to this slot1\n");
                //cout << "PRIME???" << (v_slot==tomb_prime) << endl;
                return v_slot == tomb_stone ? NULL : v_slot;
            } else {
                //printf("here i get a tomb prime\n");
                return get_slot(topmap, chm->check_slot(topmap, kvs, index, key_slot), 
                            key_slot, fullhash);
            }
        }
        //printf("get here to 2\n");

        if (++reprobe_cnt >= reprobe_limit || key_slot == tomb_stone) {
            KVS * newkvs = chm->newkvs.load(memory_order_acquire);
            return newkvs == NULL ? NULL : get_slot(topmap, topmap->help_copy(newkvs),
                        key_slot, fullhash);
        }
        //printf("get here to 3\n");

        index = (index+1)&(len-1);
    }
}

template <typename T, typename U>
U* LFHashMap<T,U>::put_if_match(T* kkey, U* val, Slot * oldval_slot) {
    KVS * kvs = this->mapkvs.load(memory_order_acquire);
    //cout << "kkkkk " << mapkvs << endl;
    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check im" << endl;
    //    //if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //}
    if(oldval_slot == NULL) {
        return NULL;
    }

    //cout << "lfkey" << *kkey << endl;
    //cout << "thiskeayad" << kkey << endl;
    //cout << * ((T*) kkey) << endl;
    Slot * key_slot = new Slot(false, (void*)kkey);
    //cout << "keyslotadd" << key_slot;
    //cout << * ((T*)key_slot->ptr) << endl;
    //cout << * ((T*) &kkey) << endl;
    Slot * value_slot = new Slot(false, (void*)val);

    //cout << "ali" << kvs->data[2] << endl;
    //cout << "ali" << &(kvs) << endl;
    Slot * ret = put_if_match(this, kvs, key_slot, value_slot, oldval_slot);
    kvs = this->mapkvs.load(memory_order_acquire);
    //cout << "bali" << &kvs << endl;
    //cout << "bali" << &(kvs->data[2]) << endl;

    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check imr" << endl;
    //    cout << (key(kvs, i) == tomb_stone) << "in check imr" << endl;
    //    //if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //}
    assert (ret != NULL && !is_prime(ret));
    return ret == tomb_stone ? NULL : (U*) ret->ptr;
}

template <typename T, typename U>
Slot* LFHashMap<T,U>::put_if_match(LFHashMap * topmap, KVS * kvs, Slot * key_slot, Slot * val_slot, Slot * oldval_slot) {
    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check i0" << endl;
    //    if(key(kvs, i)!=NULL && key(kvs, i)!=tomb_stone) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //    //Slot * key_slot = key(kkvs, index);
    //}

    assert (val_slot != NULL && !is_prime(val_slot) && !is_prime(oldval_slot));

    //cout << "KVSADD" << kvs << endl;
    //cout << "KCLADD" << key_slot << endl;

    //printf("here in pim\n");
    int fullhash = hash(key_slot);
    //printf("here in pim 2\n");
    int len = kvs->size;
    CHM * chm = get_chm(kvs);
    int * hashes = get_hashes(kvs);
    int index = fullhash & (len-1);
    //printf("index is %d %d\n", index, len);

    //printf("here44\n");
    int reprobe_cnt = 0;
    Slot * k_slot, * v_slot;
    KVS * newkvs;

    //for(int i = 0; i < 8; ++i) {
    //    if(key(kvs, i)!=NULL) cout << "check it " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //    //Slot * key_slot = key(kkvs, index);
    //}

    //printf("here5\n");
    while (true) {
        k_slot = key(kvs, index);
        //cout << "KSLOT!" << (k_slot==NULL) << endl;
        //if(k_slot != NULL) cout << "KSLOT!" << *((T*)k_slot->ptr) << endl;
        v_slot = val(kvs, index);
        //cout << "VSLOT!" << (v_slot==NULL) << endl;
        //if(v_slot != NULL) cout << "KSLOT!" << *((U*)v_slot->ptr) << endl;
        //if(v_slot != NULL) printf("jaja %d\n", v_slot->prime);
        if(k_slot == NULL) {
            if(v_slot == tomb_stone) {
                return val_slot;
            }
            if (CAS_key(kvs, index, NULL, key_slot)) {
                chm->slots.fetch_add(1, memory_order_relaxed);
                hashes[index] = fullhash;
                //for(int i = 0; i < 8; ++i) {
                //    if(key(kvs, i)!=NULL) cout << "check iq " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
                //    //Slot * key_slot = key(kkvs, index);
                //}
                break;
            }
            k_slot = key(kvs, index);
            assert (k_slot != NULL);
        }

        //cout << "VSLOT1!" << (v_slot==NULL) << endl;
        //printf("here56\n");
        if(same_key(k_slot, key_slot, hashes, index, fullhash)) {
            break;
        }
        //printf("here57\n");

        if (++reprobe_cnt >= get_reprobe_limit(len) || k_slot == tomb_stone) {
            newkvs = chm->resize(kvs);
            if(oldval_slot != NULL) {
                topmap->help_copy(newkvs);
            }
            return put_if_match(topmap, newkvs, key_slot, val_slot, oldval_slot);
        }
        index = (index+1)&(len-1);
    }


    //printf("here6\n");
    if (val_slot == v_slot) {
        return v_slot;
    }

    newkvs = chm->newkvs.load(memory_order_acquire);
    //printf("here7\n");

    ////printf("%d vslot is null\n", v_slot == NULL);

    if (newkvs == NULL && ((v_slot == NULL && (chm->table_full(reprobe_cnt, len))) || is_prime(v_slot))) {
        //printf("inhere7\n");
        newkvs = chm->resize(kvs);
    }
    //printf("here75\n");

    if (newkvs != NULL) {
        return put_if_match(topmap, chm->check_slot(topmap, kvs, index, oldval_slot),
                    key_slot, val_slot, oldval_slot);
    }

    //printf("here8\n");
    //for(int i = 0; i < 8; ++i) {
    ////    cout << (key(kvs, i) == NULL) << "in check i2" << endl;
    ////    if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //    //Slot * key_slot = key(kkvs, index);
    //}
    while (true) {
        assert (!is_prime(v_slot));

        //cout << "VSLOT2!" << (v_slot==NULL) << endl;
        if (oldval_slot != no_match_old &&
                    v_slot != oldval_slot &&
                    (oldval_slot != match_any || v_slot == tomb_stone || v_slot == NULL) &&
                    !(v_slot == NULL && oldval_slot == tomb_stone) &&
                    (oldval_slot == NULL || !same_val(oldval_slot, v_slot))) {
            //printf("here80 %d\n", v_slot==NULL);
            return v_slot;
        }
        //printf("here81\n");

        if (CAS_val(kvs, index, v_slot, val_slot)) {
            if (oldval_slot != NULL) {
                if ((v_slot == NULL || v_slot == tomb_stone) && val_slot != tomb_stone) {
                    chm->size.fetch_add(1, memory_order_relaxed);
                } 
                if (!(v_slot == NULL || v_slot == tomb_stone) && val_slot == tomb_stone) {
                    chm->size.fetch_add(-1, memory_order_relaxed);
                } 
                //for(int i = 0; i < 8; ++i) {
                //    if(key(kvs, i)!=NULL) cout << "check ir " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
                //    //Slot * key_slot = key(kkvs, index);
                //}
                //if (key(kvs, 2) != NULL) cout << key(kvs, 2)->ptr << " a2" << endl;
            }
    //for(int i = 0; i < 8; ++i) {
    //    cout << (key(kvs, i) == NULL) << "in check i3" << endl;
    ////    if(key(kvs, i)!=NULL) cout << "check i0 " << i << " " << *((T*) key(kvs, i)->ptr) << endl;
    //    //Slot * key_slot = key(kkvs, index);
    //}
    //cout << "cali" << &kvs << endl;
    //cout << "cali" << kvs->data[2] << endl;
            return (v_slot == NULL && oldval_slot != NULL) ? tomb_stone : v_slot;
        }
        //printf("here82\n");

        v_slot = val(kvs, index);

        if(is_prime(v_slot)) {
            return put_if_match(topmap, chm->check_slot(topmap, kvs, index, oldval_slot),
                        key_slot, val_slot, oldval_slot);
        }
    }

    //printf("here9\n");
}

template <typename T, typename U>
KVS * LFHashMap<T,U>::help_copy(KVS * helper) {
    //printf(" help cpy ~\n");
    KVS * topkvs = mapkvs.load(memory_order_acquire);
    CHM * topchm = get_chm(topkvs);

    if(topchm->newkvs.load(memory_order_relaxed) == NULL) {
        return helper;
    } else {
        //printf("here in hc\n");
        topchm->help_copy(this, topkvs);
        return helper;
    }
}
