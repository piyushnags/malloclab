/*
 * mm.c
 *
 * Name: 
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "mm.h"
#include "memlib.h"


/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
#define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16

//Static Functions
static size_t compare_min_size(size_t x, size_t y);
static void printfl();
/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

//Returns the lesser size of the two size_t arguments
static size_t compare_min_size(size_t x, size_t y){
    if (x <= y){
        return x;
    }
    else{
        return y;
    }
}


//Global Data

static void *free_list_head = NULL;

//Debugger func
static void printfl(){
    void *curr = free_list_head;
    void *heap_hi = mem_heap_hi();
    while ((curr != NULL)&&(curr < heap_hi-7)){
        dbg_printf("Head address: %p, Head value: %lu\n", curr, *(unsigned long *)curr);
        curr = (void *)(*(unsigned long *)(curr + 8));
    }
}

/*
 * Initialize: returns false on error, true on success.
 */
//If mem_heap_lo() returns a null pointer, then we must return false
//because the heap functions aren't working. Else, we initialize 
//the heap region and return true

bool mm_init(void)
{
    /* IMPLEMENT THIS */
    void *heap_lo = mem_heap_lo();
    if (heap_lo == NULL){
        return false;
    }
    memset(heap_lo, 0, mem_heapsize());
    return true;
}

/*
 * malloc
 */

/*The malloc function has been broken down into a series of subcases. The explicit free list implementation
  speeds up the code by a significant amount since only the free blocks are traversed. When the malloc function
  is called, it first checks if the heap is empty or not. If the heap is empty, then the program extends the heap,
  intializes the prologue and epilogue, and allocates space to the user without any free list taversal. If the heap is non-empty
  , then the program checks if the free list is empty. If the free list is empty, then the heap is extended without traversal.
  If the free list is non-empty, the free list is traversed to find a suitable free block to allocate to the user.
  If no suitable free block is found, then the heap is extended and space is allocated to the user. Thus, traversal
  only takes place when the free list is not empty.
  
  Allocated blocks of memory have the allocation bit set to 1 at their header and footer to differentiate
  between free and allocated chunks of memory*/
void* malloc(size_t size)
{
    /* IMPLEMENT THIS */
    if (size == 0){
        return NULL;
    }
    size_t aligned_size = align(size);
    void *heap_lo = mem_heap_lo();
    void *heap_hi = mem_heap_hi();
    if ((heap_lo-1) == heap_hi){
        //Initializing emptyheap with prologue, epilogue, and allocating space to user.
        void *mm_prologue1 = heap_lo;
        *(unsigned long *)mm_prologue1 = (unsigned long)1;
        void *header = mem_sbrk((intptr_t)8)+8;
        *(unsigned long *)header = ((unsigned long)aligned_size)|1;
        void *ret_ptr = mem_sbrk((intptr_t)8)+8;
        void *footer = mem_sbrk((unsigned long)aligned_size)+(unsigned long)aligned_size;
        *(unsigned long *)footer = ((unsigned long)aligned_size)|1;
        void *epilogue = mem_sbrk((intptr_t)8)+8;
        *(unsigned long *)epilogue = (unsigned long)1;
        mem_sbrk((intptr_t)8);
        free_list_head = NULL;
        return ret_ptr;
    }
    else{
        if (free_list_head == NULL){
            /*If the free list is empty and the heap is non-empty
              we must extend the heap*/
            void *curr = heap_hi - 7;
            void *ret_ptr = curr + 8;
            void *a = NULL;
            if ((a = mem_sbrk((intptr_t)aligned_size + 16)) == (void *)-1){
                return NULL;
            }
            *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
            curr = curr + 8 + (unsigned long)aligned_size;
            *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
            curr = curr + 8;
            *(unsigned long *)curr = (unsigned long)1;
            return ret_ptr;
        }
        else{
            /*If the free list is not empty and and the heap is not empty
              find a free block to give to the user and remove the current block
              from the free list*/
            if (free_list_head != NULL){
                *(unsigned long *)(free_list_head + 16) = (unsigned long)0;
            }
            void *curr = free_list_head;
            int found = 0;
            unsigned long actual_block_size = 0;
            while ((curr < (heap_hi-7)) && (curr != NULL)){
                unsigned long stored_block_size = *(unsigned long *)curr;
                actual_block_size = stored_block_size & (0xFFFFFFFFFFFFFFFE);
                stored_block_size = (stored_block_size & (0x00000001));
                if ((unsigned long)aligned_size >= actual_block_size){
                    curr = (void *)*(unsigned long *)(curr + 8);
                }
                else{
                    found = 1;
                    break;
                }
            }
            if (found == 1){
                /*If the block is found, remove it from the free list and give the chunk to the user*/                
                void *prev_block = (void *)*(unsigned long *)(curr + 16);
                void *next_block = (void *)*(unsigned long *)(curr + 8);
                
                /*The 4 cases of removing from a linked list, i.e. if the node to be removed
                  is the only node in the free list, if it is the first node, the last node, or 
                  an arbitrary node in the middle of the free list*/
                if ((prev_block == NULL) && (next_block == NULL)){
                    free_list_head = NULL;
                }
                else if (prev_block == NULL){
                    free_list_head = next_block;
                    *(unsigned long *)(next_block + 16) = (unsigned long)0;
                }
                else if (next_block == NULL){
                    *(unsigned long *)(prev_block + 8) = (unsigned long)0;
                }
                else{
                    *(unsigned long *)(prev_block + 8) = (unsigned long)next_block;
                    *(unsigned long *)(next_block + 16) = (unsigned long)prev_block;
                }

                /*If there is insufficient space for predecessor and successor pointers, and for 
                  another pair of header and footer, then there is no need to split the block.
                  Instead, allocate the entire chunk of memory to the user*/
                if (((unsigned long)aligned_size == actual_block_size)||((actual_block_size-(unsigned long)aligned_size) <= 32)){
                    *(unsigned long *)curr = actual_block_size|1;
                    void *ret_ptr = curr + 8;
                    curr = curr + 8 + actual_block_size;
                    *(unsigned long *)curr = actual_block_size|1;
                    return ret_ptr;
                }
                else{
                    /*Here, allocating the entire chunk may not be optimal and hence the block is split.
                    After splitting the block, we must add the remaining smaller portion back on to the free list*/
                    
                    /*Splitting begin*/
                    void *ret_ptr = curr + 8;
                    *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
                    curr = curr + 8 + (unsigned long)aligned_size;
                    *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
                    curr = curr + 8;
                    unsigned long temp_size = actual_block_size - (unsigned long)aligned_size - 16;
                    *(unsigned long *)curr = temp_size;
                    void *new_header = curr;
                    curr = curr + 8 + temp_size;
                    *(unsigned long *)curr = temp_size;
                    /*Splitting end*/
                    
                    /*Adding the split chunk of memory back to the free list*/
                    if (free_list_head != NULL){
                        void *temp_node = free_list_head;
                        *(unsigned long *)(temp_node + 16) = (unsigned long)new_header;
                        *(unsigned long *)(new_header + 8) = (unsigned long)temp_node;
                        *(unsigned long *)(new_header + 16) = (unsigned long)0;
                        free_list_head = new_header;
                    }
                    else{
                        free_list_head = new_header;
                        *(unsigned long *)(new_header + 8) = (unsigned long)0;
                        *(unsigned long *)(new_header + 16) = (unsigned long)0;
                    }
                    curr = curr + 8;
                    return ret_ptr;
                }
            }
            else{
                /*If the block is not found, extend the heap*/
                curr = heap_hi - 7;
                void *ret_ptr = curr + 8;
                void *a = NULL;
                if ((a = mem_sbrk((intptr_t)aligned_size + 16)) == (void *)-1){
                    return NULL;
                }
                *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
                curr = curr + 8 + (unsigned long)aligned_size;
                *(unsigned long *)curr = ((unsigned long)aligned_size)|1;
                curr = curr + 8;
                *(unsigned long *)curr = (unsigned long)1;
                return ret_ptr;
            }
        }
    }
    return NULL;
}

/*
 * free
 */

/*The free function frees the chunk of memory pointed at, and also performs
  coalescing of blocks. Before freeing, the program checks if the neighbouring
  blocks are free or not. If either of the neighboring blocks are free, coalescing takes
  place. Only after coalescing the blocks is the free list updated accordingly.
  More details of how the free list is updated depending on the case are explained
  below. Once the block is freed, it is imperative to set the allocation bit to 0
  to indicate that it is free.*/
void free(void* ptr)
{
    /* IMPLEMENT THIS */
    if (ptr == NULL){
        return;
    }

    /*Some flag variables and size variables to help implement coalescing*/
    int prev_flag = 0;
    int next_flag = 0;
    unsigned long prev_size = *(unsigned long *)(ptr-16);
    unsigned long stored_prev_size = prev_size;
    prev_size = prev_size & (0xFFFFFFFFFFFFFFFE);
    unsigned long curr_size = *(unsigned long *)(ptr-8);
    curr_size = curr_size & (0xFFFFFFFFFFFFFFFE);
    unsigned long next_size = *(unsigned long *)(ptr + curr_size + 8);
    unsigned long stored_next_size = next_size;
    next_size = next_size & (0xFFFFFFFFFFFFFFFE);
    unsigned long prev_check = stored_prev_size & (0x00000001);
    unsigned long next_check = stored_next_size & (0x00000001);
    if (prev_check == 0){
        prev_flag = 1;
    }
    if (next_check == 0){
        next_flag = 1;
    }
    if (free_list_head != NULL){
        *(unsigned long *)(free_list_head + 16) = (unsigned long)0;
    }
    
    //CASE 1: Neither of the neighbouring blocks are free
    if ((prev_flag == 0) && (next_flag == 0)){
        
        //Just need to update allocation bit in header and footer
        void *curr_header = ptr-8;
        unsigned long val_header = *(unsigned long *)curr_header;
        val_header = val_header & (0xFFFFFFFFFFFFFFFE);
        *(unsigned long *)curr_header = val_header;
        void *footer = ptr + val_header;
        *(unsigned long *)footer = val_header;

        /*No coalescing required for this case, just need to add the block to 
          the free list.*/
        if (free_list_head != NULL){
            void *temp_node = free_list_head;
            *(unsigned long *)(temp_node + 16) = (unsigned long)curr_header;
            *(unsigned long *)(curr_header + 8) = (unsigned long)temp_node;
            *(unsigned long *)(curr_header + 16) = (unsigned long)0;
            free_list_head = curr_header;
        }
        else{
            free_list_head = curr_header;
            *(unsigned long *)(curr_header + 8) = (unsigned long)0;
            *(unsigned long *)(curr_header + 16) = (unsigned long)0;
        }   
        assert(mm_checkheap(__LINE__));     
        return;
    }
    
    //CASE 2: Previous adjacent block and next adjacent block are free
    else if ((prev_flag == 1) && (next_flag == 1)){
        
        //Update allocation bit and header/footer info
        void *new_header = ptr - 16 - prev_size - 8;
        void *old_footer = ptr - 16;
        unsigned long old_footer_ptr_val = *(unsigned long *)(old_footer - *(unsigned long *)old_footer + 8);
        *(unsigned long *)new_header = curr_size + prev_size + next_size + 16 + 16;
        void *new_footer = ptr + curr_size + 16 + next_size;
        *(unsigned long *)new_footer = curr_size + prev_size + next_size + 16 + 16;

        /*Need to remove the next block on the free list. There is no need to add
          another block to the free list as the previous block is already on the free
          list*/
        void *iter = ptr + curr_size + 8;
        void *iter_previous = (void *)*(unsigned long *)(iter + 16);
        void *prev_block = (void *)*(unsigned long *)(iter + 16);
        void *next_block = (void *)*(unsigned long *)(iter + 8);
        if ((prev_block == NULL) && (next_block == NULL)){
            free_list_head = NULL;
        }
        else if (prev_block == NULL){
            free_list_head = next_block;
            *(unsigned long *)(next_block + 16) = (unsigned long)0;
        }
        else if (next_block == NULL){
            *(unsigned long *)(prev_block + 8) = (unsigned long)0;
        }
        else{
            *(unsigned long *)(prev_block + 8) = (unsigned long)next_block;
            *(unsigned long *)(next_block + 16) = (unsigned long)prev_block;
        }
        /*Need to update the new previous free block pointer with block pointer
          stored in previous block due to coalescing*/
        
        if ((void *)old_footer_ptr_val != iter){
            *(unsigned long *)(new_header+16) = old_footer_ptr_val;
        }
        else{
            *(unsigned long *)(new_header+16) = (unsigned long)iter_previous;
        }
        assert(mm_checkheap(__LINE__));
        return;
    }
    //CASE 3: Previous adjacent block isn't free, but next adjcent block is free
    else if ((prev_flag == 0) && (next_flag == 1)){
        
        //Updating allocation bit and header/footer info
        void *new_header = ptr - 8;
        *(unsigned long *)new_header = curr_size + 16 + next_size;
        void *new_footer = ptr + curr_size + 16 + next_size;
        *(unsigned long *)new_footer = curr_size + 16 + next_size;
        
        /*Need to remove next block from free list and add the new free block to the 
          free list*/
        void *iter = ptr + curr_size + 8;
        void *prev_block = (void *)*(unsigned long *)(iter + 16);
        void *next_block = (void *)*(unsigned long *)(iter + 8);
        if ((prev_block == NULL) && (next_block == NULL)){
            free_list_head = NULL;
        }
        else if (prev_block == NULL){
            free_list_head = next_block;
            *(unsigned long *)(next_block + 16) = (unsigned long)0;
        }
        else if (next_block == NULL){
            *(unsigned long *)(prev_block + 8) = (unsigned long)0;
        }
        else{
            *(unsigned long *)(prev_block + 8) = (unsigned long)next_block;
            *(unsigned long *)(next_block + 16) = (unsigned long)prev_block;
        }
        /*Need to add the coalesced block (its header) to the free list
          after removing the next block from the free list*/
        if (free_list_head != NULL){
            void *temp_node = free_list_head;
            *(unsigned long *)(temp_node + 16) = (unsigned long)new_header;
            *(unsigned long *)(new_header + 8) = (unsigned long)temp_node;
            *(unsigned long *)(new_header + 16) = (unsigned long)0;
            free_list_head = new_header;
        }
        else{
            free_list_head = new_header;
            *(unsigned long *)(new_header + 8) = (unsigned long)0;
            *(unsigned long *)(new_header + 16) = (unsigned long)0;
        }
        assert(mm_checkheap(__LINE__));
        return;
    }
    else if ((prev_flag == 1) && (next_flag == 0)){
        void *new_header = ptr - 16 - prev_size - 8;
        void *old_footer = ptr - 16;
        unsigned long old_footer_ptr_val = *(unsigned long *)(old_footer - *(unsigned long *)old_footer + 8);
        *(unsigned long *)new_header = prev_size + 16 + curr_size;
        void *new_footer = ptr + curr_size;
        *(unsigned long *)new_footer = prev_size + 16 + curr_size;

        /*Previous block is free and already exists in the free list.
          Hence, there is no need to add the block to the free list again.
          We must update the new footer+8 position with the block pointer*/
        
        *(unsigned long *)(new_header+16) = old_footer_ptr_val;
        assert(mm_checkheap(__LINE__));
        return;
    }
    return;
}

/*
 * realloc
 */

//If oldptr is NULL, return the pointer returned by malloc(size).
//If size is 0, then perform free the memory chunk pointed to by
//oldptr. Allocate new space using malloc, write the minimum of the
//new size and the original block size number of bytes to new
//memory location. After copying data using memcpy, free old space
//and return pointer from malloc.

//If the original size is larger or if the size difference is less
//than space for header & footer, return the same ptr as malloc is 
//not required for this case and the old location remains valid.
void* realloc(void* oldptr, size_t size)
{
    /* IMPLEMENT THIS */
    if (oldptr == NULL){
        void *new_ptr = malloc(size);
        return new_ptr;
    }
    if (size == 0){
        free(oldptr);
        return NULL;
    }
    unsigned long old_size = *(unsigned long *)(oldptr-8);
    old_size = old_size & (0xFFFFFFFFFFFFFFFE);
    if ((old_size >= size) && ((old_size-size) < 16)){
        return oldptr;
    }
    void *new_ptr = malloc(size);
    size_t min_size = compare_min_size(align(size), (size_t)old_size);
    memcpy(new_ptr, (const void *)oldptr, min_size);
    free(oldptr);
    return new_ptr;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
    /* Write code to check heap invariants here */
    /* IMPLEMENT THIS */
    void *heap_lo = mem_heap_lo();
    void *curr = heap_lo + 8;
    void *heap_hi = mem_heap_hi() - 7;
    
    /*Checks if free list head is corrupted or if it is not getting updated correctly*/
    if (free_list_head != NULL){
        if (*(unsigned long *)(free_list_head + 16) != (unsigned long)0){
            dbg_printf("Free list head is corrupted, prev pointer of head is not null\n");
            return false;
        }
    }
    /*Checks if the free blocks in the free list are actually marked as free
      Also checks if the pointers in the free block point to valid heap addresses*/
    curr = free_list_head;
    while ((curr < heap_hi - 7)&&(curr != NULL)){
        unsigned long stored_header_val = *(unsigned long *)curr;
        unsigned long block_size = stored_header_val & (0xFFFFFFFFFFFFFFFE);
        unsigned long stored_footer_val = *(unsigned long *)(curr + 8 + block_size);
        void *next_free_block = (void *)*(unsigned long *)(curr + 8);
        void *prev_free_block = (void *)*(unsigned long *)(curr + 16);
        if (next_free_block != NULL){
            if ((next_free_block < heap_lo) || (next_free_block > heap_hi)){
                dbg_printf("Next free block pointer points to invalid address, Invalid pointer: %p\n", next_free_block);
                return false;
            }
        }
        if (prev_free_block != NULL){
            if ((prev_free_block < heap_lo) || (prev_free_block > heap_hi)){
                dbg_printf("Prev free block pointer points to invalid address, Invalid pointer: %p\n", prev_free_block);
                return false;
            }
        }
        if ((stored_header_val&(0x1)) == (unsigned long)1){
            dbg_printf("Dirty header value for free block: %p\n", curr);
            return false;
        }
        if ((stored_footer_val&(0x1)) == (unsigned long)1){
            dbg_printf("Dirty footer value for free block: %p\n", curr);
            return false;
        }
        curr = next_free_block;
    }

    /*Checks if the headers and footers are the same for a given arbitrary block
      Checks if there are any contiguous blocks of memory that are not coalesced*/
    curr = heap_lo + 8;
    while (curr < heap_hi - 7){
        unsigned long curr_size = (*(unsigned long *)curr)&((0xFFFFFFFFFFFFFFFE));
        unsigned long header_val = *(unsigned long *)curr;
        unsigned long footer_val = *(unsigned long *)(curr + 8 + curr_size);
        void *next_block = curr + 8 + curr_size + 8;
        unsigned long is_curr_free = (*(unsigned long *)curr)&(0x1);
        unsigned long is_next_free = (*(unsigned long *)next_block)&(0x1);
        if (header_val != footer_val){
            dbg_printf("Mismatch at block header: %p, block footer: %p\nHeader val: 0x%lx, Footer val: 0x%lx\n", curr, curr + 8 + curr_size, header_val, footer_val);
            return false;
        }
        if (is_curr_free == 0){
            if (is_next_free == 0){
                dbg_printf("Blocks not coalesced correctly during free. Current Block: %p, Next Block: %p\n", curr, next_block);
                return false;
            }
        }
        curr = next_block;
    }

#endif /* DEBUG */
    return true;
}