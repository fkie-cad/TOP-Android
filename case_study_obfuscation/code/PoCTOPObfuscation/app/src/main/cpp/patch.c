//
// Created by kuehnemann on 22.09.23.
//

#include <jni.h>

#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include <android/log.h>

#include "table.h"

#define READ_QWORD(address) *(uint64_t*)(address)
#define WRITE_QWORD(address, value) *(uint64_t*)address = value

/**
 * Obfuscation Techniques:
 * - Throw Oriented Programming
 * - "Malicious"/Flag code encoded in large random byte table (size = 2^16)
 *
 * Virtual Register Assignments:
 * - v0: Exception object used for returning from gadget to dispatcher.
 * - v1: Virtual program counter that selects the next gadget to run.
 * - v2: Secret key used for decryption.
 * - v3: Character array of decoded values. Later returned.
 * - v4: Temporary register holding en/decrypted message characters.
 * - v5: Array index register for filling output array.
 *
 * Assumptions:
 * - JNIEnv::GetStaticMethodID on static method "getText" of Test returns an ArtMethod*, not an encoded id.
 *
 * Further Ideas:
 * - One may use Scudo's (heap allocator) randomness by allocating all required gadgets and more
 *   through the primary allocator. If the current batch in Scudo is big enough, then a lot of
 *   (superfluous) gadgets can be stored with offsets less than 2^31-1. These "small" offsets are
 *   required by the dispatcher. E.g. allocate small memory chunks via malloc until the smallest
 *   and largest address observed differ by "a lot" (determine through analysing Scudo source code
 *   or observe that all batches are allocated through mmap, meaning ASLR introduces large gaps).
 *   Then start allocating (distraction) gadgets through primary (random chunk order is a feature).
 *   Distraction gadgets e.g. like the random table used here.
 * */

#define NAME_CLASS "com/top/poctopobfuscation/Test"
#define NAME_METHOD "getText"
#define SIGNATURE_METHOD "()V"

// android/content/ActivityNotFoundException in classes.dex of THIS .apk file.
#define EXCEPTION_TYPE "\x55\x00"

/**
 * Layout:
 * BUFFER -> -----------------------
 *           |                     |
 *           |       Bytecode      |
 *           |      Dispatcher     |
 *           |                     |
 * +0x200    -----------------------
 *           |                     |
 *           |       Random        |
 *           |       Table         |
 *           |        with         |
 *           |       Gadgets       |
 *           |                     |
 *           -----------------------
 * */
#define SIZE_BYTECODE (0x200)
#define SIZE_TABLE (1 << 16)
#define SIZE_BUFFER (SIZE_BYTECODE + SIZE_TABLE)
static uint8_t BUFFER[SIZE_BUFFER];
#define ADDRESS_BYTECODE ((uint64_t)BUFFER)
#define ADDRESS_TABLE ((uint64_t)ADDRESS_BYTECODE + SIZE_BYTECODE)

// new-instance v0, #+0xffff
#define BYTECODE_NEW_INSTANCE ("\x22\x00" EXCEPTION_TYPE)
#define SIZE_NEW_INSTANCE 4

// const/4 v1, #-1
#define BYTECODE_SET_COUNTER "\x12\xf1"
#define SIZE_SET_COUNTER 2

// add-int/lit8 v1, v1, #+1
#define BYTECODE_INCREMENT_COUNTER "\xd8\x01\x01\x01"
#define SIZE_INCREMENT_COUNTER 4
#define OFFSET_LOOP (SIZE_NEW_INSTANCE + SIZE_SET_COUNTER)

// packed-switch v1, #+3
#define BYTECODE_DISPATCHER "\x2b\x01\x03\x00\x00\x00"
#define SIZE_DISPATCHER 6
#define OFFSET_DISPATCHER (OFFSET_LOOP + SIZE_INCREMENT_COUNTER)

#define SIZE_CODE_ITEM_HEADER sizeof (struct CodeItem)
#define JUMP_OFFSET(OFFSET_GADGET)\
    (((ADDRESS_TABLE + OFFSET_GADGET) - (ADDRESS_BYTECODE + SIZE_CODE_ITEM_HEADER + OFFSET_DISPATCHER)) >> 1)

#define JUMP_TABLE {\
    JUMP_OFFSET(0x2c98),\
    JUMP_OFFSET(0x4660),\
    JUMP_OFFSET(0xea4e),\
    JUMP_OFFSET(0xa182),\
    JUMP_OFFSET(0xd89c),\
    JUMP_OFFSET(0x2578),\
    JUMP_OFFSET(0xab9e),\
    JUMP_OFFSET(0x17c6),\
    JUMP_OFFSET(0x648),\
    JUMP_OFFSET(0x374e),\
    JUMP_OFFSET(0x295e),\
    JUMP_OFFSET(0x927e),\
    JUMP_OFFSET(0x69d8),\
    JUMP_OFFSET(0xb8b6),\
    JUMP_OFFSET(0x2d14),\
    JUMP_OFFSET(0x1536),\
    JUMP_OFFSET(0xce96),\
    JUMP_OFFSET(0x6be2),\
    JUMP_OFFSET(0x14e8),\
    JUMP_OFFSET(0x9ce),\
    JUMP_OFFSET(0x41bc),\
    JUMP_OFFSET(0x369c),\
}

#define SIZEOF(x) (sizeof (x) / sizeof (x[0]))

uint64_t get_libart_base(JNIEnv *env);
uint64_t get_execute_nterp_impl_address(uint64_t base_libart);
uint64_t get_static_method_address(JNIEnv *env);
void setup_bytecode(uint8_t *bytecode, uint64_t size);
void hijack_method(JNIEnv *env);

/**
 * Runtime method description used for hijacking control flow in bytecode.
 * */
struct ArtMethod {
    uint32_t declaring_class;
    uint32_t access_flags;
    uint32_t dex_method_index;
    uint16_t method_index;
    union {
        uint16_t hotness_count;
        uint16_t imt_index;
    };

    struct PtrSizedFields {
        uint64_t data;
        uint64_t entry_point_from_quick_compiled_code;
    } ptr_sized_fields;
};

/**
 * Description of a method. Instructions follow this struct.
 * */
struct CodeItem {
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    uint16_t tries_size;
    uint32_t debug_info_off;
    uint32_t insns_size;
};

/**
 * Table of case - offsets. The actual array of offsets follows this struct.
 * */
struct PackedSwitchPayload {
    uint16_t ident;
    uint16_t size;
    int32_t first_key;
};

/**
 * try - region determining the region of covered instructions.
 * */
struct TryItem {
    uint32_t start_address;
    uint16_t insn_count;
    uint16_t handler_offset;
};

uint64_t get_libart_base(JNIEnv *env) {
    return (uint64_t)(*env)->NewByteArray - 0x5f97f4;
}

uint64_t get_execute_nterp_impl_address(uint64_t base_libart) {
    return base_libart + 0x200090;
}

uint64_t get_static_method_address(JNIEnv *env) {
    jclass cls = (*env)->FindClass(env, "com/top/poctopobfuscation/Test");
    return (uint64_t)(*env)->GetStaticMethodID(env, cls, "getText", "()[C");
}

void setup_bytecode(uint8_t *bytecode, uint64_t size) {

    memset(bytecode, '\0', SIZE_BYTECODE);
    uint8_t temp[] = TABLE;
    memcpy(bytecode + SIZE_BYTECODE, temp, SIZE_TABLE);

    // Setup code item
    struct CodeItem *code_item = (struct CodeItem*)bytecode;
    code_item->registers_size = 5;
    code_item->ins_size = 0;
    code_item->outs_size = 0;
    code_item->tries_size = 1;
    code_item->debug_info_off = 0;

    // Write dispatcher into bytecode;
    uint64_t current = sizeof (struct CodeItem);

    memcpy(bytecode + current, BYTECODE_NEW_INSTANCE, SIZE_NEW_INSTANCE);
    current += SIZE_NEW_INSTANCE;
    memcpy(bytecode + current, BYTECODE_SET_COUNTER, SIZE_SET_COUNTER);
    current += SIZE_SET_COUNTER;
    memcpy(bytecode + current, BYTECODE_INCREMENT_COUNTER, SIZE_INCREMENT_COUNTER);
    current += SIZE_INCREMENT_COUNTER;
    memcpy(bytecode + current, BYTECODE_DISPATCHER, SIZE_DISPATCHER);
    current += SIZE_DISPATCHER;

    // Write jump table
    int32_t jump_table[] = JUMP_TABLE;
    struct PackedSwitchPayload *jumps = (struct PackedSwitchPayload*)(bytecode + current);
    jumps->ident = 0x100;
    jumps->size = SIZEOF(jump_table);
    jumps->first_key = 0;
    current += sizeof (struct PackedSwitchPayload);

    uint8_t i;
    for (i = 0; i < jumps->size; i++) {
        memcpy(bytecode + current, (uint8_t*)&jump_table[i], sizeof (jump_table[i]));
        current += sizeof (jump_table[i]);
    }

    code_item->insns_size = ((current - sizeof (struct CodeItem)) >> 1);

    // Prepare exception handlers
    struct TryItem *try = (struct TryItem*)(bytecode + current);
    try->start_address = 0;
    try->insn_count = 0xffff;
    try->handler_offset = 0x1;

    current += sizeof (struct TryItem);

    // As it is tricky to model LEB128 without implementing it (which is unnecessessary effort),
    // it will be hardcoded.
    current += (uint64_t)bytecode;
    *(uint8_t*)(current + 0) = 0x1;   // number of handlers
    *(uint8_t*)(current + 1) = 0;   // size of catch handler: 0 -> catch all
    *(uint8_t*)(current + 2) = (OFFSET_LOOP >> 1);    // offset of dispatcher relative to method start in code units
}

void hijack_method(JNIEnv *env) {
    // 1. Get libart.so base
    uint64_t base_libart = get_libart_base(env);

    // 2. Get address of ArtMethod of Test::<init>
    uint64_t addr_init = get_static_method_address(env);
    struct ArtMethod *method = (struct ArtMethod*)addr_init;

    // 3. Prepare bytecode
    setup_bytecode(BUFFER, SIZE_BUFFER);

    // 4. Overwrite addresses in ArtMethod
    uint64_t ExecuteNterpImpl = get_execute_nterp_impl_address(base_libart);
    method->ptr_sized_fields.entry_point_from_quick_compiled_code = ExecuteNterpImpl;
    method->ptr_sized_fields.data = (uint64_t)BUFFER;
}

JNIEXPORT
void
JNICALL
Java_com_top_poctopobfuscation_MainActivity_setup(
        JNIEnv *env,
        jobject /* this */) {
    hijack_method(env);
}