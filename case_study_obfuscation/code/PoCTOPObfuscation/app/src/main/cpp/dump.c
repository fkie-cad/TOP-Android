//
// Created by kuehnemann on 25.09.23.
//
/*struct Node {
    uint64_t key;
    const char *value;
    struct Node *left;
    struct Node *right;
    struct Node *parent;
};

uint64_t debug = 0;
void construct_tree(uint64_t address, struct Node *current) {

    uint64_t addr_oat_file = address + 0x20;
    uint64_t oat_file = READ_QWORD(addr_oat_file);

    uint64_t addr_file_name = oat_file + 0x18;
    const char *file_name = (const char*)READ_QWORD(addr_file_name);

    current->key = oat_file;
    current->value = file_name;

    uint64_t addr_child;
    uint64_t child;
    struct Node *node;

    // Go left child
    addr_child = address + 0x0;
    child = READ_QWORD(addr_child);
    if (child != 0) {
        node = (struct Node*)calloc(1, sizeof(struct Node));
        node->parent = current;
        current->left = node;

        construct_tree(child, node);
    }

    // Go right child
    addr_child = address + 0x8;
    child = READ_QWORD(addr_child);
    if (child != 0) {
        node = (struct Node*)calloc(1, sizeof(struct Node));
        node->parent = current;
        current->right = node;

        construct_tree(child, node);
    }
}

struct Node *traverse_name_search(struct Node *root, const char *name) {

    if (strstr(root->value, name) != NULL) {
        return root;
    }

    struct Node *result = NULL;
    if (root->left != NULL) {
        result = traverse_name_search(root->left, name);
    }
    if (result == NULL && root->right != NULL) {
        result = traverse_name_search(root->right, name);
    }

    return result;
}

uint64_t get_vdex_base(JNIEnv *env) {

    // NewByteArray at 0x5b9144 relative to libart.so
    // NewByteArray at 0x5f97f4 relative to libart.so in release build
    uint64_t base_libart = (uint64_t)(*env)->NewByteArray - 0x5f97f4;

    // art::Runtime::instance_ at 0xa158e0 relative to libart.so
    uint64_t addr_instance_ = base_libart + 0xa158e0;
    uint64_t instance_ = READ_QWORD(addr_instance_);

    // oat_file_manager_ at 0x570 relative to art::Runtime
    uint64_t addr_oat_file_manager_ = instance_ + 0x570;
    uint64_t oat_file_manager_ = READ_QWORD(addr_oat_file_manager_);

    // oat_files_ at 0x8 relative to OatFileManager
    uint64_t addr_oat_files = oat_file_manager_ + 0x8;
    uint64_t oat_files_ = READ_QWORD(addr_oat_files);

    // Create tree
    uint64_t addr_root = oat_files_ + 0x0;
    uint64_t key_root = addr_root;

    struct Node *root = (struct Node*)calloc(1, sizeof(struct Node));
    construct_tree(key_root, root);

    // Iterate through tree and search for base.odex
    struct Node *match = traverse_name_search(root, "/base.odex");
    if (match == NULL) {
        return 0;
    }

    uint64_t base_odex = match->key;
    if (base_odex == 0) {
        return 0;
    }

    uint64_t addr_base_vdex = base_odex + 0x70;
    return READ_QWORD(addr_base_vdex);
}

void destroy_tree(struct Node *root) {

    if (root->left != NULL) {
        destroy_tree(root->left);
        root->left = NULL;
    }

    if (root->right != NULL) {
        destroy_tree(root->right);
        root->right = NULL;
    }

    free(root);
}

void list_env(JNIEnv *env) {

    uint64_t i;
    char buffer[64];

    for (i = 0; i < sizeof (**env); i += 8) {

        memset(buffer, '\0', sizeof (buffer));
        snprintf(buffer, sizeof (buffer), "%#lx", (uint64_t)*(env + i));
        __android_log_write(ANDROID_LOG_INFO, "ENV DUMP: ", buffer);
    }
}

void print_long(const char *prefix, uint64_t val) {
    char buffer[64] = { 0 };
    snprintf(buffer, sizeof (buffer), "%#lx", (uint64_t)val);
    __android_log_write(ANDROID_LOG_INFO, prefix, buffer);
}



void test_alloc() {
#define SIZE 256
    void *ptrs[SIZE] = { 0 };

    ptrs[0] = malloc(0x20);
    uint64_t min = (uint64_t)ptrs[0];
    uint64_t max = min;

    uint64_t i;
    uint64_t current;
    for (i = 1; i < SIZE; i++) {
        ptrs[i] = malloc(0x40);
        current = (uint64_t)ptrs[i];
        if (min > current) {
            min = current;
        } else if (max < current) {
            max = current;
        }
    }

    // USE PTRS HERE

    // Free
    char buffer[64] = { 0 };
    for (i = 0; i < SIZE; i++) {
        snprintf(buffer, 64, "%#lx", ptrs[i]);
        __android_log_write(ANDROID_LOG_INFO, "PTRS", buffer);
        free(ptrs[i]);
    }
}
 */