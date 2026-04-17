// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

typedef struct {
    uint32_t mode;
    ObjectID hash;
    char path[512];
} TreeIndexEntry;

typedef struct {
    TreeIndexEntry entries[10000];
    int count;
} TreeIndex;

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

static int load_index_for_tree(TreeIndex *index) {
    if (!index) {
        return -1;
    }

    index->count = 0;
    FILE *index_file = fopen(INDEX_FILE, "r");
    if (!index_file) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }

    int max_entries = (int)(sizeof(index->entries) / sizeof(index->entries[0]));
    char line_buf[2048];
    while (fgets(line_buf, sizeof(line_buf), index_file)) {
        if (index->count >= max_entries) {
            fclose(index_file);
            return -1;
        }

        TreeIndexEntry *entry = &index->entries[index->count];
        char hash_hex[HASH_HEX_SIZE + 1];
        unsigned int entry_mode;
        unsigned long long ignored_mtime;
        unsigned int ignored_size;
        char entry_path[sizeof(entry->path)];

        int parsed_fields = sscanf(line_buf, "%o %64s %llu %u %511[^\n]",
                                   &entry_mode, hash_hex, &ignored_mtime, &ignored_size, entry_path);
        if (parsed_fields != 5) {
            fclose(index_file);
            return -1;
        }

        if (hex_to_hash(hash_hex, &entry->hash) != 0) {
            fclose(index_file);
            return -1;
        }

        entry->mode = entry_mode;
        snprintf(entry->path, sizeof(entry->path), "%s", entry_path);
        index->count++;
    }

    fclose(index_file);
    return 0;
}

static int build_tree_level(const TreeIndex *index, const char *prefix, ObjectID *id_out) {
    Tree level_tree;
    level_tree.count = 0;

    size_t prefix_length = strlen(prefix);
    for (int entry_idx = 0; entry_idx < index->count; entry_idx++) {
        const char *indexed_path = index->entries[entry_idx].path;
        if (prefix_length > 0 && strncmp(indexed_path, prefix, prefix_length) != 0) {
            continue;
        }

        const char *suffix_path = indexed_path + prefix_length;
        if (suffix_path[0] == '\0') {
            continue;
        }

        const char *slash_pos = strchr(suffix_path, '/');
        if (!slash_pos) {
            if (level_tree.count >= MAX_TREE_ENTRIES) {
                return -1;
            }

            TreeEntry *file_entry = &level_tree.entries[level_tree.count++];
            file_entry->mode = index->entries[entry_idx].mode;
            file_entry->hash = index->entries[entry_idx].hash;
            snprintf(file_entry->name, sizeof(file_entry->name), "%s", suffix_path);
            continue;
        }

        size_t dir_name_len = (size_t)(slash_pos - suffix_path);
        if (dir_name_len == 0 || dir_name_len >= 256) {
            return -1;
        }

        char dir_name[256];
        memcpy(dir_name, suffix_path, dir_name_len);
        dir_name[dir_name_len] = '\0';

        int dir_already_present = 0;
        for (int tree_idx = 0; tree_idx < level_tree.count; tree_idx++) {
            if (level_tree.entries[tree_idx].mode == MODE_DIR && strcmp(level_tree.entries[tree_idx].name, dir_name) == 0) {
                dir_already_present = 1;
                break;
            }
        }
        if (dir_already_present) {
            continue;
        }

        char child_prefix_path[1024];
        snprintf(child_prefix_path, sizeof(child_prefix_path), "%s%s/", prefix, dir_name);

        ObjectID child_tree_id;
        int child_result = build_tree_level(index, child_prefix_path, &child_tree_id);
        if (child_result != 0) {
            return -1;
        }

        if (level_tree.count >= MAX_TREE_ENTRIES) {
            return -1;
        }

        TreeEntry *dir_entry = &level_tree.entries[level_tree.count++];
        dir_entry->mode = MODE_DIR;
        dir_entry->hash = child_tree_id;
        snprintf(dir_entry->name, sizeof(dir_entry->name), "%s", dir_name);
    }

    if (level_tree.count == 0) {
        return -1;
    }

    void *serialized_data = NULL;
    size_t serialized_len = 0;
    if (tree_serialize(&level_tree, &serialized_data, &serialized_len) != 0) {
        return -1;
    }

    int write_result = object_write(OBJ_TREE, serialized_data, serialized_len, id_out);
    free(serialized_data);
    return write_result;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    if (!id_out) {
        return -1;
    }

    TreeIndex tree_index;
    if (load_index_for_tree(&tree_index) != 0) {
        return -1;
    }

    if (tree_index.count == 0) {
        return -1;
    }

    return build_tree_level(&tree_index, "", id_out);
}