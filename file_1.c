#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BUFFER_SIZE 64

typedef struct {
    uint8_t prev_tx_hash[32];
    uint32_t prev_tx_index;
    uint64_t script_length;
    uint8_t *script;
    uint32_t sequence;
    char address[35];
} TxInput;

typedef struct {
    uint64_t value;
    uint64_t script_length;
    uint8_t *script;
    char address[35];
} TxOutput;

typedef struct {
    uint32_t version;
    uint64_t input_count;
    TxInput *inputs;
    uint64_t output_count;
    TxOutput *outputs;
    uint32_t locktime;
} BitcoinTransaction;

typedef struct {
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_length;
    size_t total_length;
    BitcoinTransaction transaction;
    size_t offset;
    int state;
    int input_index;
    int output_index;
} Deserializer;

void init_deserializer(Deserializer *deserializer) {
    deserializer->buffer_length = 0;
    deserializer->total_length = 0;
    deserializer->offset = 0;
    deserializer->state = 0;
    deserializer->input_index = 0;
    deserializer->output_index = 0;
    memset(&deserializer->transaction, 0, sizeof(BitcoinTransaction));
}

uint64_t read_varint(const uint8_t *data, size_t *offset) {
    uint8_t first = data[*offset];
    (*offset)++;
    if (first < 0xfd) {
        return first;
    } else if (first == 0xfd) {
        uint16_t value = data[*offset] | (data[*offset + 1] << 8);
        *offset += 2;
        return value;
    } else if (first == 0xfe) {
        uint32_t value = data[*offset] | (data[*offset + 1] << 8) |
                         (data[*offset + 2] << 16) | (data[*offset + 3] << 24);
        *offset += 4;
        return value;
    } else {
        uint64_t value = (uint64_t)data[*offset] |
                         ((uint64_t)data[*offset + 1] << 8) |
                         ((uint64_t)data[*offset + 2] << 16) |
                         ((uint64_t)data[*offset + 3] << 24) |
                         ((uint64_t)data[*offset + 4] << 32) |
                         ((uint64_t)data[*offset + 5] << 40) |
                         ((uint64_t)data[*offset + 6] << 48) |
                         ((uint64_t)data[*offset + 7] << 56);
        *offset += 8;
        return value;
    }
}

void parse_input_script(const uint8_t *script, uint64_t script_length, char *address) {
    snprintf(address, 35, "script: ");
    for (uint64_t i = 0; i < script_length && (2 * i + 8) < 34; ++i) {
        snprintf(address + strlen(address), 3, "%02x", script[i]);
    }
}

void parse_output_script(const uint8_t *script, uint64_t script_length, char *address) {
    snprintf(address, 35, "script: ");
    for (uint64_t i = 0; i < script_length && (2 * i + 8) < 34; ++i) {
        snprintf(address + strlen(address), 3, "%02x", script[i]);
    }
}

int add_chunk(Deserializer *deserializer, const uint8_t *chunk, size_t chunk_length) {
    memcpy(deserializer->buffer + deserializer->buffer_length, chunk, chunk_length);
    deserializer->buffer_length += chunk_length;
    deserializer->total_length += chunk_length;

    size_t offset = deserializer->offset;
    BitcoinTransaction *tx = &deserializer->transaction;

    while (offset < deserializer->buffer_length) {
        switch (deserializer->state) {
            case 0: // Version
                if (deserializer->buffer_length >= 4) {
                    tx->version = *((uint32_t *)(deserializer->buffer + offset));
                    offset += 4;
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
            case 1: // Input count
                if (offset < deserializer->buffer_length) {
                    tx->input_count = read_varint(deserializer->buffer, &offset);
                    tx->inputs = calloc(tx->input_count, sizeof(TxInput));
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
            case 2: // Inputs
                while (deserializer->input_index < tx->input_count) {
                    TxInput *input = &tx->inputs[deserializer->input_index];
                    if (offset + 32 <= deserializer->buffer_length) {
                        memcpy(input->prev_tx_hash, deserializer->buffer + offset, 32);
                        offset += 32;
                    } else {
                        return 0;
                    }
                    if (offset + 4 <= deserializer->buffer_length) {
                        input->prev_tx_index = *((uint32_t *)(deserializer->buffer + offset));
                        offset += 4;
                    } else {
                        return 0;
                    }
                    input->script_length = read_varint(deserializer->buffer, &offset);
                    if (offset + input->script_length <= deserializer->buffer_length) {
                        input->script = malloc(input->script_length);
                        memcpy(input->script, deserializer->buffer + offset, input->script_length);
                        parse_input_script(input->script, input->script_length, input->address);
                        offset += input->script_length;
                    } else {
                        return 0;
                    }
                    if (offset + 4 <= deserializer->buffer_length) {
                        input->sequence = *((uint32_t *)(deserializer->buffer + offset));
                        offset += 4;
                    } else {
                        return 0;
                    }
                    deserializer->input_index++;
                }
                deserializer->state++;
                break;
            case 3: // Output count
                if (offset < deserializer->buffer_length) {
                    tx->output_count = read_varint(deserializer->buffer, &offset);
                    tx->outputs = calloc(tx->output_count, sizeof(TxOutput));
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
            case 4: // Outputs
                while (deserializer->output_index < tx->output_count) {
                    TxOutput *output = &tx->outputs[deserializer->output_index];
                    if (offset + 8 <= deserializer->buffer_length) {
                        output->value = *((uint64_t *)(deserializer->buffer + offset));
                        offset += 8;
                    } else {
                        return 0;
                    }
                    output->script_length = read_varint(deserializer->buffer, &offset);
                    if (offset + output->script_length <= deserializer->buffer_length) {
                        output->script = malloc(output->script_length);
                        memcpy(output->script, deserializer->buffer + offset, output->script_length);
                        parse_output_script(output->script, output->script_length, output->address);
                        offset += output->script_length;
                    } else {
                        return 0;
                    }
                    deserializer->output_index++;
                }
                deserializer->state++;
                break;
            case 5: // Locktime
                if (offset + 4 <= deserializer->buffer_length) {
                    tx->locktime = *((uint32_t *)(deserializer->buffer + offset));
                    offset += 4;
                    deserializer->state++;
                    deserializer->offset = offset;
                    return 1;
                } else {
                    return 0;
                }
                break;
        }
    }

    deserializer->offset = offset;
    return 0;
}

void free_transaction(BitcoinTransaction *tx) {
    for (size_t i = 0; i < tx->input_count; i++) {
        free(tx->inputs[i].script);
    }
    free(tx->inputs);
    for (size_t i = 0; i < tx->output_count; i++) {
        free(tx->outputs[i].script);
    }
    free(tx->outputs);
}

void display_transaction(const BitcoinTransaction *tx) {
    printf("Version: %u\n", tx->version);
    printf("Input Count: %llu\n", tx->input_count);
    for (size_t i = 0; i < tx->input_count; i++) {
        printf("Input %zu:\n", i);
        printf("  Previous Transaction Hash: ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", tx->inputs[i].prev_tx_hash[j]);
        }
        printf("\n  Previous Transaction Index: %u\n", tx->inputs[i].prev_tx_index);
        printf("  Script Length: %llu\n", tx->inputs[i].script_length);
        printf("  Script: ");
        for (uint64_t j = 0; j < tx->inputs[i].script_length; j++) {
            printf("%02x", tx->inputs[i].script[j]);
        }
        printf("\n  Address: %s\n", tx->inputs[i].address);
        printf("  Sequence: %u\n", tx->inputs[i].sequence);
    }
    printf("Output Count: %llu\n", tx->output_count);
    for (size_t i = 0; i < tx->output_count; i++) {
        printf("Output %zu:\n", i);
        printf("  Value: %llu\n", tx->outputs[i].value);
        printf("  Script Length: %llu\n", tx->outputs[i].script_length);
        printf("  Script: ");
        for (uint64_t j = 0; j < tx->outputs[i].script_length; j++) {
            printf("%02x", tx->outputs[i].script[j]);
        }
        printf("\n  Address: %s\n", tx->outputs[i].address);
    }
    printf("Locktime: %u\n", tx->locktime);
}

int main() {
    Deserializer deserializer;
    init_deserializer(&deserializer);

    // Simulate receiving chunks of data
    uint8_t chunks[][BUFFER_SIZE] = {
        {0x01, 0x00, 0x00, 0x00},  // Version (4 bytes)
        {0x01},  // Input count (1 byte varint)
        {0x4a, 0x5e, 0x16, 0xa0, 0x20, 0xf0, 0xf7, 0x64, 0x2a, 0x89, 0x34, 0x19, 0xf7, 0x5e, 0xa1, 0x14,
         0x59, 0x67, 0x4a, 0xe3, 0x56, 0x6a, 0x52, 0x6c, 0xae, 0xb7, 0x6e, 0x0a, 0xab, 0xaa, 0xd1, 0x3e}, // Previous Transaction Hash
        {0x00, 0x00, 0x00, 0x00}, // Previous Transaction Index
        {0x19}, // Script Length (25 bytes)
        {0x76, 0xa9, 0x14, 0x1b, 0x8c, 0xd3, 0xd5, 0x27, 0x7f, 0xd4, 0x69, 0xbc, 0x26, 0x2b, 0x8d, 0x8b,
         0x0f, 0xf7, 0xd0, 0x91, 0x69, 0xbc, 0x88, 0xac}, // Script
        {0xff, 0xff, 0xff, 0xff}, // Sequence
        {0x01}, // Output count (1 byte varint)
        {0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00}, // Value (8 bytes)
        {0x19}, // Script Length (25 bytes)
        {0x76, 0xa9, 0x14, 0x1b, 0x8c, 0xd3, 0xd5, 0x27, 0x7f, 0xd4, 0x69, 0xbc, 0x26, 0x2b, 0x8d, 0x8b,
         0x0f, 0xf7, 0xd0, 0x91, 0x69, 0xbc, 0x88, 0xac}, // Script
        {0x00, 0x00, 0x00, 0x00}, // Locktime
    };

    size_t num_chunks = sizeof(chunks) / BUFFER_SIZE;

    for (size_t i = 0; i < num_chunks; i++) {
        if (add_chunk(&deserializer, chunks[i], BUFFER_SIZE)) {
            display_transaction(&deserializer.transaction);
            break;
        }
    }

    free_transaction(&deserializer.transaction);
    return 0;
}
