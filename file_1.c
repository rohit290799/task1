// Standard input-output functions (stdio.h), standard library functions (stdlib.h), integer type definitions 
// (stdint.h), and string manipulation routines (string.h) are all included in these header files.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
// Specifies the size of the buffer that will be used to store data chunks by defining the constant 
// BUFFER_SIZE with a value of 64.
#define BUFFER_SIZE 64

// Defines a structure TxInput to represent a Bitcoin transaction input. It contains:
typedef struct {
    uint8_t prev_tx_hash[32]; //The hash of the previous transaction
    uint32_t prev_tx_index; //The index of the previous transaction's output.
    uint64_t script_length; 
    uint8_t *script;
    uint32_t sequence;
    char address[35]; //A string to store a human-readable address.
} TxInput;

//Defines a structure TxOutput to represent a Bitcoin transaction output. It contains:
typedef struct {
    uint64_t value; //The value of the output in satoshis.
    uint64_t script_length; 
    uint8_t *script;
    char address[35]; //A string to store a human-readable address.
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
    uint8_t buffer[BUFFER_SIZE]; //A buffer to store incoming data chunks.
    size_t buffer_length; //The current length of data in the buffer.
    size_t total_length; //The total length of data processed.
    BitcoinTransaction transaction; //structure to store the parsed transaction.
    size_t offset; //The current offset within the buffer.
    int state; //The current state of the deserialization process.
    int input_index; //The current index of the input being processed.
    int output_index; //The current index of the output being processed.
} Deserializer;

// Assigns the initial values to each field of a Deserializer structure to make it initial. 
// The transaction structure is zeroed out using memset.
void init_deserializer(Deserializer *deserializer) {
    deserializer->buffer_length = 0;
    deserializer->total_length = 0;
    deserializer->offset = 0;
    deserializer->state = 0;
    deserializer->input_index = 0;
    deserializer->output_index = 0;
    memset(&deserializer->transaction, 0, sizeof(BitcoinTransaction));
}

// Starts at the specified offset and reads a variable-length integer (varint) from the data buffer. 
// Depending on its first byte, the variate can have a length of 1, 3, 5, or 9 bytes. The function 
// modifies the offset and returns an integer value.
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

// Parses the script input and puts it in the address field after converting it to a human-readable manner. 
// The script is merely formatted as a hexadecimal string using this function.
void parse_input_script(const uint8_t *script, uint64_t script_length, char *address) {
    snprintf(address, 35, "script: ");
    for (uint64_t i = 0; i < script_length && (2 * i + 8) < 34; ++i) {
        snprintf(address + strlen(address), 3, "%02x", script[i]);
    }
}

// The output script is parsed in the same manner as the input script, transformed into a readable format, 
// and then saved in the address field.
void parse_output_script(const uint8_t *script, uint64_t script_length, char *address) {
    snprintf(address, 35, "script: ");
    for (uint64_t i = 0; i < script_length && (2 * i + 8) < 34; ++i) {
        snprintf(address + strlen(address), 3, "%02x", script[i]);
    }
}

// Modifies the buffer's length and total length and adds a new piece of data.
int add_chunk(Deserializer *deserializer, const uint8_t *chunk, size_t chunk_length) {
    memcpy(deserializer->buffer + deserializer->buffer_length, chunk, chunk_length);
    deserializer->buffer_length += chunk_length;
    deserializer->total_length += chunk_length;

    // Sets the pointer to the transaction that is being deserialised and the current offset's 
    // local variables to their initial values.
    size_t offset = deserializer->offset;
    BitcoinTransaction *tx = &deserializer->transaction;

    while (offset < deserializer->buffer_length) {
        switch (deserializer->state) {
// State 0: If the buffer contains at least 4 bytes, read the transaction version. 
// advances the offset before going on to the following state.
            case 0: // Version
                if (deserializer->buffer_length >= 4) {
                    tx->version = *((uint32_t *)(deserializer->buffer + offset));
                    offset += 4;
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
// State1: Uses read_varint to read the input count, allocates memory for the inputs, and then advances
 // to the next step.
            case 1: // Input count
                if (offset < deserializer->buffer_length) {
                    tx->input_count = read_varint(deserializer->buffer, &offset);
                    tx->inputs = calloc(tx->input_count, sizeof(TxInput));
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
// Stage 2: Examines every input field for every input, including the script length, sequence, index, prior 
// transaction hash, and script. Changes the state and input index and allocates RAM as needed.
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
// State 3: Uses read_varint to read the output count, allocates memory for the outputs, and advances to the following state.
            case 3: // Output count
                if (offset < deserializer->buffer_length) {
                    tx->output_count = read_varint(deserializer->buffer, &offset);
                    tx->outputs = calloc(tx->output_count, sizeof(TxOutput));
                    deserializer->state++;
                } else {
                    return 0;
                }
                break;
// State 4: Reads the value, script length, and script for each output field across all outputs. Memory is 
// allocated as needed, and the output index and state are updated.
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
// State 5: If the buffer contains at least 4 bytes, reads the locktime. completes the deserialisation operation, 
// updates the offset, and returns 1 to signify success.
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
// returns 0 if the deserialization is not complete and updates the offset of the deserializer.
    deserializer->offset = offset;
    return 0;
}
//Releases the memory used for the inputs and outputs of the transaction.
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
//Shows the transaction's specifics, such as the version, the number of inputs and outputs, and 
// comprehensive details on each input and output.
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
//When the transaction has been fully deserialised, adds each chunk to the deserializer and shows it.
    for (size_t i = 0; i < num_chunks; i++) {
        if (add_chunk(&deserializer, chunks[i], BUFFER_SIZE)) {
            display_transaction(&deserializer.transaction);
            break;
        }
    }
//Returns 0 to signify successful execution and releases the memory allotted for the transaction.
    free_transaction(&deserializer.transaction);
    return 0;
}
