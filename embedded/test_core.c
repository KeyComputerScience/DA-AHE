/* SPDX-License-Identifier: MIT */
/* Independent known-answer cases. Authored, never compiled or run at delivery. */
#include "daahe_core.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "failed at line %d: %s\n", __LINE__, #expression); return 1; \
} } while (0)

static int test_only_accept(void *context, size_t source, size_t block,
                            size_t count, const uint8_t *payload, size_t length,
                            const uint8_t mac[16]) {
    (void)context; (void)source; (void)block; (void)count;
    (void)payload; (void)length; (void)mac;
    return 1; /* Test double, never a production authenticator. */
}

static int test_only_reject(void *context, size_t source, size_t block,
                            size_t count, const uint8_t *payload, size_t length,
                            const uint8_t mac[16]) {
    (void)context; (void)source; (void)block; (void)count;
    (void)payload; (void)length; (void)mac;
    return 0;
}

static int test_matrix_element(void *context, size_t row, size_t column, uint32_t *value) {
    if (context && row == 5 && column == 1) return 0;
    if (column >= 2) return 0;
    *value = (uint32_t)(row + column + 1);
    return 1;
}

int main(void) {
    uint32_t a[DAAHE_D] = {0}, b[DAAHE_D] = {0}, out[DAAHE_D];
    uint32_t tag[DAAHE_TAG_DIM] = {0};
    uint32_t tag_input[2] = {2,3}, streamed_tag[DAAHE_TAG_DIM];
    int32_t data[2] = {1, -2};
    uint8_t accumulator[DAAHE_CIPHER_BYTES], payload[64], mac[16] = {0};
    daahe_stream stream;
    size_t i, source, block;
    a[255] = 1; b[1] = 1;
    daahe_ring_mul(out,a,b);
    CHECK(out[0] == UINT32_MAX);
    for (i=1;i<DAAHE_D;++i) CHECK(out[i] == 0);
    memset(a,0,sizeof a); memset(b,0,sizeof b);
    a[0] = UINT32_MAX; b[0] = UINT32_MAX;
    daahe_ring_mul(out,a,b);
    CHECK(out[0] == 1);
    CHECK(daahe_pack(out,data,2,tag,100,16) == 1);
    CHECK(out[0] == 1 && out[1] == 65535);
    CHECK(daahe_pack(out,data,2,tag,32769,1) == 0);
    CHECK(daahe_decode_word(0) == 0);
    CHECK(daahe_decode_word(65535) == 1);
    CHECK(daahe_decode_word(UINT32_C(4294901761)) == 65536);
    CHECK(daahe_linear_tag_stream(streamed_tag,tag_input,2,tag,test_matrix_element,NULL) == 1);
    for (i=0;i<DAAHE_TAG_DIM;++i) CHECK(streamed_tag[i] == (uint32_t)(5*i+8));
    CHECK(daahe_linear_tag_stream(streamed_tag,tag_input,2,tag,test_matrix_element,&stream) == 0);
    for (i=0;i<DAAHE_TAG_DIM;++i) CHECK(streamed_tag[i] == 0);
    memset(payload,0,sizeof payload);
    for (i=0;i<sizeof payload;i+=4) payload[i]=1;
    CHECK(daahe_stream_init(&stream,accumulator,sizeof accumulator,4096,2,64) == 1);
    for (source=0;source<2;++source) {
        for (block=0;block<64;++block) {
            CHECK(daahe_stream_push(&stream,source,block,64,payload,64,mac,test_only_accept,NULL) == 1);
        }
    }
    CHECK(daahe_stream_finish(&stream) == 1);
    for (i=0;i<sizeof accumulator;i+=4) {
        CHECK(accumulator[i]==2 && accumulator[i+1]==0 && accumulator[i+2]==0 && accumulator[i+3]==0);
    }
    CHECK(daahe_stream_init(&stream,accumulator,sizeof accumulator,4096,1,64) == 1);
    CHECK(daahe_stream_push(&stream,0,0,64,payload,64,mac,test_only_reject,NULL) == 0);
    CHECK(daahe_stream_finish(&stream) == 0);
    for (i=0;i<sizeof accumulator;++i) CHECK(accumulator[i]==0);
    puts("portable core known-answer cases passed in this execution");
    return 0;
}

