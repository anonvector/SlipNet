/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "tls_api.h"
#include "picoquic_internal.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

picoquic_stored_token_t* picoquic_format_token(uint64_t time_valid_until,
    char const* sni, uint16_t sni_length, uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t const* token, uint16_t token_length)
{
    size_t token_size = sizeof(picoquic_stored_token_t) + sni_length + 1 + ip_addr_length + 1 + token_length;
    picoquic_stored_token_t* stored = (picoquic_stored_token_t*)malloc(token_size);
    
    if (stored != NULL) {
        uint8_t* next_p = ((uint8_t*)stored) + sizeof(picoquic_stored_token_t);

        memset(stored, 0, token_size);
        stored->time_valid_until = time_valid_until;
        stored->sni = (char const *)next_p;
        stored->sni_length = sni_length;
        memcpy(next_p, sni, sni_length);
        next_p += sni_length;
        *next_p++ = 0;

        stored->ip_addr = next_p;
        stored->ip_addr_length = ip_addr_length;
        memcpy(next_p, ip_addr, ip_addr_length);
        next_p += ip_addr_length;
        *next_p++ = 0;

        stored->token = next_p;
        stored->token_length = token_length;
        memcpy(next_p, token, token_length);
    }

    return stored;
}

int picoquic_serialize_token(const picoquic_stored_token_t * token, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t required_length;

    /* Compute serialized length */
    required_length = (size_t)(8 + 2 + 2 + 2) + token->sni_length + token->ip_addr_length + token->token_length;
    /* Serialize */
    if (required_length > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        picoformat_64(bytes + byte_index, token->time_valid_until);
        byte_index += 8;

        picoformat_16(bytes + byte_index, token->sni_length);
        byte_index += 2;
        memcpy(bytes + byte_index, token->sni, token->sni_length);
        byte_index += token->sni_length;

        picoformat_16(bytes + byte_index, token->ip_addr_length);
        byte_index += 2;
        memcpy(bytes + byte_index, token->ip_addr, token->ip_addr_length);
        byte_index += token->ip_addr_length;

        picoformat_16(bytes + byte_index, token->token_length);
        byte_index += 2;
        memcpy(bytes + byte_index, token->token, token->token_length);
        byte_index += token->token_length;

        *consumed = byte_index;
    }

    return ret;
}

int picoquic_deserialize_token(picoquic_stored_token_t ** token, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    uint64_t time_valid_until = 0;
    size_t required_length = 8 + 2 + 2 + 2;
    size_t byte_index = 0;
    size_t sni_index = 0;
    size_t ip_addr_index = 0;
    size_t token_index = 0;
    uint16_t sni_length = 0;
    uint8_t ip_addr_length = 0;
    uint16_t token_length = 0;


    *consumed = 0;
    *token = NULL;

    if (required_length < bytes_max) {
        time_valid_until = PICOPARSE_64(bytes);
        byte_index = 8;
        sni_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        sni_index = byte_index;
        required_length += sni_length;
        byte_index += sni_length;
    }
    
    if (required_length < bytes_max) {
        ip_addr_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        ip_addr_index = byte_index;
        required_length += ip_addr_length;
        byte_index += ip_addr_length;
    }

    if (required_length < bytes_max) {
        token_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        token_index = byte_index;
        required_length += token_length;
    }

    if (required_length > bytes_max) {
        *token = NULL;
        ret = PICOQUIC_ERROR_INVALID_TOKEN;
    } else {
        *token = picoquic_format_token(time_valid_until, (const char *)(bytes + sni_index), sni_length,
            bytes + ip_addr_index, ip_addr_length, bytes + token_index, token_length);
        if (*token == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            *consumed = required_length;
        }
    }

    return ret;
}

int picoquic_store_token(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t const* token, uint16_t token_length)
{
    int ret = 0;
    picoquic_stored_token_t** pp_first_token = &quic->p_first_token;
    uint64_t current_time = picoquic_get_tls_time(quic);

    if (token_length < 1 || sni == NULL || sni_length == 0) {
        ret = PICOQUIC_ERROR_INVALID_TOKEN;
    }
    else {
        /* There is no explicit TTL for tokens. We assume they are OK for 24 hours */
        uint64_t time_valid_until = current_time + ((uint64_t)24 * 3600) * ((uint64_t)1000000);
        picoquic_stored_token_t* stored = picoquic_format_token(time_valid_until, sni, sni_length,
            ip_addr, ip_addr_length, token, token_length);
        if (stored == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            picoquic_stored_token_t* next;
            picoquic_stored_token_t** pprevious;

            stored->next_token = next = *pp_first_token;
            *pp_first_token = stored;
            pprevious = &stored->next_token;

            /* Now remove the old tokens for that SNI & ip_addr */
            while (next != NULL) {
                if (next->time_valid_until <= stored->time_valid_until && next->sni_length == sni_length && next->ip_addr_length == ip_addr_length && memcmp(next->sni, sni, sni_length) == 0 && memcmp(next->ip_addr, ip_addr, ip_addr_length) == 0) {
                    picoquic_stored_token_t* deleted = next;
                    next = next->next_token;
                    *pprevious = next;
                    free(deleted);
                }
                else {
                    pprevious = &next->next_token;
                    next = next->next_token;
                }
            }
        }
    } 

    return ret;
}

int picoquic_get_token(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t** token, uint16_t* token_length, int mark_used)
{
    int ret = 0;

    uint64_t current_time = picoquic_get_tls_time(quic);
    picoquic_stored_token_t* p_first_token = quic->p_first_token;
    picoquic_stored_token_t* next = p_first_token;
    picoquic_stored_token_t* best_match = NULL;

    while (next != NULL) {
        if (next->time_valid_until > current_time && next->sni_length == sni_length && memcmp(next->sni, sni, sni_length) == 0 && next->was_used == 0){
            if (ip_addr_length > 0) {
                if (next->ip_addr_length == ip_addr_length && memcmp(next->ip_addr, ip_addr, ip_addr_length) == 0) {
                    best_match = next;
                    break;
                }
            }
            else {
                if (best_match == NULL || next->time_valid_until > best_match->time_valid_until) {
                    best_match = next;
                }
            }
        } 
        next = next->next_token;
    }

    if (best_match == NULL || best_match->token_length == 0 || (*token = (uint8_t *)malloc(best_match->token_length)) == NULL) {
        *token = NULL;
        *token_length = 0;
        ret = -1;
    } else {
        *token_length = best_match->token_length;
        memcpy(*token, (uint8_t*)best_match->token, best_match->token_length);
        best_match->was_used = mark_used;
    }

    return ret;
}

int picoquic_save_tokens(picoquic_quic_t * quic,
    char const* token_file_name)
{
    int ret = 0;
    FILE* F = NULL;
    const picoquic_stored_token_t* first_token = quic->p_first_token;
    const picoquic_stored_token_t* next = first_token;
    uint64_t current_time = picoquic_get_tls_time(quic);

    if ((F = picoquic_file_open(token_file_name, "wb")) == NULL) {
        ret = -1;
    } else {
        while (ret == 0 && next != NULL) {
            /* Only store the tokens that are valid going forward */
            if (next->time_valid_until > current_time && next->was_used == 0) {
                /* Compute the serialized size */
                uint8_t buffer[2048];
                size_t record_size;

                ret = picoquic_serialize_token(next, buffer, sizeof(buffer), &record_size);

                if (ret == 0) {
                    if (fwrite(&record_size, 4, 1, F) != 1 || fwrite(buffer, 1, record_size, F) != record_size) {
                        ret = PICOQUIC_ERROR_INVALID_FILE;
                        break;
                    }
                }
            }
            next = next->next_token;
        }
        (void)picoquic_file_close(F);
    }

    return ret;
}

int picoquic_load_tokens(picoquic_quic_t* quic, char const* token_file_name)
{
    int ret = 0;
    int file_ret = 0;
    FILE* F = NULL;
    picoquic_stored_token_t* previous = NULL;
    picoquic_stored_token_t* next = NULL;
    uint32_t record_size;
    uint32_t storage_size;
    uint64_t current_time = picoquic_get_tls_time(quic);
    picoquic_stored_token_t** pp_first_token = &quic->p_first_token;

    if ((F = picoquic_file_open_ex(token_file_name, "rb", &file_ret)) == NULL) {
        ret = (file_ret == ENOENT) ? PICOQUIC_ERROR_NO_SUCH_FILE : -1;
    }

    while (ret == 0) {
        if (fread(&storage_size, 4, 1, F) != 1) {
            /* end of file */
            break;
        }
        else if (storage_size > 2048 ||
            (record_size = storage_size + offsetof(struct st_picoquic_stored_token_t, time_valid_until)) > 2048) {
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }
        else {
            uint8_t buffer[2048];
            if (fread(buffer, 1, storage_size, F) != storage_size) {
                ret = PICOQUIC_ERROR_INVALID_FILE;
            }
            else {
                size_t consumed = 0;
                ret = picoquic_deserialize_token(&next, buffer, storage_size, &consumed);

                if (ret == 0 && (consumed != storage_size || next == NULL)) {
                    ret = PICOQUIC_ERROR_INVALID_FILE;
                }

                if (ret == 0 && next != NULL) {
                    if (next->time_valid_until < current_time) {
                        free(next);
                        next = NULL;
                    }
                    else {
                        next->sni = ((char*)next) + sizeof(picoquic_stored_token_t);
                        next->ip_addr = ((uint8_t*)next->sni) + next->sni_length + 1;
                        next->token = (uint8_t*)(next->ip_addr + next->ip_addr_length + 1);
                        next->next_token = NULL;
                        if (previous == NULL) {
                            *pp_first_token = next;
                        }
                        else {
                            previous->next_token = next;
                        }

                        previous = next;
                    }
                }
            }
        }
    }

    (void)picoquic_file_close(F);

    return ret;
}

void picoquic_free_tokens(picoquic_stored_token_t** pp_first_token)
{
    picoquic_stored_token_t* next;

    while ((next = *pp_first_token) != NULL) {
        *pp_first_token = next->next_token;

        free(next);
    }
}
