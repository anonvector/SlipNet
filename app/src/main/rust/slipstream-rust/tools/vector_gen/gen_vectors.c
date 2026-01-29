#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "lua-resty-base-encoding-base32.h"
#include "slipstream_inline_dots.h"

#define QNAME_MAX 512

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static uint8_t *parse_hex(const char *hex, size_t *out_len) {
    if (hex == NULL) {
        return NULL;
    }
    if (hex[0] == '\0' || (hex[0] == '-' && hex[1] == '\0')) {
        uint8_t *bytes = (uint8_t *)malloc(1);
        if (bytes == NULL) {
            return NULL;
        }
        *out_len = 0;
        return bytes;
    }

    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return NULL;
    }

    size_t bytes_len = len / 2;
    uint8_t *bytes = (uint8_t *)malloc(bytes_len);
    if (bytes == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = bytes_len;
    return bytes;
}

static int streq_icase(const char *left, const char *right) {
    while (*left != '\0' && *right != '\0') {
        if (toupper((unsigned char)*left) != toupper((unsigned char)*right)) {
            return 0;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static int parse_rcode(const char *text, dns_rcode_t *out) {
    if (text == NULL || text[0] == '\0') {
        return 0;
    }
    if (streq_icase(text, "OK")) {
        *out = RCODE_OKAY;
        return 1;
    }
    if (streq_icase(text, "FORMAT_ERROR")) {
        *out = RCODE_FORMAT_ERROR;
        return 1;
    }
    if (streq_icase(text, "SERVER_FAILURE")) {
        *out = RCODE_SERVER_FAILURE;
        return 1;
    }
    if (streq_icase(text, "NAME_ERROR")) {
        *out = RCODE_NAME_ERROR;
        return 1;
    }
    return -1;
}

static char *hex_encode(const uint8_t *buf, size_t len) {
    static const char *hex = "0123456789ABCDEF";
    char *out = (char *)malloc(len * 2 + 1);
    if (out == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(buf[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[buf[i] & 0xF];
    }
    out[len * 2] = '\0';
    return out;
}

static void print_json_string(FILE *out, const char *s) {
    fputc('"', out);
    for (const char *p = s; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            fputc('\\', out);
            fputc(c, out);
        } else if (c < 0x20) {
            fprintf(out, "\\u%04X", c);
        } else {
            fputc(c, out);
        }
    }
    fputc('"', out);
}

static const char *rcode_name(dns_rcode_t rcode) {
    switch (rcode) {
        case RCODE_OKAY:
            return "OK";
        case RCODE_FORMAT_ERROR:
            return "FORMAT_ERROR";
        case RCODE_SERVER_FAILURE:
            return "SERVER_FAILURE";
        case RCODE_NAME_ERROR:
            return "NAME_ERROR";
        default:
            return "OTHER";
    }
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return s;
}

static int build_qname(char *out, size_t out_len, const uint8_t *payload, size_t payload_len, const char *domain) {
    size_t domain_len = strlen(domain);
    size_t encoded_len = b32_encode(out, (const char *)payload, payload_len, 1, 0);
    if (encoded_len >= out_len) {
        return -1;
    }

    size_t dotted_len = slipstream_inline_dotify(out, out_len, encoded_len);
    if (dotted_len == (size_t)-1) {
        return -1;
    }

    size_t required = dotted_len + 1 + domain_len + 1 + 1;
    if (required > out_len) {
        return -1;
    }

    out[dotted_len] = '.';
    memcpy(out + dotted_len + 1, domain, domain_len);
    out[dotted_len + 1 + domain_len] = '.';
    out[dotted_len + 1 + domain_len + 1] = '\0';

    return 0;
}

static int encode_query_packet(uint16_t id, const char *qname, uint16_t qtype, size_t qdcount, bool is_query,
                               uint8_t *out, size_t *out_len, dns_question_t *out_question) {
    dns_question_t question;
    question.name = (char *)qname;
    question.type = qtype;
    question.class = CLASS_IN;

    dns_answer_t edns = {0};
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    edns.opt.udp_payload = 1232;

    dns_query_t query = {0};
    query.id = id;
    query.query = is_query;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = qdcount;
    query.questions = (qdcount > 0) ? &question : NULL;
    query.arcount = 1;
    query.additional = &edns;

    dns_rcode_t rc = dns_encode((dns_packet_t *)out, out_len, &query);
    if (rc != RCODE_OKAY) {
        return -1;
    }

    if (out_question != NULL && qdcount > 0) {
        *out_question = question;
    }

    return 0;
}

static int encode_response_packet(uint16_t id, const dns_question_t *question, bool rd, bool cd,
                                  dns_rcode_t error_rcode, const uint8_t *payload, size_t payload_len,
                                  uint8_t *out, size_t *out_len) {
    dns_answer_t edns = {0};
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    edns.opt.udp_payload = 1232;

    dns_txt_t answer_txt;
    dns_query_t response = {0};
    response.id = id;
    response.query = false;
    response.opcode = OP_QUERY;
    response.aa = true;
    response.rd = rd;
    response.cd = cd;
    response.rcode = error_rcode;
    response.qdcount = 1;
    response.questions = (dns_question_t *)question;
    response.arcount = 1;
    response.additional = &edns;

    if (payload_len > 0) {
        answer_txt.name = question->name;
        answer_txt.type = question->type;
        answer_txt.class = question->class;
        answer_txt.ttl = 60;
        answer_txt.text = (char *)payload;
        answer_txt.len = payload_len;

        response.ancount = 1;
        response.answers = (dns_answer_t *)&answer_txt;
    } else if (error_rcode == RCODE_OKAY) {
        response.rcode = RCODE_NAME_ERROR;
    }

    dns_rcode_t rc = dns_encode((dns_packet_t *)out, out_len, &response);
    if (rc != RCODE_OKAY) {
        return -1;
    }

    return 0;
}

static int emit_vector(FILE *out, const char *name, uint16_t id, const char *domain,
                       const uint8_t *payload, size_t payload_len, const char *mode,
                       const char *qname_override, int has_error_rcode, dns_rcode_t error_rcode,
                       const char *raw_query_hex, int first) {
    const char *mode_name = (mode == NULL || mode[0] == '\0') ? "normal" : mode;
    const bool raw_mode = streq_icase(mode_name, "raw_query_hex");
    const bool use_override = (qname_override != NULL && qname_override[0] != '\0');
    const bool override_required = streq_icase(mode_name, "invalid_base32") ||
                                   streq_icase(mode_name, "suffix_mismatch") ||
                                   streq_icase(mode_name, "empty_subdomain");
    bool emit_response_ok = payload_len > 0 && streq_icase(mode_name, "normal") && !raw_mode;
    bool emit_response_no_data = !raw_mode;
    bool emit_response_error = has_error_rcode && !raw_mode;
    const char *expected_action = raw_mode ? "drop" : "reply";
    uint16_t qtype = RR_TXT;
    size_t qdcount = 1;
    bool is_query = true;

    if (!has_error_rcode && !raw_mode) {
        if (streq_icase(mode_name, "invalid_base32")) {
            error_rcode = RCODE_SERVER_FAILURE;
            has_error_rcode = 1;
            emit_response_error = true;
        } else if (streq_icase(mode_name, "suffix_mismatch")) {
            error_rcode = RCODE_NAME_ERROR;
            has_error_rcode = 1;
            emit_response_error = true;
        } else if (streq_icase(mode_name, "non_txt")) {
            error_rcode = RCODE_NAME_ERROR;
            has_error_rcode = 1;
            emit_response_error = true;
        } else if (streq_icase(mode_name, "empty_subdomain")) {
            error_rcode = RCODE_NAME_ERROR;
            has_error_rcode = 1;
            emit_response_error = true;
        } else if (streq_icase(mode_name, "qdcount_zero")) {
            error_rcode = RCODE_FORMAT_ERROR;
            has_error_rcode = 1;
            emit_response_error = true;
        } else if (streq_icase(mode_name, "not_query")) {
            error_rcode = RCODE_FORMAT_ERROR;
            has_error_rcode = 1;
            emit_response_error = true;
        }
    }

    if (!raw_mode) {
        if (streq_icase(mode_name, "non_txt")) {
            qtype = RR_A;
        } else if (streq_icase(mode_name, "qdcount_zero")) {
            qdcount = 0;
        } else if (streq_icase(mode_name, "not_query")) {
            is_query = false;
        }
    }

    if (override_required && !use_override) {
        fprintf(stderr, "Missing qname override for %s\n", name);
        return -1;
    }

    if (raw_mode && (raw_query_hex == NULL || raw_query_hex[0] == '\0')) {
        fprintf(stderr, "Missing raw query hex for %s\n", name);
        return -1;
    }

    char qname[QNAME_MAX];
    if (use_override) {
        if (strlen(qname_override) >= sizeof(qname)) {
            fprintf(stderr, "QNAME override too long for %s\n", name);
            return -1;
        }
        snprintf(qname, sizeof(qname), "%s", qname_override);
    } else if (raw_mode) {
        qname[0] = '\0';
    } else {
        if (payload_len == 0) {
            fprintf(stderr, "Payload cannot be empty for normal mode: %s\n", name);
            return -1;
        }
        if (build_qname(qname, sizeof(qname), payload, payload_len, domain) != 0) {
            fprintf(stderr, "Failed to build qname for %s\n", name);
            return -1;
        }
    }

    uint8_t query_packet[MAX_DNS_QUERY_SIZE];
    size_t query_len = 0;
    dns_question_t question = {0};
    if (raw_mode) {
        size_t raw_len = 0;
        uint8_t *raw_bytes = parse_hex(raw_query_hex, &raw_len);
        if (raw_bytes == NULL || raw_len == 0) {
            free(raw_bytes);
            fprintf(stderr, "Invalid raw query hex for %s\n", name);
            return -1;
        }
        if (raw_len > sizeof(query_packet)) {
            free(raw_bytes);
            fprintf(stderr, "Raw query too large for %s\n", name);
            return -1;
        }
        memcpy(query_packet, raw_bytes, raw_len);
        query_len = raw_len;
        free(raw_bytes);
    } else {
        query_len = sizeof(query_packet);
        if (encode_query_packet(id, qname, qtype, qdcount, is_query, query_packet, &query_len, &question) != 0) {
            fprintf(stderr, "Failed to encode query for %s\n", name);
            return -1;
        }
    }

    uint8_t response_ok_packet[MAX_DNS_QUERY_SIZE];
    size_t response_ok_len = 0;
    if (emit_response_ok) {
        response_ok_len = sizeof(response_ok_packet);
        if (encode_response_packet(id, &question, true, false, RCODE_OKAY, payload, payload_len,
                                   response_ok_packet, &response_ok_len) != 0) {
            fprintf(stderr, "Failed to encode OK response for %s\n", name);
            return -1;
        }
    }

    uint8_t response_no_data_packet[MAX_DNS_QUERY_SIZE];
    size_t response_no_data_len = 0;
    dns_question_t fallback_question = question;
    if (emit_response_no_data) {
        response_no_data_len = sizeof(response_no_data_packet);
        if (qdcount == 0) {
            fallback_question.name = qname;
            fallback_question.type = qtype;
            fallback_question.class = CLASS_IN;
        }
        if (encode_response_packet(id, qdcount > 0 ? &question : &fallback_question, true, false,
                                   RCODE_OKAY, NULL, 0, response_no_data_packet, &response_no_data_len) != 0) {
            fprintf(stderr, "Failed to encode no-data response for %s\n", name);
            return -1;
        }
    }

    uint8_t response_error_packet[MAX_DNS_QUERY_SIZE];
    size_t response_error_len = 0;
    if (emit_response_error) {
        response_error_len = sizeof(response_error_packet);
        if (encode_response_packet(id, qdcount > 0 ? &question : &fallback_question, true, false, error_rcode, NULL, 0,
                                   response_error_packet, &response_error_len) != 0) {
            fprintf(stderr, "Failed to encode error response for %s\n", name);
            return -1;
        }
    }

    char *payload_hex = hex_encode(payload, payload_len);
    char *query_hex = hex_encode(query_packet, query_len);
    char *response_ok_hex = emit_response_ok ? hex_encode(response_ok_packet, response_ok_len) : NULL;
    char *response_no_data_hex = emit_response_no_data ? hex_encode(response_no_data_packet, response_no_data_len) : NULL;
    char *response_error_hex = emit_response_error ? hex_encode(response_error_packet, response_error_len) : NULL;
    if (payload_hex == NULL || query_hex == NULL) {
        fprintf(stderr, "Failed to encode hex output for %s\n", name);
        free(payload_hex);
        free(query_hex);
        free(response_ok_hex);
        free(response_no_data_hex);
        free(response_error_hex);
        return -1;
    }
    if (emit_response_ok && response_ok_hex == NULL) {
        fprintf(stderr, "Failed to encode OK response hex for %s\n", name);
        free(payload_hex);
        free(query_hex);
        free(response_ok_hex);
        free(response_no_data_hex);
        free(response_error_hex);
        return -1;
    }
    if (emit_response_no_data && response_no_data_hex == NULL) {
        fprintf(stderr, "Failed to encode no-data response hex for %s\n", name);
        free(payload_hex);
        free(query_hex);
        free(response_ok_hex);
        free(response_no_data_hex);
        free(response_error_hex);
        return -1;
    }
    if (emit_response_error && response_error_hex == NULL) {
        fprintf(stderr, "Failed to encode error response hex for %s\n", name);
        free(payload_hex);
        free(query_hex);
        free(response_ok_hex);
        free(response_no_data_hex);
        free(response_error_hex);
        return -1;
    }

    if (!first) {
        fputc(',', out);
    }

    fputc('\n', out);
    fprintf(out, "  {\n");
    fprintf(out, "    \"name\": ");
    print_json_string(out, name);
    fprintf(out, ",\n    \"domain\": ");
    print_json_string(out, domain);
    fprintf(out, ",\n    \"id\": %u,\n", id);
    fprintf(out, "    \"payload_len\": %zu,\n", payload_len);
    fprintf(out, "    \"payload_hex\": ");
    print_json_string(out, payload_hex);
    fprintf(out, ",\n    \"mode\": ");
    print_json_string(out, mode_name);
    fprintf(out, ",\n    \"expected_action\": ");
    print_json_string(out, expected_action);
    fprintf(out, ",\n    \"qname\": ");
    print_json_string(out, qname);
    fprintf(out, ",\n    \"query\": {\n");
    fprintf(out, "      \"packet_len\": %zu,\n", query_len);
    fprintf(out, "      \"packet_hex\": ");
    print_json_string(out, query_hex);
    fprintf(out, "\n    },\n    \"response_ok\": ");
    if (emit_response_ok) {
        fprintf(out, "{\n");
        fprintf(out, "      \"rcode\": ");
        print_json_string(out, rcode_name(RCODE_OKAY));
        fprintf(out, ",\n      \"packet_len\": %zu,\n", response_ok_len);
        fprintf(out, "      \"packet_hex\": ");
        print_json_string(out, response_ok_hex);
        fprintf(out, "\n    }");
    } else {
        fprintf(out, "null");
    }
    fprintf(out, ",\n    \"response_no_data\": ");
    if (emit_response_no_data) {
        fprintf(out, "{\n");
        fprintf(out, "      \"rcode\": ");
        print_json_string(out, rcode_name(RCODE_NAME_ERROR));
        fprintf(out, ",\n      \"packet_len\": %zu,\n", response_no_data_len);
        fprintf(out, "      \"packet_hex\": ");
        print_json_string(out, response_no_data_hex);
        fprintf(out, "\n    }");
    } else {
        fprintf(out, "null");
    }
    if (emit_response_error) {
        fprintf(out, ",\n    \"response_error\": {\n");
        fprintf(out, "      \"rcode\": ");
        print_json_string(out, rcode_name(error_rcode));
        fprintf(out, ",\n      \"packet_len\": %zu,\n", response_error_len);
        fprintf(out, "      \"packet_hex\": ");
        print_json_string(out, response_error_hex);
        fprintf(out, "\n    }");
    }
    fprintf(out, "\n  }");

    free(payload_hex);
    free(query_hex);
    free(response_ok_hex);
    free(response_no_data_hex);
    free(response_error_hex);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <vectors.txt>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    fprintf(stdout, "{\n  \"schema_version\": 2,\n  \"generated_by\": ");
    print_json_string(stdout, "tools/vector_gen/gen_vectors.c");
    fprintf(stdout, ",\n  \"vectors\": [");

    char line[4096];
    int first = 1;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *raw = trim(line);
        if (raw[0] == '\0' || raw[0] == '#') {
            continue;
        }

        char *name = trim(strtok(raw, ","));
        char *id_str = trim(strtok(NULL, ","));
        char *domain = trim(strtok(NULL, ","));
        char *payload_hex = trim(strtok(NULL, ","));
        char *mode = NULL;
        char *qname_override = NULL;
        char *error_rcode_str = NULL;
        char *mode_raw = strtok(NULL, ",");
        char *qname_override_raw = strtok(NULL, ",");
        char *error_rcode_raw = strtok(NULL, ",");
        char *raw_query_hex_raw = strtok(NULL, ",");
        if (mode_raw != NULL) {
            mode = trim(mode_raw);
        }
        if (qname_override_raw != NULL) {
            qname_override = trim(qname_override_raw);
        }
        if (error_rcode_raw != NULL) {
            error_rcode_str = trim(error_rcode_raw);
        }
        char *raw_query_hex = NULL;
        if (raw_query_hex_raw != NULL) {
            raw_query_hex = trim(raw_query_hex_raw);
        }
        if (mode != NULL && strcmp(mode, "-") == 0) {
            mode = NULL;
        }
        if (qname_override != NULL && strcmp(qname_override, "-") == 0) {
            qname_override = NULL;
        }
        if (error_rcode_str != NULL && strcmp(error_rcode_str, "-") == 0) {
            error_rcode_str = NULL;
        }
        if (raw_query_hex != NULL && strcmp(raw_query_hex, "-") == 0) {
            raw_query_hex = NULL;
        }
        if (name == NULL || id_str == NULL || domain == NULL || payload_hex == NULL) {
            fprintf(stderr, "Invalid vector line: %s\n", raw);
            fclose(fp);
            return 1;
        }

        unsigned long id_ul = strtoul(id_str, NULL, 0);
        if (id_ul > 0xFFFF) {
            fprintf(stderr, "ID out of range for %s\n", name);
            fclose(fp);
            return 1;
        }

        size_t payload_len = 0;
        uint8_t *payload = parse_hex(payload_hex, &payload_len);
        if (payload == NULL) {
            fprintf(stderr, "Invalid payload hex for %s\n", name);
            fclose(fp);
            return 1;
        }

        dns_rcode_t error_rcode = RCODE_OKAY;
        int has_error_rcode = parse_rcode(error_rcode_str, &error_rcode);
        if (has_error_rcode < 0) {
            fprintf(stderr, "Invalid error rcode for %s\n", name);
            free(payload);
            fclose(fp);
            return 1;
        }

        if (emit_vector(stdout, name, (uint16_t)id_ul, domain, payload, payload_len,
                        mode, qname_override, has_error_rcode == 1, error_rcode,
                        raw_query_hex, first) != 0) {
            free(payload);
            fclose(fp);
            return 1;
        }
        first = 0;
        free(payload);
    }

    fprintf(stdout, "\n  ]\n}\n");
    fclose(fp);
    return 0;
}
