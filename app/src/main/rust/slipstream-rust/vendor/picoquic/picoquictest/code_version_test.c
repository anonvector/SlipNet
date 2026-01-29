/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

#include <string.h>
#include "picoquic.h"
#include "picoquic_utils.h"

static char* skip_blank(char* line)
{
    char* x = line;
    while (*x != 0 && (*x == ' ' || *x == '\t')) {
        x++;
    }
    return(x);
}

static int starts_with(char* line, const char* text, size_t text_len, size_t* offset)
{
    int ret = -1;
    char* x = skip_blank(line);

    if (x != NULL && strlen(x) >= text_len && memcmp(x, text, text_len) == 0) {
        ret = 0;
        *offset = (x - line);
    }

    return(ret);
}

int code_version_test()
{
    char cmake_file[512];
    int ret = picoquic_get_input_path(cmake_file, sizeof(cmake_file), picoquic_solution_dir, "CMakeLists.txt");

    if (ret >= 0) {
        int last_err = 0;
        FILE* F = picoquic_file_open_ex(cmake_file, "r", &last_err);

        ret = -1; /* will be set to zero if successful */

        if (F == NULL) {
            DBG_PRINTF("Cannot open <%s> error %d(0x%x)", cmake_file, last_err, last_err);
        }
        else {
            char line[512];
            char const* project = "project(picoquic";
            size_t project_len = strlen(project);
            char const* version = "VERSION";
            size_t version_len = strlen(version);

            size_t offset;

            while (fgets(line, sizeof(line), F) != NULL) {
                /* find line that include "project(picoquic" */
                if (starts_with(line, project, project_len, &offset) == 0) {
                    /* get next line, which should include <space>VERSION<space>x.y.z.t */
                    if (fgets(line, sizeof(line), F) != NULL &&
                        starts_with(line, version, version_len, &offset) == 0) {
                        char* x = skip_blank(&line[offset + version_len]);
                        size_t x_len = strlen(x);
                        const char* v = PICOQUIC_VERSION;
                        size_t v_len = strlen(v);
                        if (x_len >= v_len && memcmp(x, v, v_len) == 0) {
                            char* y = x + v_len;
                            if (*y == ' ' || *y == '\t' || *y == '\r' || *y == '\n') {
                                ret = 0;
                            }
                        }
                    }
                    /* Extract the version string. */
                    /* compare to version in picoquic.h */
                    break;
                }
            }
        }
    }

    return ret;
}