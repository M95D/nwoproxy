/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1999 George Talusan <gstalusan@uwaterloo.ca>
 * Copyright (C) 2002 James E. Flemer <jflemer@acm.jhu.edu>
 * Copyright (C) 2002 Robert James Kaes <rjkaes@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* A substring of the domain to be filtered goes into the file
 * pointed at by DEFAULT_FILTER.
 */

#include "main.h"

#include <regex.h>
#include <fnmatch.h>
#include "filter.h"
#include "heap.h"
#include "log.h"
#include "reqs.h"
#include "conf.h"
#include "sblist.h"
#include <sqlite3.h>
#include "filterdb.h"

#define FILTER_BUFFER_LEN (512)

static int err;

struct filter_list {
        union {
                regex_t cpatb;
                char *pattern;
        } u;
};

static sblist *fl = NULL;
static int already_init = 0;

/*
 * Initializes a list of strings containing hosts/urls to be filtered
 */
void filter_init (void)
{
        /* New filtering uses SQLite database. No file-based parsing.
         * We simply mark the filter as initialized when a filter DB is
         * configured. The actual DB connection is handled in filterdb.c
         * (opened at startup).
         */
        if (already_init) return;

        if (!config || !config->filter) {
                /* No filtering configured */
                already_init = 0;
                return;
        }

        already_init = 1;
}

/* unlink the list */
void filter_destroy (void)
{
        /* Nothing to free for DB-backed filters here. The DB connection
         * is closed by filterdb_close() called from main.c on shutdown.
         */
        already_init = 0;
}

/**
 * reload the filter file if filtering is enabled
 */
void filter_reload (void)
{
        /* With DB-backed filters we don't reload from file; nothing to do.
         * Keep API for compatibility.
         */
        if (config && config->filter) {
                log_message (LOG_NOTICE, "Filter DB in use; reload is a no-op.");
        }
}

/* Return 0 to allow, non-zero to block */
int filter_run (const char *str)
{
        sqlite3 *db;
        char *copy = NULL;
        char **parents = NULL;
        size_t np = 0;
        int i;
        int rc;
        char *errmsg = NULL;
        char *sql = NULL;
        int result = 0; /* 0 allow, 1 deny */

        if (!config || !config->filter) goto COMMON_EXIT;
        if (!already_init) goto COMMON_EXIT;
        if (!str) goto COMMON_EXIT;

        db = filterdb_get_handle();
        if (!db) {
                log_message(LOG_ERR, "Filter DB not open");
                goto COMMON_EXIT;
        }

        /* Make a mutable copy of the hostname */
        copy = safestrdup(str);
        if (!copy) {
                log_message(LOG_ERR, "Out of memory in filter_run");
                goto COMMON_EXIT;
        }

        /* Strip possible port part if present (e.g. example.com:8080) */
        {
                char *pcolon = strrchr(copy, ':');
                char *pbracket = strchr(copy, ']'); /* IPv6 literals like [::1]:port */
                if (pcolon) {
                        /* If there's a ']' before the colon, it's an IPv6 literal with port; keep up to ']' */
                        if (!pbracket || pbracket < pcolon) {
                                /* colon likely indicates port; remove it */
                                *pcolon = '\0';
                        }
                }
        }

        /* Build list of parent domains: fullhost, then removing leftmost label each time */
        {
                char *p = copy;
                while (p && *p) {
                        char *entry = safestrdup(p);
                        if (!entry) goto oom;
                        parents = (char **) realloc(parents, sizeof(char*) * (np + 1));
                        if (!parents) {
                                safefree(entry);
                                goto oom;
                        }
                        parents[np++] = entry;
                        char *dot = strchr(p, '.');
                        if (!dot) break;
                        p = dot + 1;
                }
        }

        /* Build SQL statement. We will use direct execution since number of parameters varies.
         * Use single quotes around domain names (domain names cannot contain single quote or backslash
         * per the project assumptions) and COLLATE NOCASE for case-insensitive matching.
         */
        {
                size_t bufsz = 1024;
                size_t used = 0;
                sql = safemalloc(bufsz);
                if (!sql) goto oom;
                used += snprintf(sql + used, bufsz - used,
                                 "SELECT rule FROM domains WHERE rule IS NOT NULL AND (");

                /* exact match */
                used += snprintf(sql + used, bufsz - used,
                                 "(domain = '%s' COLLATE NOCASE)", parents[0]);

                /* subdomain matches for parents excluding the full host */
                if (np > 1) {
                        used += snprintf(sql + used, bufsz - used,
                                         " OR (subdomains = 'Y' AND (domain IN (");

                        for (i = 1; i < (int)np; ++i) {
                                /* grow buffer if necessary */
                                size_t need = strlen(parents[i]) + 8;
                                if (used + need + 64 > bufsz) {
                                        bufsz *= 2;
                                        sql = saferealloc(sql, bufsz);
                                        if (!sql) goto oom;
                                }
                                used += snprintf(sql + used, bufsz - used, "'%s'%s",
                                                 parents[i], (i + 1 < (int)np) ? "," : "");
                        }
                        used += snprintf(sql + used, bufsz - used,
                                         ")) COLLATE NOCASE)" );
                }

                used += snprintf(sql + used, bufsz - used,
                                 ") ORDER BY LENGTH(domain) DESC LIMIT 1;" );
        }

        /* Execute query */
        {
                char **results = NULL;
                int rows = 0, cols = 0;
                rc = sqlite3_get_table(db, sql, &results, &rows, &cols, &errmsg);
                if (rc != SQLITE_OK) {
                        log_message(LOG_ERR, "Filter DB query failed: %s", errmsg ? errmsg : sqlite3_errmsg(db));
                        if (errmsg) sqlite3_free(errmsg);
                        if (results) sqlite3_free_table(results);
                        goto COMMON_EXIT;
                }

                if (rows > 0 && cols > 0) {
                        /* results array: first row is header, data starts at index cols */
                        char *val = results[cols];
                        if (val && val[0] == 'P') {
                                result = 0; /* permit */
                        } else if (val && val[0] == 'D') {
                                result = 1; /* deny */
                        } else {
                                /* Unexpected value - treat as default */
                                result = (config->filter_opts & FILTER_OPT_DEFAULT_DENY) ? 1 : 0;
                        }
                } else {
                        /* No matching rule found */
                        result = (config->filter_opts & FILTER_OPT_DEFAULT_DENY) ? 1 : 0;
                }

                if (results) sqlite3_free_table(results);
        }

        /* fall through to cleanup */

COMMON_EXIT:
        if (copy) safefree(copy);
        if (parents) {
                for (i = 0; i < (int)np; ++i) safefree(parents[i]);
                free(parents);
        }
        if (sql) safefree(sql);
        return result;

oom:
        log_message(LOG_ERR, "Out of memory parsing filter data");
        if (copy) safefree(copy);
        if (parents) {
                for (i = 0; i < (int)np; ++i) safefree(parents[i]);
                free(parents);
        }
        if (sql) safefree(sql);
        /* On OOM, be conservative and block if default deny, otherwise allow */
        return (config && (config->filter_opts & FILTER_OPT_DEFAULT_DENY)) ? 1 : 0;
}
