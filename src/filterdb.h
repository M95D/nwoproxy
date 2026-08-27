#ifndef FILTERDB_H
#define FILTERDB_H

#include <sqlite3.h>

/* Open (and create if necessary) the filter database at 'path'.
 * Returns 0 on success, non-zero on failure.
 */
int filterdb_open(const char *path);

/* Close the currently open filter database (no-op if not open). */
void filterdb_close(void);

/* Return the sqlite3* handle (or NULL if not opened). */
sqlite3 *filterdb_get(void);

#endif /* FILTERDB_H */
