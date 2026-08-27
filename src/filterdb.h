#include <sqlite3.h>

// (Create and) open the filter database.
// return: 0 ok, -1 error
int filterdb_open(void);

// Close filter database.
void filterdb_close(void);
