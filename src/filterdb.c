#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sqlite3.h>
#include "main.h"
#include "log.h"
#include "conf.h"
#include "filterdb.h"

// Global database connection handle
static sqlite3 *filterdb_handle = NULL;

// Database schema
static const char *filterdb_schema=
	"CREATE TABLE IF NOT EXISTS domains ( \
		requests INTEGER DEFAULT 0, \
		rule TEXT CHECK(rule IN ('P', 'D', NULL)) DEFAULT NULL, \
		subdomains TEXT CHECK(subdomains IN ('Y', 'N')) DEFAULT 'N', \
		domain TEXT PRIMARY KEY, \
		comment TEXT \
	) STRICT;"

static const char *filterdb_check="\
	SELECT requests,rule,subdomains,domain,comment \
	FROM domains

// Initialize the SQLite database.
// Opens or creates the database file specified in config->filterdb.
int filterdb_open(void){
	int ret;
	char *errmsg = NULL;
	
	//TODO: is it necessary to check config here?
	if(!config || !config->filter) {
	//if(config == NULL || config->filter == NULL) {
		log_message(LOG_ERR, "Configuration error: no filter database.");
		return -1;
	}

	// Open the database
	ret = sqlite3_open(config->filter, &filterdb_handle);
	if (ret != SQLITE_OK) {
		log_message(LOG_ERR, "Failed to open SQLite database at %s: %s",
			config->filter, sqlite3_errmsg(filterdb_handle));
		sqlite3_close(filterdb_handle);
		filterdb_handle = NULL;
		return -1;
	}
	log_message(LOG_INFO, "Filter database opened: %s", config->filter);

	// Try to create table
	ret = sqlite3_exec(filterdb_handle, filterdb_schema, NULL, NULL, &errmsg);
	if (ret != SQLITE_OK) {
		log_message(LOG_ERR, "Database schema creation failed: %s", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(filterdb_handle);
		filterdb_handle = NULL;
		return -1;
	}
	log_message(LOG_INFO, "Filter database initialized.");
	return 0;
}

// Close filter database.
int filterdb_close(void){
	int ret;
	if(!filterdb_handle) return 0;
	//if(filterdb_handle==NULL) return 0;
	ret = sqlite3_close(filterdb_handle);
	if(ret != SQLITE_OK){
		log_message(LOG_ERR, "Error closing database: %s", sqlite3_errmsg(filterdb_handle));
		return -1;
	}
	filterdb_handle = NULL;
	log_message(LOG_INFO, "Database connection closed.");
	return 0;
}

