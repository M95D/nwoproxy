# Action Plan: TinyProxy conversion

## Summary
TinyProxy is a filtering proxy server. These modifications are planned:
- Replace text file based URL and domain filtering system with a SQLite database, domain-only, case-insensitive filtering system.
- Update configuration files for the new filtering system.
- Modify build system to link to system's SQLite shared library. New filtering system is always-on - can't be disabled by build configuration.
- Query database for each connection. No in-memory filters. No SIGHUP reload.
- Modify WebUI administration interface of TinyProxy to operate it's SQLite database instead of text file filters.
- Add Android app as an alternative to WebUI.
- Rename the project.
- Update documentation.

## 1. Database Schema

Table "domains":

| Column | Name | Type | Contents |
|:---:|---|---|---|
| 1 | requests | integer | Number of requests, counts the number of times each domain was requested |
| 2 | rule | "P"/"D"/NULL | P=permit, D=deny, NULL=undetermined (use default mode) |
| 3 | subdomains | "Y"/"N" | Match subdomains when applying filter rule (yes/no) |
| 4 | domain | string | Domain, subdomain or complete host name to be matched. |
| 5 | comment | string | Comment |

## 2. Operation of the new filtering system

Each time a connection is requested:
1) The requested complete host name (domain + all subdomains) is added to the database if it doesn't already exist and "requests" counter is incremented.
2) The database is searched for an exact match of host name or, if not found or rule is NULL, search for parent domains with "Y" in "match subdomains" column, where rule is not null, in descending order. If no rule is found for any of them, the default filtering mode should be applied.
Example: When receiving a request for "sub2.sub1.domain.co.uk", database will be searched like this:

`SELECT rule FROM domains WHERE rule IS NOT NULL AND ( ( domain = "sub2.sub1.domain.co.uk") OR ( subdomains = "Y" AND ( domain IN ("sub1.domain.co.uk", "domain.co.uk", "co.uk" ) ORDER BY LENGTH (domain) DESC LIMIT 1;`

## Implementation steps (priority)

1) Add host SQLite shared library dependency to the build system. Quit with error if not found. Tolerate cross-compiling - don't use hardcoded paths to build host's filesystem.
2) Modify configuration file and it's processing for the new filtering system. The database path is set with the same option "Filter". The fallback rule remains "FilterDefaultDeny". The rest of the Filter configuration options are no longer used and must be removed.
3) Modify the startup and shutdown. At startup, the database must be opened or created if it does not exist. At shutdown it must be closed.
4) Replace current URL and domain filtering with SQLite query explained above.
5) Remove regex dependencies from the build system.
6) Search and remove remaining references to old text file based filters.
7) Add error handling for database errors: Check database on startup. If error occurs during startup, log error and exit. If error occurs during operation, log error and return 503 to clients.
8) Optimizations.
9) Rename the project.
10) Update documentation.

## Implementation steps (later)

11) Modify WebUI to operate SQLite database instead of text files
12) Implement live monitoring of requests in WebUI with separate pages or tabs for each client.
13) Implement setting of rules directly from the live monitoring page of WebUI.
14) Implement delaying connections to new domains for which no rule exists, when the live monitoring page is opened, to allow the user to create rules on-the-go.
15) Create Android app as an alternative to WebUI.
16) Implement certificate-based security to connections to the admin interface, both Android app API and WebUI.
17) Add / update automated tests.
