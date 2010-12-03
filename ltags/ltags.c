#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <assert.h>

#include "queue.h"

#include "ext/sqlite/sqlite3.h"

#ifdef _WIN32
# include "ext/dirent.h"
# include "ext/getopt/getopt.h"
#else
# include <getopt.h>
# include <dirent.h>
# include <strings.h>
# define stricmp strcasecmp
#endif

#ifndef MAX_PATH
# define MAX_PATH 1000
#endif
 
void debug(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}

sqlite3 *db;

char *loadWhole(const char *path, char **end) {
	char *r = 0;
	struct stat st;
		
	if(0 <= stat(path, &st)) {
		r = malloc(st.st_size + 1);
		
		if(r) {
			FILE *fp = fopen(path, "r");
			if(fp) {
				int size = fread(r, 1, st.st_size, fp);
				if(end)
					*end = r + size;
					
				if(size < st.st_size) {
					fprintf(stderr, "Can't read more than %d of %d in %s", 
						size, st.st_size, path);
				}

				fclose(fp);
			} else {
				fprintf(stderr, "Can't fopen %s\n", path);
			}
				
		} else {
			fprintf(stderr, "No memory to load %s\n", path);
		}
	} else {
		fprintf(stderr, "Can't stat %s\n", path);
	}

	return r;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
  int i;
  for(i=0; i<argc; i++){
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  return 0;
}

void run(char *stmt) {
	int rc;
  char *zErrMsg = 0;
  rc = sqlite3_exec(db, stmt, callback, 0, &zErrMsg);
  if( rc!=SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
		exit(1);
  }
}

struct Word {
	const char *start, *end;
};

#define MAX_TAG_CNT 256

struct Span {
	const char *name, *nameEnd;
	struct Word tags[256], *tagsEnd;
	int start, end;
	int mtime;
	const char *path;

	struct Span *parent;
	void *particular;
};

// parser state		
struct File {
	const char *path;
	int mtime;

	char *contents;
	char *contentsEnd;
	char *token;
	char *tokenEnd;
	struct Span *rootSpan;
	struct Span *currentSpan;
	void *langParserState;
};

// Let's be consistent with a metaphor of a tree
#define UP '/' 

// hyperoptimized

#define CHAR_TOKENMIDDLE 1
#define CHAR_TOKENSTART  2
#define CHAR_SPACE       4

const int charFlags[/*256*/128] = {
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 00
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10
	4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 30
	0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 40
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 3, 0, // 50
	0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 60
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, // 70
};

#define countof(something_M) (sizeof(something_M)/sizeof(something_M[0]))

int loadSpan(struct Span *pSpan) {
	return 1;
}

#define ASSERTSQL(expr_M) do{\
	r = expr_M; if(r != SQLITE_OK) {\
	fprintf(stderr, "SQLite assertion fail: '%s', code %d\n", #expr_M, r);\
	exit(1);\
	}}while(0)

void saveSpan(const struct Span *pSpan) {
	int r;
	sqlite3_stmt *stm;
	static const char *update = "UPDATE spans SET status=0 WHERE " 
		"name=? AND path=? AND start=? AND end=? AND tags=?",
		*insert = "INSERT INTO spans (name, path, start, end, tags, mtime, status) "
		"VALUES (?, ?, ?, ?, ?, ?, 0)";
	const char *op = update;

	char text[MAX_TAG_CNT * 32], *tail =  text, *nextTail = text;
	const struct Word *w = pSpan->tags;

	while(w < pSpan->tagsEnd) {
		nextTail = tail + (w->end - w->start) + 1;
		if(nextTail > text + sizeof text) {
			debug("SPAN TEXT OVERFLOW");
			break;
		}

		memcpy(tail, w->start, w->end - w->start);
		tail = nextTail;
		tail[-1] = ' ';
		w++;
	}
	tail[-1] = 0;
	debug("Saving span: %s", text);
	
	
	while(1) {
		r = sqlite3_prepare_v2(db, op, -1, &stm, 0);
		if(r != SQLITE_OK) { 
			fprintf(stderr, "prep (%s): %d\n", op, r);
			exit(1);
		}

		ASSERTSQL(sqlite3_bind_text(stm, 1, pSpan->name, pSpan->nameEnd - pSpan->name, 
				SQLITE_STATIC));
		ASSERTSQL(sqlite3_bind_text(stm, 2, pSpan->path, -1, SQLITE_STATIC));
		ASSERTSQL(sqlite3_bind_int(stm, 3, pSpan->start));
		ASSERTSQL(sqlite3_bind_int(stm, 4, pSpan->end));
		ASSERTSQL(sqlite3_bind_int(stm, 4, pSpan->end));
		ASSERTSQL(sqlite3_bind_text(stm, 5, text, -1, SQLITE_STATIC));

		if(insert == op) {
			ASSERTSQL(sqlite3_bind_int(stm, 6, pSpan->mtime));
		}

		// TODO LOCK

		r = sqlite3_step(stm);
		if(r != SQLITE_DONE) {
			fprintf(stderr, "step: %d\n", r);
			exit(1);
		}

		r = sqlite3_changes(db);
		
		// TODO UNLOCK

		if(r)
			return;

		op = insert;
	}
}
	

struct JavaParserState {
	char *probableName, *probableNameEnd;
};

struct JavaSpanState {
	int braceCnt;
};

#define THIS ((struct JavaParserState*)(pFile->langParserState))

static void startParsingJavaSrc(struct File *pFile) {
	pFile->langParserState = calloc(sizeof (struct JavaParserState), 1);
}


struct Span *addTagToCurrentSpan(struct File *pf, 
	const char *start, const char *end) {
	pf->currentSpan->tagsEnd->start = start;
	pf->currentSpan->tagsEnd->end = end;
	pf->currentSpan->tagsEnd++;
	return pf->currentSpan;
}

struct Span *startSpan(struct File *pf, const char *name, const char *nameEnd,
	const char *start) {
	struct Span *s = malloc(sizeof (struct Span));
	s->name = name;
	s->nameEnd = nameEnd;
	s->path = pf->path;
	s->mtime = pf->mtime;
	s->start = start - pf->contents;
	s->tagsEnd = s->tags;
	s->end = 0;

	s->parent = pf->currentSpan;
	pf->currentSpan = s;
	addTagToCurrentSpan(pf, name, nameEnd);
	return s;
}

struct Span *finishLastSpan(struct File *pf, const char *end) {
	struct Span *s = pf->currentSpan;
	s->end = end - pf->contents;
	saveSpan(s);
	pf->currentSpan = s->parent;
	free(s);
	return pf->currentSpan;
}

	

static void parseJavaWord(struct File *pf) {
	int rw = getJavaReservedWordIndex(pf->token, pf->tokenEnd - pf->token);
	
	if(!pf->currentSpan)
		startSpan(pf, pf->token, pf->tokenEnd, pf->token);
	else 
		addTagToCurrentSpan(pf, pf->token, pf->tokenEnd);
}

static void parseJavaPunctuation(struct File *pf, const char *p) {
	struct Span *newSpan;
	switch(*p) {
	case ';':
	case ')':
		if(pf->currentSpan)
			finishLastSpan(pf, p);
	}
}



#define SPACE         0
#define TOKEN         1
#define NUMBER        2
#define COMMENT_LINE  '\n'
#define COMMENT_LINES '*'

void parseJava(struct File *pf) {
	int r;
	char *p;
	int mode, flags;
	
	pf->token = p = pf->contents;
	mode = SPACE;
	flags = 0;
	for(;;p++) {
		switch(mode) {
		case '\'':
		case '"':
			// p[-1] is valid here, bc we must have entered this mode by
			// reading some characters
			if(mode == *p) {
				if('\\' != p[-1]) 
					mode = SPACE;
			}	else if(pf->contentsEnd == p)
				goto end;
			break;
					
			
		case COMMENT_LINE:
			if('\n' == *p) {
				if(pf->contentsEnd == p)
					goto end;
				mode = SPACE;
			}
			break;

		case COMMENT_LINES:
			if('*' == *p) {
				// p[1] is valid here, bc last valid byte is padded '\n'
				if('/' == p[1])
					mode = SPACE;
			} else if (pf->contentsEnd == p) 
				goto end;
			break;

		case NUMBER:
			if('.' == *p)
				break;
			if(*p >= countof(charFlags))
				flags = CHAR_TOKENSTART | CHAR_TOKENMIDDLE;
			else 
				flags = charFlags[*p];
			
			if(flags & CHAR_TOKENMIDDLE) 
				break;
			
			goto space;
			
		case TOKEN:
			if(*p >= countof(charFlags))
				flags = CHAR_TOKENSTART | CHAR_TOKENMIDDLE;
			else 
				flags = charFlags[*p];

			if(flags & CHAR_TOKENMIDDLE) 
				break;
			else {
				// token just completed!
				pf->tokenEnd = p;
				parseJavaWord(pf);
				mode = SPACE;
				// no break
			}
			
		case SPACE:
		space:

			if('/' == *p) {
				// p[1] is a valid memory reference here because the last byte is 
				// appended '\n'
				if('*' == p[1]) {
					mode = COMMENT_LINES;
					break;
				} else if('/' == p[1]) {
					mode = COMMENT_LINE;
					break;
				}
			}

			if('"' == *p || '\'' == *p) {
				mode = *p;
				break;
			}
			
			if(*p >= countof(charFlags))
				flags = CHAR_TOKENSTART | CHAR_TOKENMIDDLE;
			else 
				flags = charFlags[*p];
			
			if(CHAR_TOKENSTART & flags) {
				pf->token = p;
				mode = TOKEN;
			} else if(CHAR_TOKENMIDDLE & flags) {
				mode = NUMBER;
			} else if(CHAR_SPACE & flags) {
				if(pf->contentsEnd == p)
					goto end;
				break;
			} else 
				parseJavaPunctuation(pf, p);
			
		} // switch(mode)
	} // for(;;p++)
		
		
	
 end:;
}


pthread_t parserThreads[4];
void *files[5];
queue_t fileQueue = QUEUE_INITIALIZER(files);

void updateFile(const char *path) {
	char bf[2 * MAX_PATH], *name, *nameEnd;
	struct File *pf;
	struct stat st;
	int r;
	int storedTime = 0;
	sqlite3_stmt *stm;
	
	r = stat(path, &st);
	if(r < 0) {
		debug("Can't stat %s", path);
		return;
	}

	name = strrchr(path, UP);
	nameEnd = strchr(name, '.');
	ASSERTSQL(sqlite3_prepare_v2(db, "SELECT mtime FROM spans WHERE name = ?", -1,
			&stm, 0));

	ASSERTSQL(sqlite3_bind_text(stm, 1, name, nameEnd - name, SQLITE_STATIC));

	r = sqlite3_step(stm);
	if(SQLITE_ROW == r) {
		storedTime = sqlite3_column_int(stm, 0);
	} else if(r != SQLITE_DONE) {
		fprintf(stderr, "step: %d\n", r);
		return;
	}
	
	if(storedTime == st.st_mtime) {
		debug("Skipping: %s", path);
		return;
	}
	pf = malloc(sizeof(*pf));
			
	pf->path = strdup(path);
	pf->mtime = st.st_mtime;
	pf->currentSpan = NULL;


	debug("Loading: %s", path);
	pf->contents = loadWhole(path, &pf->contentsEnd);
	*pf->contentsEnd = '\n'; //padding

	queue_enqueue(&fileQueue, pf);
}

void updateDir(char *path) {
	char *end = strrchr(path, 0), *suffix;
	DIR *d;
	struct dirent *entry;

	if(*path) {
		d = opendir(path);
		*end++ = UP;
	} else {
		d = opendir(".");
	}

	if(!d) {
		debug("Can't opendir: %s", path);
		return;
	}
	
	while(entry = readdir(d)) {
		if('.' == entry->d_name[0])
			continue;
		
		if(DT_DIR & entry->d_type) {
			strncpy(end, entry->d_name, MAX_PATH - (end - path));
			updateDir(path);
			continue;
		}

		strncpy(end, entry->d_name, MAX_PATH - (end - path));
		suffix = strrchr(end, 0) - 5;
		if(suffix > path && !stricmp(suffix, ".java")) {
			updateFile(path);
		}
	}	
}

void *parserThread(void *unused) {
	struct File *pf = 0;

	while(1) {
		pf = queue_dequeue(&fileQueue);
		if(!pf)
			break;
		parseJava(pf);
		free(pf->path);
		free(pf);
	}
}

/*
	Tested on android/packages/apps/Gallery/
	
	vg@nostromo:~/src/android/packages/apps/Gallery$ find -iname *.java|xargs du -ch	
	...
	520K    total

	Single threaded, THREADSAFE=1
	real    2m43.952s
	user    2m35.610s
	sys     0m0.676s

	
	Single threaded, THREADSAFE=0
	real    2m35.707s
	user    2m25.605s
	sys     0m1.528s

	Queue of 5, 4 parser threads
	real    2m49.338s
	user    2m33.246s
	sys     0m6.472s
*/


#define PROGNAME "ltags"

const char *dbName = "." PROGNAME ".sqlite";
char wdPath[MAX_PATH];
char dbPath[MAX_PATH];
char dbDirPath[MAX_PATH];

void update() {
	int r;
	char curPath[MAX_PATH];
	sqlite3_stmt *stm;
	struct stat st;
	int justCreated = 0;
	
	int i;

	if(stat(dbPath, &st) < 0)
		justCreated = 1;

	r = sqlite3_open(dbPath, &db);
	if(r) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	//run("CREATE VIRTUAL TABLE regions USING rtree(id, start, end)");

	if(justCreated) {
		ASSERTSQL(sqlite3_prepare_v2(db, 
				"CREATE VIRTUAL TABLE spans USING fts3("
				"name   VARCHAR(100), "
				"path   VARCHAR(256), "
				"mtime  INTEGER, "
				"start  INTEGER, "
				"end    INTEGER, "
				"status INTEGER, "
				"tags   TEXT)",
				-1, &stm, 0));

		r = sqlite3_step(stm);
		if(r != SQLITE_DONE) {
			debug("Table creation step: %d", r);
		}
		ASSERTSQL(sqlite3_finalize(stm));
	
	/*run("CREATE TABLE IF NOT EXISTS spans("
		"name   VARCHAR(100), "
		"path   VARCHAR(256), "
		"mtime  INTEGER, "
		"start  INTEGER, "
		"end    INTEGER, "
		"status INTEGER)");
	
	/*run("CREATE TABLE IF NOT EXISTS tags("
		"name   VARCHAR(100), "
		"sid    INTEGER)");*/
	}

	for(i = 0; i < countof(parserThreads); i++) {
		pthread_create(&parserThreads[i], NULL, parserThread, NULL);
	}
	
	debug("Invalidating old entries...");
	run("UPDATE spans SET status=1"); // 1 means "questionable"
	run("BEGIN");
	strcpy(curPath, dbDirPath);
	updateDir(curPath);


	for(i = 0; i < countof(parserThreads); i++) {
		queue_enqueue(&fileQueue, NULL);
	}
	for(i = 0; i < countof(parserThreads); i++) {
		pthread_join(parserThreads[i], NULL);
	}

	debug("Commit...");
	run("COMMIT");
	debug("Deleting old entries...");
	run("DELETE FROM spans WHERE status=1");

	sqlite3_close(db);
}

const char *getPathFrom(char *d, const char *path, const char *base) {
	// Both arguments are absolute paths 
	// base is a path to a directory
	const char *slash = NULL;
	
	*d = 0;
#ifdef _WIN32
	while(*path && tolower(*path) == tolower(*base)) {
#else
	while(*path && *path == *base) {
#endif
		if('/' == *base) {
			slash = base;
		}
		path++, base++;
	}

	if(!slash) // different Windows drive letters
		return path;
	
	if(*base) { // go back
		path -= (base - slash);
		base = slash;
	}

	while(*base) {
		if('/' == *base)
			strcat(d, "../");
		base++;
	}
	
	strcat(d, path + 1);
	return d;
}

int findDb() {
	char *end, *minEnd = 0;
	struct stat st;

	strcpy(dbDirPath, wdPath);
	end = strchr(dbDirPath, 0);
	strcat(dbDirPath, "/");
	do {
		strcpy(end + 1, dbName);
		
		if(stat(dbDirPath, &st) >= 0 ) {
			minEnd = end;
		}

		*end = 0;
		end = strrchr(dbDirPath, '/');
	} while(end > dbDirPath + 2);

	if(!minEnd)
		return 0;
	
	strcpy(dbDirPath, wdPath);
	*minEnd = 0;
	
	strcpy(dbPath, dbDirPath);
	strcat(dbPath, "/");
	strcat(dbPath, dbName);
	return 1;
}
		
	
	
	

#define SEARCH 1
#define COMPLETE 2
#define UPDATE 3

int main(int argc, char **argv){
	int r;
	sqlite3_stmt *stm;
	int mode = UPDATE;

	static struct option longOpts[] = {
		{"complete", required_argument, 0, 'C'},
		{0, 0, 0, 0}
	};

	int c, optInd = 0;

	const char *prefix = "";
	int completionTargetIndex = 0;

	char *p;
	
	/*for(c = 0; c < argc; c++)
		debug("\narg %d: '%s'", c, argv[c]);
	//*/

	if(!getcwd(wdPath, sizeof dbPath - sizeof dbName - 2)) {
		fprintf(stderr, "Can't getcwd");
		exit(1);
	}

	for(p = wdPath; *p; p++) 
		if('\\' == *p) *p = '/';
	
	while(c = getopt_long(argc, argv, "", longOpts, &optInd), c != -1) {
		switch(c) {
		case 'C':
			mode = COMPLETE;
			completionTargetIndex = atoi(optarg);
		}
	}

	if(optind < argc) {
		if(UPDATE == mode)
			mode = SEARCH;
	}


	if(UPDATE == mode) {
		if(!findDb()) {
			strcpy(dbPath, wdPath);
			strcat(dbPath, "/");
			strcat(dbPath, dbName);
		}
		update();
	} else {
		char query[1024];
		// --complete really should be as time-sensitive as we can get,
		// because I get really annoyed when I press TAB and bash goes
		// god knows where
		if(!findDb()) {
			if(SEARCH == mode) {
				fprintf(stderr, "No database found!\n");
				return 1;
			} else {
				// Autocompletion is notoriously noninteractive process, so I think
				// we have to take every chance to send out a message we can get
				puts("--create-index-because-it-s-not-found");
				return 0;
			}
		}
		
		r = sqlite3_open(dbPath, &db);
		if(r) {
			fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}

		*query = 0;
		if(COMPLETE == mode) {
			completionTargetIndex += optind;
			optind++; // program name comes first
		}

		while(optind < argc) {
			strncat(query, argv[optind], sizeof query);
			if(completionTargetIndex == optind) {
				prefix = argv[optind];
				strncat(query, "*", sizeof query);
			}
			strncat(query, " ", sizeof query);
			optind++;
		}
			
		//debug(query);
		if(COMPLETE == mode && !*query) {
		ASSERTSQL(sqlite3_prepare_v2(db, 
				"SELECT name, path, start, end, tags " 
				"FROM spans ",
				-1, &stm, 0));
		} else {
			ASSERTSQL(sqlite3_prepare_v2(db, 
					"SELECT name, path, start, end, tags " 
					"FROM spans " 
					"WHERE tags MATCH ? ", 
					-1, &stm, 0));
		
			ASSERTSQL(sqlite3_bind_text(stm, 1, query, -1, SQLITE_STATIC));
		}

		while(r = sqlite3_step(stm), r == SQLITE_ROW) {
			char pathFromWd[MAX_PATH];
			const char *path, *name, *absPath;
			const char *contents, *contentsEnd;
			const char *line, *target, *nextLine;
			int start, end;
			int lineNumber;

			name = sqlite3_column_text(stm, 0);
			absPath = sqlite3_column_text(stm, 1);
			start = sqlite3_column_int(stm, 2);
			end = sqlite3_column_int(stm, 3);

			// Count lines to make output grep-like
			
			if(SEARCH == mode) {
				path = getPathFrom(pathFromWd, absPath, wdPath);
				
				// print the shortest path
				if(strlen(absPath) <= strlen(path))
					path = absPath;

				contents = loadWhole(path, &contentsEnd);
				if(!contents) {
					fprintf(stderr, "Can't load %s\n", path);
					continue;
				}
				
				lineNumber = 1;
				target = contents + start;
				line = contents;
				do {
					nextLine = memchr(line, '\n', contentsEnd - line);
					if(!nextLine) {
						nextLine = contentsEnd;
						break;
					} else 
						nextLine++;

					if(nextLine > target)
						break;
					lineNumber++;
					line = nextLine;
				} while(1);
				
			
				printf("%s:%d:", path, lineNumber);
				fwrite(line, 1, nextLine - line, stdout); 
			} else {
				const char *tags = sqlite3_column_text(stm, 4), *next = tags;
				while(*tags) {
					next = strchr(tags, ' ');
					if(!next)
						next = strchr(tags, 0);
					if(!strncmp(prefix, tags, strlen(prefix))) {
							fwrite(tags, 1, next - tags, stdout);
							fputs(" ", stdout);
					}
					if(*next)
						next++;
					tags = next;
				}					
			}
		}

		if(r != SQLITE_DONE) {
			fprintf(stderr, "No step: %d", r);
			exit(1);
		}
	}

  return 0;
}
