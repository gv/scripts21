#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <assert.h>

#include "ext/sqlite/sqlite3.h"

#include "queue.h"

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
					fprintf(stderr, "Can't read more than %d of %u in %s", 
						size, (unsigned)st.st_size, path);
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

const char *getPathFrom(char *d, const char *path, const char *base) {
	// Both arguments are absolute paths 
	// base is a path to a directory
	const char *slash = NULL;
	
	*d = 0;
#ifdef _WIN32
	while(*path && tolower(*path) == tolower(*base)) 
#else
		while(*path && *path == *base) 
#endif
			{
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

#define PROGNAME "ltags"

const char *dbName = "." PROGNAME ".sqlite";
char wdPath[MAX_PATH];
char dbPath[MAX_PATH];
char dbDirPath[MAX_PATH];

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
		
	
	
static int callback(void *NotUsed, int argc, char **argv, char **azColName){
  int i;
  for(i=0; i<argc; i++){
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  return 0;
}


sqlite3 *db;

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
	struct Word tags[256], *tagsEnd;
	int start, end;
	int mtime;
	const char *path;
	
	struct Span *parent;
	void *particular;
};
 

struct File;
struct Language {
	int (*couldDoPath)(const char *path);
	void (*processWord)(struct File*);
	void (*processNonword)(struct File*, const char*);
};

// parser state		
struct File {
	char *path;
	int mtime;

	char *contents;
	char *contentsEnd;
	char *token;
	char *tokenEnd;
	struct Span *rootSpan;
	struct Span *currentSpan;

	struct Language *language;
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
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 3, 3, // 50
	0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 60
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, // 70
};
#define countof(something_M) (sizeof(something_M)/sizeof(something_M[0]))


int loadSpan(struct Span *pSpan) {
	return 1;
}
 
unsigned classifyChar(int c) {
	if(c >= countof(charFlags))
		return CHAR_TOKENSTART | CHAR_TOKENMIDDLE;
	else 
		return charFlags[c];
}
 
#define ASSERTSQL(expr_M) do{																						\
		r = expr_M; if(r != SQLITE_OK) {																		\
			fprintf(stderr, "SQLite assertion fail: '%s', code %d\n", #expr_M, r); \
			exit(1);																													\
		}}while(0)
 

#ifdef _WIN32
# define __thread __declspec(thread)
#endif

__thread sqlite3_stmt *spanUpdateStm, *spanInsertStm;

void saveSpan(const struct Span *pSpan) {
	int r;
	sqlite3_stmt *stm;
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
	//debug("Saving span: %s", text);
	
	
	stm = spanUpdateStm;
	while(1) {
		ASSERTSQL(sqlite3_reset(stm));
		ASSERTSQL(sqlite3_bind_text(stm, 1, pSpan->path, -1, SQLITE_STATIC));
		ASSERTSQL(sqlite3_bind_int(stm, 2, pSpan->start));
		ASSERTSQL(sqlite3_bind_int(stm, 3, pSpan->end));
		ASSERTSQL(sqlite3_bind_text(stm, 4, text, -1, SQLITE_STATIC));

		if(spanInsertStm == stm) {
			ASSERTSQL(sqlite3_bind_int(stm, 5, pSpan->mtime));
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
		
		stm = spanInsertStm;
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

struct Span *startSpan(struct File *pf, const char *start) {
	struct Span *s = malloc(sizeof (struct Span));
	s->path = pf->path;
	s->mtime = pf->mtime;
	s->start = start - pf->contents;
	s->tagsEnd = s->tags;
	s->end = 0;

	s->parent = pf->currentSpan;
	pf->currentSpan = s;
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

int spanHasTag(const struct Span *ps, const char *start) {
	const struct Word *w = ps->tagsEnd;
	while(--w >= ps->tags) {
		if(start == w->start)
			return 1;
	}
	 
	return 0;
}
	 
	 
	 
const char F_FEATURE[] = "f"; // file
const char D_FEATURE[] = "d"; // definition
const char C_FEATURE[] = "c"; // class

static void processJavaWord(struct File *pf) {
	int rw = getJavaReservedWordIndex(pf->token, pf->tokenEnd - pf->token);
	
	if(spanHasTag(pf->currentSpan, F_FEATURE))
		startSpan(pf, pf->token);
	addTagToCurrentSpan(pf, pf->token, pf->tokenEnd);
}

static void processJavaNonword(struct File *pf, const char *p) {
	struct Span *newSpan;
	switch(*p) {
	case ';':
	case ')':
		if(!spanHasTag(pf->currentSpan, F_FEATURE))
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
				pf->language->processWord(pf);
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
			
			flags = classifyChar(*p);
			
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
				pf->language->processNonword(pf, p);
		} // switch(mode)
	} // for(;;p++)
	
		
	
 end:;
}

 static int endsWithDotJava(const char *path) {
	const char *suffix;
	suffix = strrchr(path, 0) - 5;
	return (suffix > path && !stricmp(suffix, ".java"));
}

const struct Language languages[] = {
	{endsWithDotJava, processJavaWord, processJavaNonword}
};
 
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
	const struct Language *l;
	
	r = stat(path, &st);
	if(r < 0) {
		debug("Can't stat %s", path);
		return;
	}

	/*name = strrchr(path, UP);
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
	*/

	if(storedTime == st.st_mtime) {
		debug("Skipping: %s", path);
		return;
	}

	l = languages + countof(languages);
	while(--l >= languages) {
		if(l->couldDoPath(path)) {
			break;
		}
	}
	if(l < languages) {
		debug("No language detected for for %s", path);
		return;
	}
		
	
	pf = malloc(sizeof(*pf));
	pf->language = l;
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
		updateFile(path);
	}	
}



void *parserThread(void *unused) {
	int r;
	struct File *pf = 0;
	const char *ws, *we;

	ASSERTSQL(sqlite3_prepare_v2(db, 
			"UPDATE spans SET status=0 WHERE " 
			"path=? AND start=? AND end=? AND tags MATCH ?",
			-1, &spanUpdateStm, 0));
	ASSERTSQL(sqlite3_prepare_v2(db,
			"INSERT INTO spans (path, start, end, tags, mtime, status) "
			"VALUES (?, ?, ?, ?, ?, 0)",
			-1, &spanInsertStm, 0));

	while(1) {
		pf = queue_dequeue(&fileQueue);
		if(!pf)
			break;
		
		startSpan(pf, pf->contents);
		addTagToCurrentSpan(pf, F_FEATURE, F_FEATURE + 1);

		assert(strchr(pf->path, '/'));
		ws = we = strrchr(pf->path, 0);
		while(--ws) {
			if(!(CHAR_TOKENMIDDLE & classifyChar(*ws))) {
				
				if(we - ws > 1)
					addTagToCurrentSpan(pf, ws+1, we);
				if('/' == *ws)
					break;
				we = ws;
			}
		}
			
		debug("Parsing: %s", pf->path);
		parseJava(pf);

		while(pf->currentSpan)
			finishLastSpan(pf, pf->contentsEnd);
		free(pf->contents);
		free(pf->path);
		free(pf);
	}
	return 0;
}

/*
	Tested on android/packages/apps/Gallery/
	
	vg@nostromo:~/src/android/packages/apps/Gallery$ find -iname *.java|xargs du -ch	
	...
	520K    total


*/



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

	//#ifdef USE_FTS3
		if(justCreated) {
			ASSERTSQL(sqlite3_prepare_v2(db, 
					"CREATE VIRTUAL TABLE spans USING fts3("
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
		}
		//#endif

			/*run("CREATE TABLE IF NOT EXISTS spans("
				"path   VARCHAR(256), "
				"mtime  INTEGER, "
				"start  INTEGER, "
				"end    INTEGER, "
				"status INTEGER)");
	
				/*run("CREATE TABLE IF NOT EXISTS tags("
				"name   VARCHAR(100), "
				"sid    INTEGER)");*/
		run("PRAGMA journal_mode=WAL");
	
		//run("CREATE INDEX spidx on spans(path, start)");

		for(i = 0; i < countof(parserThreads); i++) {
			pthread_create(&parserThreads[i], NULL, parserThread, NULL);
		}
	
		debug("Invalidating old entries...");
		run("UPDATE spans SET status=1"); // 1 means "questionable"
		run("BEGIN");
		strcpy(curPath, dbDirPath);
		updateDir(curPath);

		// parser thread stops when it receives NULL
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
			strncat(query, argv[optind], sizeof query - 1);
			if(completionTargetIndex == optind) {
				prefix = argv[optind];
				strncat(query, "*", sizeof query);
			}
			strncat(query, " ", sizeof query - 1);
			optind++;
		}
			
		//debug(query);
		if(COMPLETE == mode && !*query) {
			ASSERTSQL(sqlite3_prepare_v2(db, 
					"SELECT path, start, end, tags " 
					"FROM spans ",
					-1, &stm, 0));
		} else {
			ASSERTSQL(sqlite3_prepare_v2(db, 
					"SELECT path, start, end, tags " 
					"FROM spans " 
					"WHERE tags MATCH ? ", 
					-1, &stm, 0));
		
			ASSERTSQL(sqlite3_bind_text(stm, 1, query, -1, SQLITE_STATIC));
		}

		while(r = sqlite3_step(stm), r == SQLITE_ROW) {
			char pathFromWd[MAX_PATH];
			const char *path, *absPath;
			const char *contents;
			char *contentsEnd;
			const char *line, *target, *nextLine;
			int start, end;
			int lineNumber;

			absPath = sqlite3_column_text(stm, 0);
			start = sqlite3_column_int(stm, 1);
			end = sqlite3_column_int(stm, 2);

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
				const char *tags = sqlite3_column_text(stm, 3), *next = tags;
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
