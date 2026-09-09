/* Library which manipulates firewall rules.  Version $Revision: 1.35 $ */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C)1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR "/usr/local/lib/iptables"
#endif

#ifndef __OPTIMIZE__
STRUCT_ENTRY_TARGET *
GET_TARGET(STRUCT_ENTRY *e)
{
	return (void *)e + e->target_offset;
}
#endif

static int sockfd = -1;
static void *iptc_fn = NULL;

static const char *hooknames[]
= { [HOOK_PRE_ROUTING]  "PREROUTING",
    [HOOK_LOCAL_IN]     "INPUT",
    [HOOK_FORWARD]      "FORWARD",
    [HOOK_LOCAL_OUT]    "OUTPUT",
    [HOOK_POST_ROUTING] "POSTROUTING",
#ifdef HOOK_DROPPING
    [HOOK_DROPPING]	"DROPPING"
#endif
};

struct counter_map
{
	enum {
		COUNTER_MAP_NOMAP,
		COUNTER_MAP_NORMAL_MAP,
		COUNTER_MAP_ZEROED,
		COUNTER_MAP_SET
	} maptype;
	unsigned int mappos;
};

/* Convenience structures */
struct ipt_error_target
{
	STRUCT_ENTRY_TARGET t;
	char error[TABLE_MAXNAMELEN];
};

struct chain_cache
{
	char name[TABLE_MAXNAMELEN];
	/* This is the first rule in chain. */
	STRUCT_ENTRY *start;
	/* Last rule in chain */
	STRUCT_ENTRY *end;
};

STRUCT_TC_HANDLE
{
	/* Have changes been made? */
	int changed;
	/* Size in here reflects original state. */
	STRUCT_GETINFO info;

	struct counter_map *counter_map;
	/* Array of hook names */
	const char **hooknames;
	
	unsigned int gemdb;
	unsigned int gemsize;

	/* Cached position of chain heads (NULL = no cache). */
	unsigned int cache_num_chains;
	unsigned int cache_num_builtins;
	struct chain_cache *cache_chain_heads;

	/* Chain iterator: current chain cache entry. */
	struct chain_cache *cache_chain_iteration;

	/* Rule iterator: terminal rule */
	STRUCT_ENTRY *cache_rule_end;

	/* Number in here reflects current state. */
	unsigned int new_number;
	STRUCT_GET_ENTRIES entries;
};

static void
set_changed(TC_HANDLE_T h)
{
	if (h->cache_chain_heads) {
		free(h->cache_chain_heads);
		h->cache_chain_heads = NULL;
		h->cache_num_chains = 0;
		h->cache_chain_iteration = NULL;
		h->cache_rule_end = NULL;
	}
	h->changed = 1;
}

#ifdef IPTC_DEBUG
static void do_check(TC_HANDLE_T h, unsigned int line);
#define CHECK(h) do { if (!getenv("IPTC_NO_CHECK")) do_check((h), __LINE__); } while(0)
#else
#define CHECK(h)
#endif

static inline int
get_number(const STRUCT_ENTRY *i,
	   const STRUCT_ENTRY *seek,
	   unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static unsigned int
entry2index(const TC_HANDLE_T h, const STRUCT_ENTRY *seek)
{
	unsigned int pos = 0;

	if (ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
			  get_number, seek, &pos) == 0) {
		fprintf(stderr, "ERROR: offset %i not an entry!\n",
			(char *)seek - (char *)h->entries.entrytable);
		abort();
	}
	return pos;
}

static inline int
get_entry_n(STRUCT_ENTRY *i,
	    unsigned int number,
	    unsigned int *pos,
	    STRUCT_ENTRY **pe)
{
	if (*pos == number) {
		*pe = i;
		return 1;
	}
	(*pos)++;
	return 0;
}

static STRUCT_ENTRY *
index2entry(TC_HANDLE_T h, unsigned int index)
{
	unsigned int pos = 0;
	STRUCT_ENTRY *ret = NULL;

	ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
		      get_entry_n, index, &pos, &ret);

	return ret;
}

static inline STRUCT_ENTRY *
get_entry(TC_HANDLE_T h, unsigned int offset)
{
	return (STRUCT_ENTRY *)((char *)h->entries.entrytable + offset);
}

static inline unsigned long
entry2offset(const TC_HANDLE_T h, const STRUCT_ENTRY *e)
{
	return (char *)e - (char *)h->entries.entrytable;
}

static unsigned long
index2offset(TC_HANDLE_T h, unsigned int index)
{
	return entry2offset(h, index2entry(h, index));
}

static const char *
get_errorlabel(TC_HANDLE_T h, unsigned int offset)
{
	STRUCT_ENTRY *e;

	e = get_entry(h, offset);
	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) != 0) {
		fprintf(stderr, "ERROR: offset %u not an error node!\n",
			offset);
		abort();
	}

	return (const char *)GET_TARGET(e)->data;
}

/* Allocate handle of given size */
static TC_HANDLE_T
alloc_handle(const char *tablename, unsigned int size, unsigned int num_rules)
{
	size_t len;
	TC_HANDLE_T h;

	len = sizeof(STRUCT_TC_HANDLE)
		+ size
		+ num_rules * sizeof(struct counter_map);

	if ((h = malloc(len)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	h->changed = 0;
	h->cache_num_chains = 0;
	h->cache_chain_heads = NULL;
	h->counter_map = (void *)h
		+ sizeof(STRUCT_TC_HANDLE)
		+ size;
	
	strcpy(h->info.name, tablename);
	strcpy(h->entries.name, tablename);

	return h;
}

TC_HANDLE_T
TC_INIT(const char *tablename)
{
	TC_HANDLE_T h;
	STRUCT_GETINFO info;
	unsigned int i;
	int tmp;
	socklen_t s;

	iptc_fn = TC_INIT;

	if (sockfd != -1)
		close(sockfd);

	sockfd = socket(TC_AF, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		return NULL;

	s = sizeof(info);
	if (strlen(tablename) >= TABLE_MAXNAMELEN) {
		errno = EINVAL;
		return NULL;
	}
	strcpy(info.name, tablename);
	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0)
		return NULL;

	if ((h = alloc_handle(info.name, info.size, info.num_entries))
	    == NULL)
		return NULL;

/* Too hard --RR */
#if 0
	sprintf(pathname, "%s/%s", IPT_LIB_DIR, info.name);
	dynlib = dlopen(pathname, RTLD_NOW);
	if (!dynlib) {
		errno = ENOENT;
		return NULL;
	}
	h->hooknames = dlsym(dynlib, "hooknames");
	if (!h->hooknames) {
		errno = ENOENT;
		return NULL;
	}
#else
	h->hooknames = hooknames;
#endif

	/* Initialize current state */
	h->info = info;
	h->new_number = h->info.num_entries;
	for (i = 0; i < h->info.num_entries; i++)
		h->counter_map[i]
			= ((struct counter_map){COUNTER_MAP_NORMAL_MAP, i});

	h->entries.size = h->info.size;

	tmp = sizeof(STRUCT_GET_ENTRIES) + h->info.size;

	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_ENTRIES, &h->entries,
		       &tmp) < 0) {
		free(h);
		return NULL;
	}

	CHECK(h);
	return h;
}

static inline int
print_match(const STRUCT_ENTRY_MATCH *m)
{
	printf("Match name: `%s'\n", m->u.user.name);
	return 0;
}

static int dump_entry(STRUCT_ENTRY *e, const TC_HANDLE_T handle);
 
void
TC_DUMP_ENTRIES(const TC_HANDLE_T handle)
{
	CHECK(handle);

	printf("libiptc v%s.  %u entries, %u bytes.\n",
	       IPTABLES_VERSION,
	       handle->new_number, handle->entries.size);
	printf("Table `%s'\n", handle->info.name);
	printf("Hooks: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.hook_entry[HOOK_PRE_ROUTING],
	       handle->info.hook_entry[HOOK_LOCAL_IN],
	       handle->info.hook_entry[HOOK_FORWARD],
	       handle->info.hook_entry[HOOK_LOCAL_OUT],
	       handle->info.hook_entry[HOOK_POST_ROUTING]);
	printf("Underflows: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.underflow[HOOK_PRE_ROUTING],
	       handle->info.underflow[HOOK_LOCAL_IN],
	       handle->info.underflow[HOOK_FORWARD],
	       handle->info.underflow[HOOK_LOCAL_OUT],
	       handle->info.underflow[HOOK_POST_ROUTING]);

	ENTRY_ITERATE(handle->entries.entrytable, handle->entries.size,
		      dump_entry, handle);
}

/* Returns 0 if not hook entry, else hooknumber + 1 */
static inline unsigned int
is_hook_entry(STRUCT_ENTRY *e, TC_HANDLE_T h)
{
	unsigned int i;

	for (i = 0; i < NUMHOOKS; i++) {
		if ((h->info.valid_hooks & (1 << i))
		    && get_entry(h, h->info.hook_entry[i]) == e)
			return i+1;
	}
	return 0;
}

static inline int
add_chain(STRUCT_ENTRY *e, TC_HANDLE_T h, STRUCT_ENTRY **prev)
{
	unsigned int builtin;

	/* Last entry.  End it. */
	if (entry2offset(h, e) + e->next_offset == h->entries.size) {
		/* This is the ERROR node at end of the table */
		h->cache_chain_heads[h->cache_num_chains-1].end = *prev;
		return 0;
	}

	/* We know this is the start of a new chain if it's an ERROR
	   target, or a hook entry point */
	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) == 0) {
		/* prev was last entry in previous chain */
		h->cache_chain_heads[h->cache_num_chains-1].end
			= *prev;

		strcpy(h->cache_chain_heads[h->cache_num_chains].name,
		       (const char *)GET_TARGET(e)->data);
		h->cache_chain_heads[h->cache_num_chains].start
			= (void *)e + e->next_offset;
		h->cache_num_chains++;
	} else if ((builtin = is_hook_entry(e, h)) != 0) {
		if (h->cache_num_chains > 0)
			/* prev was last entry in previous chain */
			h->cache_chain_heads[h->cache_num_chains-1].end
				= *prev;

		strcpy(h->cache_chain_heads[h->cache_num_chains].name,
		       h->hooknames[builtin-1]);
		h->cache_chain_heads[h->cache_num_chains].start
			= (void *)e;
		h->cache_num_chains++;
	}

	*prev = e;
	return 0;
}

static int alphasort(const void *a, const void *b)
{
	return strcmp(((struct chain_cache *)a)->name,
		      ((struct chain_cache *)b)->name);
}

static int populate_cache(TC_HANDLE_T h)
{
	unsigned int i;
	STRUCT_ENTRY *prev;

	/* # chains < # rules / 2 + num builtins - 1 */
	h->cache_chain_heads = malloc((h->new_number / 2 + 4)
				      * sizeof(struct chain_cache));
	if (!h->cache_chain_heads) {
		errno = ENOMEM;
		return 0;
	}

	h->cache_num_chains = 0;
	h->cache_num_builtins = 0;

	/* Count builtins */
	for (i = 0; i < NUMHOOKS; i++) {
		if (h->info.valid_hooks & (1 << i))
			h->cache_num_builtins++;
	}

	prev = NULL;
	ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
		      add_chain, h, &prev);

	qsort(h->cache_chain_heads + h->cache_num_builtins,
	      h->cache_num_chains - h->cache_num_builtins,
	      sizeof(struct chain_cache), alphasort);

	return 1;
}

/* Returns cache ptr if found, otherwise NULL. */
static struct chain_cache *
find_label(const char *name, TC_HANDLE_T handle)
{
	unsigned int i;

	if (handle->cache_chain_heads == NULL
	    && !populate_cache(handle))
		return NULL;

	/* FIXME: Linear search through builtins, then binary --RR */
	for (i = 0; i < handle->cache_num_chains; i++) {
		if (strcmp(handle->cache_chain_heads[i].name, name) == 0)
			return &handle->cache_chain_heads[i];
	}

	return NULL;
}

/* Does this chain exist? */
int TC_IS_CHAIN(const char *chain, const TC_HANDLE_T handle)
{
	return find_label(chain, handle) != NULL;
}

/* Returns the position of the final (ie. unconditional) element. */
static unsigned int
get_chain_end(const TC_HANDLE_T handle, unsigned int start)
{
	unsigned int last_off, off;
	STRUCT_ENTRY *e;

	last_off = start;
	e = get_entry(handle, start);

	/* Terminate when we meet a error label or a hook entry. */
	for (off = start + e->next_offset;
	     off < handle->entries.size;
	     last_off = off, off += e->next_offset) {
		STRUCT_ENTRY_TARGET *t;
		unsigned int i;

		e = get_entry(handle, off);

		/* We hit an entry point. */
		for (i = 0; i < NUMHOOKS; i++) {
			if ((handle->info.valid_hooks & (1 << i))
			    && off == handle->info.hook_entry[i])
				return last_off;
		}

		/* We hit a user chain label */
		t = GET_TARGET(e);
		if (strcmp(t->u.user.name, ERROR_TARGET) == 0)
			return last_off;
	}
	/* SHOULD NEVER HAPPEN */
	fprintf(stderr, "ERROR: Off end (%u) of chain from %u!\n",
		handle->entries.size, off);
	abort();
}

/* Iterator functions to run through the chains. */
const char *
TC_FIRST_CHAIN(TC_HANDLE_T *handle)
{
	if ((*handle)->cache_chain_heads == NULL
	    && !populate_cache(*handle))
		return NULL;

	(*handle)->cache_chain_iteration
		= &(*handle)->cache_chain_heads[0];

	return (*handle)->cache_chain_iteration->name;
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
const char *
TC_NEXT_CHAIN(TC_HANDLE_T *handle)
{
	(*handle)->cache_chain_iteration++;

	if ((*handle)->cache_chain_iteration - (*handle)->cache_chain_heads
	    == (*handle)->cache_num_chains)
		return NULL;

	return (*handle)->cache_chain_iteration->name;
}

/* Get first rule in the given chain: NULL for empty chain. */
const STRUCT_ENTRY *
TC_FIRST_RULE(const char *chain, TC_HANDLE_T *handle)
{
	struct chain_cache *c;

	c = find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return NULL;
	}

	/* Empty chain: single return/policy rule */
	if (c->start == c->end)
		return NULL;

	(*handle)->cache_rule_end = c->end;
	return c->start;
}

/* Returns NULL when rules run out. */
const STRUCT_ENTRY *
TC_NEXT_RULE(const STRUCT_ENTRY *prev, TC_HANDLE_T *handle)
{
	if ((void *)prev + prev->next_offset
	    == (void *)(*handle)->cache_rule_end)
		return NULL;

	return (void *)prev + prev->next_offset;
}

#if 0
/* How many rules in this chain? */
unsigned int
TC_NUM_RULES(const char *chain, TC_HANDLE_T *handle)
{
	unsigned int off = 0;
	STRUCT_ENTRY *start, *end;

	CHECK(*handle);
	if (!find_label(&off, chain, *handle)) {
		errno = ENOENT;
		return (unsigned int)-1;
	}

	start = get_entry(*handle, off);
	end = get_entry(*handle, get_chain_end(*handle, off));

	return entry2index(*handle, end) - entry2index(*handle, start);
}

/* Get n'th rule in this chain. */
const STRUCT_ENTRY *TC_GET_RULE(const char *chain,
				unsigned int n,
				TC_HANDLE_T *handle)
{
	unsigned int pos = 0, chainindex;

	CHECK(*handle);
	if (!find_label(&pos, chain, *handle)) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, get_entry(*handle, pos));

	return index2entry(*handle, chainindex + n);
}
#endif

static const char *
target_name(TC_HANDLE_T handle, const STRUCT_ENTRY *ce)
{
	int spos;
	unsigned int labelidx;
	STRUCT_ENTRY *jumpto;

	/* To avoid const warnings */
	STRUCT_ENTRY *e = (STRUCT_ENTRY *)ce;

	if (strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET) != 0)
		return GET_TARGET(e)->u.user.name;

	/* Standard target: evaluate */
	spos = *(int *)GET_TARGET(e)->data;
	if (spos < 0) {
		if (spos == RETURN)
			return LABEL_RETURN;
		else if (spos == -NF_ACCEPT-1)
			return LABEL_ACCEPT;
		else if (spos == -NF_DROP-1)
			return LABEL_DROP;
		else if (spos == -NF_QUEUE-1)
			return LABEL_QUEUE;

		fprintf(stderr, "ERROR: off %lu/%u not a valid target (%i)\n",
			entry2offset(handle, e), handle->entries.size,
			spos);
		abort();
	}

	jumpto = get_entry(handle, spos);

	/* Fall through rule */
	if (jumpto == (void *)e + e->next_offset)
		return "";

	/* Must point to head of a chain: ie. after error rule */
	labelidx = entry2index(handle, jumpto) - 1;
	return get_errorlabel(handle, index2offset(handle, labelidx));
}

/* Returns a pointer to the target name of this position. */
const char *TC_GET_TARGET(const STRUCT_ENTRY *e,
			  TC_HANDLE_T *handle)
{
	return target_name(*handle, e);
}

/* Is this a built-in chain?  Actually returns hook + 1. */
int
TC_BUILTIN(const char *chain, const TC_HANDLE_T handle)
{
	unsigned int i;

	for (i = 0; i < NUMHOOKS; i++) {
		if ((handle->info.valid_hooks & (1 << i))
		    && handle->hooknames[i]
		    && strcmp(handle->hooknames[i], chain) == 0)
			return i+1;
	}
	return 0;
}

/* Get the policy of a given built-in chain */
const char *
TC_GET_POLICY(const char *chain,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	unsigned int start;
	STRUCT_ENTRY *e;
	int hook;

	hook = TC_BUILTIN(chain, *handle);
	if (hook != 0)
		start = (*handle)->info.hook_entry[hook-1];
	else
		return NULL;

	e = get_entry(*handle, get_chain_end(*handle, start));
	*counters = e->counters;

	return target_name(*handle, e);
}

static int
correct_verdict(STRUCT_ENTRY *e,
		char *base,
		unsigned int offset, int delta_offset)
{
	STRUCT_STANDARD_TARGET *t = (void *)GET_TARGET(e);
	unsigned int curr = (char *)e - base;

	/* Trap: insert of fall-through rule.  Don't change fall-through
	   verdict to jump-over-next-rule. */
	if (strcmp(t->target.u.user.name, STANDARD_TARGET) == 0
	    && t->verdict > (int)offset
	    && !(curr == offset &&
		 t->verdict == curr + e->next_offset)) {
		t->verdict += delta_offset;
	}

	return 0;
}

/* Adjusts standard verdict jump positions after an insertion/deletion. */
static int
set_verdict(unsigned int offset, int delta_offset, TC_HANDLE_T *handle)
{
	ENTRY_ITERATE((*handle)->entries.entrytable,
		      (*handle)->entries.size,
		      correct_verdict, (char *)(*handle)->entries.entrytable,
		      offset, delta_offset);

	set_changed(*handle);
	return 1;
}


/* If prepend is set, then we are prepending to a chain: if the
 * insertion position is an entry point, keep the entry point. */
static int
insert_rules(unsigned int num_rules, unsigned int rules_size,
	     const STRUCT_ENTRY *insert,
	     unsigned int offset, unsigned int num_rules_offset,
	     int prepend,
	     TC_HANDLE_T *handle)
{
	TC_HANDLE_T newh;
	STRUCT_GETINFO newinfo;
	unsigned int i;

	if (offset >= (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	newinfo = (*handle)->info;

	/* Fix up entry points. */
	for (i = 0; i < NUMHOOKS; i++) {
		/* Entry points to START of chain, so keep same if
                   inserting on at that point. */
		if ((*handle)->info.hook_entry[i] > offset)
			newinfo.hook_entry[i] += rules_size;

		/* Underflow always points to END of chain (policy),
		   so if something is inserted at same point, it
		   should be advanced. */
		if ((*handle)->info.underflow[i] >= offset)
			newinfo.underflow[i] += rules_size;
	}

	newh = alloc_handle((*handle)->info.name,
			    (*handle)->entries.size + rules_size,
			    (*handle)->new_number + num_rules);
	if (!newh)
		return 0;
	newh->info = newinfo;

	/* Copy pre... */
	memcpy(newh->entries.entrytable, (*handle)->entries.entrytable,offset);
	/* ... Insert new ... */
	memcpy((char *)newh->entries.entrytable + offset, insert, rules_size);
	/* ... copy post */
	memcpy((char *)newh->entries.entrytable + offset + rules_size,
	       (char *)(*handle)->entries.entrytable + offset,
	       (*handle)->entries.size - offset);

	/* Move counter map. */
	/* Copy pre... */
	memcpy(newh->counter_map, (*handle)->counter_map,
	       sizeof(struct counter_map) * num_rules_offset);
	/* ... copy post */
	memcpy(newh->counter_map + num_rules_offset + num_rules,
	       (*handle)->counter_map + num_rules_offset,
	       sizeof(struct counter_map) * ((*handle)->new_number
					     - num_rules_offset));
	/* Set intermediates to no counter copy */
	for (i = 0; i < num_rules; i++)
		newh->counter_map[num_rules_offset+i]
			= ((struct counter_map){ COUNTER_MAP_SET, 0 });

	newh->new_number = (*handle)->new_number + num_rules;
	newh->entries.size = (*handle)->entries.size + rules_size;
	newh->hooknames = (*handle)->hooknames;

	if ((*handle)->cache_chain_heads)
		free((*handle)->cache_chain_heads);
	free(*handle);
	*handle = newh;

	return set_verdict(offset, rules_size, handle);
}

static int
insert_gemdb(struct gem_head *gemdb, unsigned int gemsize, 
	     TC_HANDLE_T *handle)
{
	TC_HANDLE_T newh;

	printf("Allocating mem for all: %u+(gem) %u\n",(*handle)->entries.size,sizeof(struct gem_head) + gemsize);
	/* allocate enought memory for rules and gemdb */
	newh = alloc_handle((*handle)->info.name,
			    (*handle)->entries.size + sizeof(struct gem_head) + gemsize,
			    (*handle)->new_number);
	if (!newh)
		return 0;
	newh->info = (*handle)->info;

	/* Copy rules */
	memcpy(newh->entries.entrytable, (*handle)->entries.entrytable, (*handle)->entries.size);
	/* Copy gemdb head */
	memcpy((char *)newh->entries.entrytable + (*handle)->entries.size, 
	       gemdb, sizeof(struct gem_head));
	/* Copy gemdb structure */
	memcpy((char *)newh->entries.entrytable + (*handle)->entries.size + sizeof(struct gem_head),
	       (char *)gemdb + sizeof(struct gem_head), gemsize);

	/* Move counter map. */
	/* Copy */
	memcpy(newh->counter_map, (*handle)->counter_map,
	       sizeof(struct counter_map) * (*handle)->new_number);

	newh->new_number = (*handle)->new_number;
	newh->entries.size = (*handle)->entries.size;
	newh->hooknames = (*handle)->hooknames;
	newh->gemdb = (*handle)->gemdb;
	newh->gemsize = gemsize;
	
	if ((*handle)->cache_chain_heads)
		free((*handle)->cache_chain_heads);
	free(*handle);
	*handle = newh;
	
	return 1;
}

static int
delete_rules(unsigned int num_rules, unsigned int rules_size,
	     unsigned int offset, unsigned int num_rules_offset,
	     TC_HANDLE_T *handle)
{
	unsigned int i;

	if (offset + rules_size > (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	/* Fix up entry points. */
	for (i = 0; i < NUMHOOKS; i++) {
		/* In practice, we never delete up to a hook entry,
		   since the built-in chains are always first,
		   so these two are never equal */
		if ((*handle)->info.hook_entry[i] >= offset + rules_size)
			(*handle)->info.hook_entry[i] -= rules_size;
		else if ((*handle)->info.hook_entry[i] > offset) {
			fprintf(stderr, "ERROR: Deleting entry %u %u %u\n",
				i, (*handle)->info.hook_entry[i], offset);
			abort();
		}

		/* Underflow points to policy (terminal) rule in
                   built-in, so sequality is valid here (when deleting
                   the last rule). */
		if ((*handle)->info.underflow[i] >= offset + rules_size)
			(*handle)->info.underflow[i] -= rules_size;
		else if ((*handle)->info.underflow[i] > offset) {
			fprintf(stderr, "ERROR: Deleting uflow %u %u %u\n",
				i, (*handle)->info.underflow[i], offset);
			abort();
		}
	}

	/* Move the rules down. */
	memmove((char *)(*handle)->entries.entrytable + offset,
		(char *)(*handle)->entries.entrytable + offset + rules_size,
		(*handle)->entries.size - (offset + rules_size));

	/* Move the counter map down. */
	memmove(&(*handle)->counter_map[num_rules_offset],
		&(*handle)->counter_map[num_rules_offset + num_rules],
		sizeof(struct counter_map)
		* ((*handle)->new_number - (num_rules + num_rules_offset)));

	/* Fix numbers */
	(*handle)->new_number -= num_rules;
	(*handle)->entries.size -= rules_size;

	return set_verdict(offset, -(int)rules_size, handle);
}

static int
standard_map(STRUCT_ENTRY *e, int verdict)
{
	STRUCT_STANDARD_TARGET *t;

	t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

	if (t->target.u.target_size
	    != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) {
		errno = EINVAL;
		return 0;
	}
	/* memset for memcmp convenience on delete/replace */
	memset(t->target.u.user.name, 0, FUNCTION_MAXNAMELEN);
	strcpy(t->target.u.user.name, STANDARD_TARGET);
	t->verdict = verdict;

	return 1;
}

static int
map_target(const TC_HANDLE_T handle,
	   STRUCT_ENTRY *e,
	   unsigned int offset,
	   STRUCT_ENTRY_TARGET *old)
{
	STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*old = *t;

	/* Maybe it's empty (=> fall through) */
	if (strcmp(t->u.user.name, "") == 0)
		return standard_map(e, offset + e->next_offset);
	/* Maybe it's a standard target name... */
	else if (strcmp(t->u.user.name, LABEL_ACCEPT) == 0)
		return standard_map(e, -NF_ACCEPT - 1);
	else if (strcmp(t->u.user.name, LABEL_DROP) == 0)
		return standard_map(e, -NF_DROP - 1);
	else if (strcmp(t->u.user.name, LABEL_QUEUE) == 0)
		return standard_map(e, -NF_QUEUE - 1);
	else if (strcmp(t->u.user.name, LABEL_RETURN) == 0)
		return standard_map(e, RETURN);
	else if (TC_BUILTIN(t->u.user.name, handle)) {
		/* Can't jump to builtins. */
		errno = EINVAL;
		return 0;
	} else {
		/* Maybe it's an existing chain name. */
		struct chain_cache *c;

		c = find_label(t->u.user.name, handle);
		if (c)
			return standard_map(e, entry2offset(handle, c->start));
	}

	/* Must be a module?  If not, kernel will reject... */
	/* memset to all 0 for your memcmp convenience. */
	memset(t->u.user.name + strlen(t->u.user.name),
	       0,
	       FUNCTION_MAXNAMELEN - strlen(t->u.user.name));
	return 1;
}

static void
unmap_target(STRUCT_ENTRY *e, STRUCT_ENTRY_TARGET *old)
{
	STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*t = *old;
}

/* Insert the entry `fw' in chain `chain' into position `rulenum'. */
int
TC_INSERT_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	unsigned int chainindex, offset;
	STRUCT_ENTRY_TARGET old;
	struct chain_cache *c;
	STRUCT_ENTRY *tmp;
	int ret;

	iptc_fn = TC_INSERT_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);

	tmp = index2entry(*handle, chainindex + rulenum);
	if (!tmp || tmp > c->end) {
		errno = E2BIG;
		return 0;
	}
	offset = index2offset(*handle, chainindex + rulenum);

	/* Mapping target actually alters entry, but that's
           transparent to the caller. */
	if (!map_target(*handle, (STRUCT_ENTRY *)e, offset, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, rulenum == 0, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

/* Atomically replace rule `rulenum' in `chain' with `fw'. */
int
TC_REPLACE_ENTRY(const IPT_CHAINLABEL chain,
		 const STRUCT_ENTRY *e,
		 unsigned int rulenum,
		 TC_HANDLE_T *handle)
{
	unsigned int chainindex, offset;
	STRUCT_ENTRY_TARGET old;
	struct chain_cache *c;
	STRUCT_ENTRY *tmp;
	int ret;

	iptc_fn = TC_REPLACE_ENTRY;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);

	tmp = index2entry(*handle, chainindex + rulenum);
	if (!tmp || tmp >= c->end) {
		errno = E2BIG;
		return 0;
	}

	offset = index2offset(*handle, chainindex + rulenum);
	/* Replace = delete and insert. */
	if (!delete_rules(1, get_entry(*handle, offset)->next_offset,
			  offset, chainindex + rulenum, handle))
		return 0;

	if (!map_target(*handle, (STRUCT_ENTRY *)e, offset, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, 1, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int
TC_APPEND_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		TC_HANDLE_T *handle)
{
	struct chain_cache *c;
	STRUCT_ENTRY_TARGET old;
	int ret;

	iptc_fn = TC_APPEND_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (!map_target(*handle, (STRUCT_ENTRY *)e,
			entry2offset(*handle, c->end), &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e,
			   entry2offset(*handle, c->end),
			   entry2index(*handle, c->end),
			   0, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

static inline int
match_different(const STRUCT_ENTRY_MATCH *a,
		const unsigned char *a_elems,
		const unsigned char *b_elems,
		unsigned char **maskptr)
{
	const STRUCT_ENTRY_MATCH *b;
	unsigned int i;

	/* Offset of b is the same as a. */
	b = (void *)b_elems + ((unsigned char *)a - a_elems);

	if (a->u.match_size != b->u.match_size)
		return 1;

	if (strcmp(a->u.user.name, b->u.user.name) != 0)
		return 1;

	*maskptr += ALIGN(sizeof(*a));

	for (i = 0; i < a->u.match_size - ALIGN(sizeof(*a)); i++)
		if (((a->data[i] ^ b->data[i]) & (*maskptr)[i]) != 0)
			return 1;
	*maskptr += i;
	return 0;
}

static inline int
target_different(const unsigned char *a_targdata,
		 const unsigned char *b_targdata,
		 unsigned int tdatasize,
		 const unsigned char *mask)
{
	unsigned int i;
	for (i = 0; i < tdatasize; i++)
		if (((a_targdata[i] ^ b_targdata[i]) & mask[i]) != 0)
			return 1;

	return 0;
}

static int
is_same(const STRUCT_ENTRY *a,
	const STRUCT_ENTRY *b,
	unsigned char *matchmask);

/* Delete the first rule in `chain' which matches `fw'. */
int
TC_DELETE_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *origfw,
		unsigned char *matchmask,
		TC_HANDLE_T *handle)
{
	unsigned int offset;
	struct chain_cache *c;
	STRUCT_ENTRY *e, *fw;

	iptc_fn = TC_DELETE_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	fw = malloc(origfw->next_offset);
	if (fw == NULL) {
		errno = ENOMEM;
		return 0;
	}

	for (offset = entry2offset(*handle, c->start);
	     offset < entry2offset(*handle, c->end);
	     offset += e->next_offset) {
		STRUCT_ENTRY_TARGET discard;

		memcpy(fw, origfw, origfw->next_offset);

		/* FIXME: handle this in is_same --RR */
		if (!map_target(*handle, fw, offset, &discard)) {
			free(fw);
			return 0;
		}
		e = get_entry(*handle, offset);

#if 0
		printf("Deleting:\n");
		dump_entry(newe);
#endif
		if (is_same(e, fw, matchmask)) {
			int ret;
			ret = delete_rules(1, e->next_offset,
					   offset, entry2index(*handle, e),
					   handle);
			free(fw);
			return ret;
		}
	}

	free(fw);
	errno = ENOENT;
	return 0;
}

/* Delete the rule in position `rulenum' in `chain'. */
int
TC_DELETE_NUM_ENTRY(const IPT_CHAINLABEL chain,
		    unsigned int rulenum,
		    TC_HANDLE_T *handle)
{
	unsigned int index;
	int ret;
	STRUCT_ENTRY *e;
	struct chain_cache *c;

	iptc_fn = TC_DELETE_NUM_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	index = entry2index(*handle, c->start) + rulenum;

	if (index >= entry2index(*handle, c->end)) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, index);
	if (e == NULL) {
		errno = EINVAL;
		return 0;
	}

	ret = delete_rules(1, e->next_offset, entry2offset(*handle, e),
			   index, handle);
	return ret;
}

/* Check the packet `fw' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
const char *
TC_CHECK_PACKET(const IPT_CHAINLABEL chain,
		STRUCT_ENTRY *entry,
		TC_HANDLE_T *handle)
{
	errno = ENOSYS;
	return NULL;
}

/* Flushes the entries in the given chain (ie. empties chain). */
int
TC_FLUSH_ENTRIES(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int startindex, endindex;
	struct chain_cache *c;
	int ret;

	iptc_fn = TC_FLUSH_ENTRIES;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}
	startindex = entry2index(*handle, c->start);
	endindex = entry2index(*handle, c->end);

	ret = delete_rules(endindex - startindex,
			   (char *)c->end - (char *)c->start,
			   entry2offset(*handle, c->start), startindex,
			   handle);
	return ret;
}

void level_decode(unsigned int order, int *level, unsigned int *level_max)
{

	/* create number that encode level structure order */
	level[0] = order / 1000 ; 
	order -= level[0]*1000;
	if(level[0]<2) level_max[0] = 0xffffffff;
	else level_max[0] = 0xffff;
	level[1] = order / 100 ; 
	order -= level[1]*100;
	if(level[1]<2) level_max[1] = 0xffffffff;
	else level_max[1] = 0xffff;
	level[2] = order / 10 ; 
	order -= level[2]*10;
	if(level[2]<2) level_max[2] = 0xffffffff;
	else level_max[2] = 0xffff;
	level[3] = order; 
	if(level[3]<2) level_max[3] = 0xffffffff;
	else level_max[3] = 0xffff;
}

/* --------------------------------------------------------------------------------
                   compare function for QUICKSORT
   ----------------------------------------------------------------------------- */
int compare_values( const void *arg1, const void *arg2 )
{
	if(*(unsigned int *)arg1 > *(unsigned int *)arg2)
		return 1;
	else if(*(unsigned int *)arg1 == *(unsigned int *)arg2) 
		return 0;
	else
		return -1;
}


/* --------------------------------------------------------------------------------
      create list of filters that overlap range [l_border, r_border)
      return:          number of overlaping filters
      indirect return: list of overlaping filters (new_list)
   ----------------------------------------------------------------------------- */
unsigned int make_filters_list(int level, unsigned int max_value, struct _filter *FILTERS,
					   unsigned int *current_list, unsigned int list_count, unsigned int *new_list,
					   unsigned int l_border,unsigned int r_border )
{
unsigned int i,new_list_count;

	new_list_count = 0;
	for(i=0; i<=list_count-1; i++) /* for each filter */
	{
		if (  (FILTERS[current_list[i]].l_item[level] <= l_border) && 
			  ( ( (r_border==0) &&  /* max_value instead of r_value */
				  (FILTERS[current_list[i]].r_item[level] == max_value) ) || 
				(FILTERS[current_list[i]].r_item[level] >= r_border-1) )  )
			/* add filter to new list */
			new_list[new_list_count++] = current_list[i];
	}
	return new_list_count;
}


/* --------------------------------------------------------------------------------
      create list of different range border values
      return:          number of different values
      indirect return: list of different values (dif_values_array)
   ------------------------------------------------------------------------------ */
unsigned int c_dif_level_values(int level, unsigned int max_value, struct _filter *FILTERS,
						unsigned int *current_list, unsigned int list_count, unsigned int *dif_values_array )
{
	unsigned int  dif_values_tmp[MAX_FILTER_NUM*2];
	unsigned int  dif_values_num;
	unsigned int  i             ;

	/*  create temp array of all l_item and r_item+1 values */

	for(i=0; i<list_count; i++)
	{
		dif_values_tmp[2*i]   = FILTERS[current_list[i]].l_item[level];
		if(FILTERS[current_list[i]].r_item[level] == max_value)
			dif_values_tmp[2*i+1] = 0;
		else
			dif_values_tmp[2*i+1] = FILTERS[current_list[i]].r_item[level]+1;
	}

	/*  sort values in temp array */
	qsort((void *)dif_values_tmp, (list_count)*2,sizeof(unsigned int), compare_values);

	/*  count different values in temp array */
	dif_values_num = 1;
	for(i=1; i<2*list_count; i++)
	{
		if (dif_values_tmp[i] != dif_values_tmp[i-1]) dif_values_num++;
	}

	/*  create array of different values */

	dif_values_array[0] = dif_values_tmp[0];
	dif_values_num = 1;
	for(i=1; i<2*list_count; i++)
	{
		if( dif_values_tmp[i] != dif_values_array[dif_values_num-1] ) 
		{
			dif_values_array[dif_values_num++] = dif_values_tmp[i];
		}
	}

	return dif_values_num;
}

/* --------------------------------------------------------------------------------
      optimize last level of search database
      return:          pointer to new serch database
      indirect return: size of new database
   ----------------------------------------------------------------------------- */
struct gem_level *optimize_last_level(struct gem_level *tmp_db3,
									  struct gem_level *tmp_opt,
									  unsigned int num_dif_values4,
									  unsigned int *optimize_count )
{
struct gem_level *OPT_LEVELS;
long newsize;
long i;

	/* optimize blocks */
	tmp_opt[0].lower_border = tmp_db3[0].lower_border;
	tmp_opt[0].nextlevel = tmp_db3[0].nextlevel;
	newsize=1;
	if( num_dif_values4 > 1)
		for(i=1; i<=num_dif_values4-1; i++) 
		{
			if( tmp_db3[i].nextlevel != tmp_opt[newsize-1].nextlevel )
			{
				tmp_opt[newsize].lower_border = tmp_db3[i].lower_border;
				tmp_opt[newsize].nextlevel = tmp_db3[i].nextlevel;
				newsize++;
			}
		}
	/* allocate real last level memory block */
	OPT_LEVELS = (struct gem_level *) malloc ( sizeof(struct gem_level)*newsize );

	for(i=0; i<newsize; i++)
	{
		OPT_LEVELS[i].lower_border = tmp_opt[i].lower_border;
		OPT_LEVELS[i].nextlevel = tmp_opt[i].nextlevel;
	}

	*optimize_count = newsize;


	return ((struct gem_level *)OPT_LEVELS);

}

/* --------------------------------------------------------------------------------
      estimate size of GEM data structure
      return:  size 
   ------------------------------------------------------------------------------ */
unsigned int gem_size_estimate(	struct _filter *FILTERS, 
						struct gem_head *gem, unsigned int filters_num )
{

	struct gem_level *tmp_level; 
	struct gem_level *tmp_db3, *tmp_opt;

	unsigned int  num_dif_values1, num_dif_values2;
	unsigned int  num_dif_values3, num_dif_values4;
	unsigned int *dif_values1, *dif_values2;
	unsigned int *dif_values3, *dif_values4;

	unsigned int filter_list[MAX_FILTER_NUM];

	unsigned int new_list1[MAX_FILTER_NUM], new_list2[MAX_FILTER_NUM]; 
	unsigned int new_list3[MAX_FILTER_NUM], new_list4[MAX_FILTER_NUM];
	unsigned int new_list1_count, new_list2_count;
	unsigned int new_list3_count, new_list4_count;

	unsigned int optimize_count;

	unsigned int i,i1,i2,i3,i4;

	unsigned int counter; 
	
	counter = 0;
	
	for(i=0; i<filters_num;i++)
	{
		if( FILTERS[i].protocol == 6 || FILTERS[i].protocol == 0)
			filter_list[counter++] = i;
	}
	
	counter = 0;

	/* allocate reusable memory */
	dif_values1 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values2 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values3 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values4 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );

	tmp_db3 = (struct gem_level *) malloc ( sizeof(struct gem_level)*filters_num*2 );
	tmp_opt = (struct gem_level *) malloc ( sizeof(struct gem_level)*filters_num*2 );

    fprintf(stdout, "start counting....");
	/* ====================== FIRST LEVEL ====================== */
	/*     create list of first level different range values     */
  	num_dif_values1 = c_dif_level_values(gem->levels[0],gem->levelmax[0], FILTERS, filter_list,
		                                 filters_num, dif_values1);
	/* ------------------counters------------- */
	counter += sizeof(struct gem_level)*num_dif_values1;
	/* --------------------------------------- */

	/* for each border value of first level */
	for(i1=0;i1<num_dif_values1;i1++) 
	{
		/* create list of overlaping filters */
		if(i1<num_dif_values1-1)   
			new_list1_count = make_filters_list(gem->levels[0], gem->levelmax[0], FILTERS, filter_list, 
			                              filters_num, new_list1, dif_values1[i1],dif_values1[i1+1]);
		else
			new_list1_count = make_filters_list(gem->levels[0], gem->levelmax[0], FILTERS, filter_list, 
			                              filters_num, new_list1, dif_values1[i1],0x00000000);

		/* ====================== SECOND LEVEL ========================== */
		/*      create list of second level different range values        */
	  	num_dif_values2 = c_dif_level_values(gem->levels[1],gem->levelmax[1], FILTERS, 
			                                 new_list1,new_list1_count, dif_values2);
		
		/* --------------- counters -------------- */
		counter += sizeof(struct gem_level)*num_dif_values2;
		/* --------------------------------------- */
		for(i2=0;i2<num_dif_values2;i2++) 
		{
			if(i2<num_dif_values2-1)   
				new_list2_count = make_filters_list(gem->levels[1], gem->levelmax[1], FILTERS, new_list1, 
										  new_list1_count, new_list2, dif_values2[i2],dif_values2[i2+1]);
			else
				new_list2_count = make_filters_list(gem->levels[1], gem->levelmax[1], FILTERS, new_list1, 
										  new_list1_count, new_list2, dif_values2[i2],0x00000000);

			/* ====================== THIRD LEVEL ====================== */
			/*     create list of third level different range values     */
	  		num_dif_values3 = c_dif_level_values(gem->levels[2],gem->levelmax[2], FILTERS, 
												 new_list2, new_list2_count, dif_values3);

			/* --------------- counters -------------- */
			counter  += sizeof(struct gem_level)*num_dif_values3;
			/* --------------------------------------- */
			for(i3=0;i3<num_dif_values3;i3++) 
			{
				if(i3<num_dif_values3-1)   
					new_list3_count = make_filters_list(gem->levels[2], gem->levelmax[2], FILTERS, new_list2, 
											  new_list2_count, new_list3, dif_values3[i3],dif_values3[i3+1]);
				else
					new_list3_count = make_filters_list(gem->levels[2], gem->levelmax[2], FILTERS, new_list2, 
											  new_list2_count, new_list3, dif_values3[i3],0x00000000);

				/* ====================== FORTH LEVEL ====================== */
				/*     create list of forth level different range values     */
	  			num_dif_values4 = c_dif_level_values(gem->levels[3],gem->levelmax[3], FILTERS, 
													 new_list3, new_list3_count, dif_values4);

				/*              create forth level database               */
				/* find policy for maximum priority filter for each block */
				for(i4=0;i4<num_dif_values4;i4++)
				{

					if(i4<num_dif_values4-1)   
						new_list4_count = make_filters_list(gem->levels[3], gem->levelmax[3], FILTERS, new_list3, 
												  new_list3_count, new_list4, dif_values4[i4],dif_values4[i4+1]);
					else {
						new_list4_count = make_filters_list(gem->levels[3], gem->levelmax[3], FILTERS, new_list3, 
												  new_list3_count, new_list4, dif_values4[i4],0x00000000);
					}
 					
					/* new_list4[0] is best ! (by building style) */
					tmp_db3[i4].lower_border = dif_values4[i4];
					tmp_db3[i4].nextlevel = FILTERS[new_list4[0]].priority;

				}
				
				/*            update link from third level to optimized forth level              */
				/* ------------------------- OPTIMIZE FORTH LEVEL ------------------------------ */
				tmp_level = optimize_last_level(tmp_db3, tmp_opt, num_dif_values4, &optimize_count);

				/* ------------------counters-------------- */
				counter  += sizeof(struct gem_level)*optimize_count;
				/* ---------------------------------------- */
				
			}

		}

	}

    fprintf(stdout, "end counting : size = %u\n",counter);

	free(dif_values1); 
	free(dif_values2); 
	free(dif_values3); 
	free(dif_values4); 
	free(tmp_db3);
	free(tmp_opt);


	return counter;
}


/* --------------------------------------------------------------------------------
      create search database and write it to file
      return:   pointer to search database 
   ----------------------------------------------------------------------------- */
struct gem_head *create_srch_db(	struct _filter *FILTERS, 
						struct gem_head *gem, unsigned int filters_num )
{
	struct gem_head  *SRCH_DB;
	struct gem_level *tmp_db1, *tmp_db2;
	struct gem_level *tmp_db3, *tmp_opt;
	struct gem_level *tmp_last;
	char *GEM_head;
	char *GEM_ptr;

	unsigned int num_dif_values1, num_dif_values2;
	unsigned int num_dif_values3, num_dif_values4;
	unsigned int *dif_values1, *dif_values2;
	unsigned int *dif_values3, *dif_values4;

	unsigned int filter_list[MAX_FILTER_NUM];

	unsigned int new_list[4][MAX_FILTER_NUM];

	unsigned int new_list1_count, new_list2_count;
	unsigned int new_list3_count, new_list4_count;

	unsigned int optimize_count;

	unsigned int i,i1,i2,i3,i4;

	unsigned int counter1; 
   
    fprintf(stdout, "start building...%u rules...",filters_num);

	counter1 = 0;

	GEM_head = (char *) malloc (sizeof(struct gem_head) + gem->size);

	/* create head structure */
	SRCH_DB = (struct gem_head *)GEM_head;
	memcpy(SRCH_DB, gem, sizeof(struct gem_head));
	GEM_ptr = (char *)SRCH_DB->level;

	/* initial filter list - only needed protocol */
	for(i=0; i<filters_num;i++)
	{
		if( FILTERS[i].protocol == 6 || FILTERS[i].protocol == 0)
			filter_list[counter1++] = i;
	}
	
	counter1 = 0;
	
	/* allocate reusable memory */
	dif_values1 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values2 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values3 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	dif_values4 = (unsigned int *) malloc ( sizeof(unsigned int)*filters_num*2 );
	tmp_db3 = (struct gem_level *) malloc ( sizeof(struct gem_level)*filters_num*2 );
	tmp_opt = (struct gem_level *) malloc ( sizeof(struct gem_level)*filters_num*2 );


 	/* ====================== FIRST LEVEL ====================== */
	/*     create list of first level different range values     */
  	num_dif_values1 = c_dif_level_values(gem->levels[0],gem->levelmax[0], FILTERS, filter_list,
		                                 filters_num, dif_values1);
	SRCH_DB->levelsize = num_dif_values1;
	(struct gem_level *)GEM_ptr += num_dif_values1;

	/* ------------------counters-------------- */
	counter1 += sizeof(struct gem_level)*num_dif_values1;
	/* ---------------------------------------- */

	printf("     ");

	for(i=0; i<=num_dif_values1-1; i++) /* last number always 0xffffffff */
	{
		(SRCH_DB->level)[i].lower_border = dif_values1[i];
		(SRCH_DB->level)[i].nextlevel = 0;
		(SRCH_DB->level)[i].size = 0;
	}

	for(i1=0;i1<num_dif_values1;i1++) 
	{
		//if(i2<num_dif_values3-1)
		//	printf("%u:%u,%u,%u\n",i1,filters_num,
		//						dif_values1[i1],dif_values1[i1+1]);
		//else
		//	printf("%u:%u,%u,%u\n",i1,filters_num,
		//						dif_values1[i1],0x00000000);			

		if(i1<num_dif_values1-1)   
			new_list1_count = make_filters_list(gem->levels[0], gem->levelmax[0], FILTERS, filter_list, 
			                              filters_num, new_list[0], dif_values1[i1],dif_values1[i1+1]);
		else
			new_list1_count = make_filters_list(gem->levels[0], gem->levelmax[0], FILTERS, filter_list, 
			                              filters_num, new_list[0], dif_values1[i1],0x00000000);

		/* ==== debug print first level value namber */
		printf("\b\b\b\b\b%3d%% ",(int)((float)i1/num_dif_values1*100));

		/* ====================== SECOND LEVEL ========================== */
		/*      create list of second level different range values        */
	  	num_dif_values2 = c_dif_level_values(gem->levels[1],gem->levelmax[1], FILTERS, 
			                                 new_list[0],new_list1_count, dif_values2);

    	tmp_db1 = (struct gem_level *)GEM_ptr;
		(struct gem_level *)GEM_ptr += num_dif_values2;

		/* ------------------counters-------------- */
		counter1 += sizeof(struct gem_level)*num_dif_values2;
		/* ---------------------------------------- */

		for(i=0; i<=num_dif_values2-1; i++) 
		{
			tmp_db1[i].lower_border = dif_values2[i];
			tmp_db1[i].nextlevel = 0;
			tmp_db1[i].size = 0;
		}

		(SRCH_DB->level)[i1].nextlevel = (struct gem_level *)tmp_db1-&(SRCH_DB->level)[i1];
		(SRCH_DB->level)[i1].size = num_dif_values2;

		for(i2=0;i2<num_dif_values2;i2++) 
		{
			//if(i2<num_dif_values3-1)
			//	printf("%u-%u:%u,%u,%u\n",i1,i2,new_list1_count,
			//						dif_values2[i2],dif_values2[i2+1]);
			//else
			//	printf("%u-%u:%u,%u,%u\n",i1,i2,new_list1_count,
			//						dif_values2[i2],0x00000000);			

			if(i2<num_dif_values2-1)   
				new_list2_count = make_filters_list(gem->levels[1], gem->levelmax[1], FILTERS, new_list[0], 
										  new_list1_count, new_list[1], dif_values2[i2],dif_values2[i2+1]);
			else
				new_list2_count = make_filters_list(gem->levels[1], gem->levelmax[1], FILTERS, new_list[0], 
										  new_list1_count, new_list[1], dif_values2[i2],0x00000000);

			/* ====================== THIRD LEVEL ====================== */
			/*     create list of third level different range values     */
	  		num_dif_values3 = c_dif_level_values(gem->levels[2],gem->levelmax[2], FILTERS, 
												 new_list[1], new_list2_count, dif_values3);

	    	tmp_db2 = (struct gem_level *)GEM_ptr;
			(struct gem_level *)GEM_ptr += num_dif_values3;

			/* ------------------counters--------------- */
			counter1  += sizeof(struct gem_level)*num_dif_values3;
			/* ----------------------------------------- */

			for(i=0; i<num_dif_values3; i++) 
			{
				tmp_db2[i].lower_border = dif_values3[i];
				tmp_db2[i].nextlevel = 0;
				tmp_db2[i].size = 0;
			}

			for(i3=0;i3<num_dif_values3;i3++) 
			{
			//if(i3<num_dif_values3-1)
			//	printf("%u-%u-%u:%u,%u,%u\n",i1,i2,i3,new_list2_count,
			//						dif_values3[i3],dif_values3[i3+1]);
			//else
			//	printf("%u-%u-%u:%u,%u,%u\n",i1,i2,i3,new_list2_count,
			//						dif_values3[i3],0x00000000);			
			
				if(i3<num_dif_values3-1)   
					new_list3_count = make_filters_list(gem->levels[2], gem->levelmax[2], FILTERS, new_list[1], 
											  new_list2_count, new_list[2], dif_values3[i3],dif_values3[i3+1]);
				else
					new_list3_count = make_filters_list(gem->levels[2], gem->levelmax[2], FILTERS, new_list[1], 
											  new_list2_count, new_list[2], dif_values3[i3],0x00000000);

				/* ====================== FORTH LEVEL ====================== */
				/*     create list of forth level different range values     */
	  			num_dif_values4 = c_dif_level_values(gem->levels[3],gem->levelmax[3], FILTERS, 
													 new_list[2], new_list3_count, dif_values4);
				
				/*              create forth level database               */
				/* find policy for maximum priority filter for each block */
				for(i4=0;i4<num_dif_values4;i4++)
				{
			/*	if(i4<num_dif_values4-1)
					printf("%u-%u-%u-%u:%u,%u,%u..",i1,i2,i3,i4,new_list3_count,
										dif_values4[i4],dif_values4[i4+1]);
				else
					printf("%u-%u-%u-%u:%u,%u,%u..",i1,i2,i3,i4,new_list3_count,
										dif_values3[i4],0x00000000);			
			*/
					if(i4<num_dif_values4-1)   
						new_list4_count = make_filters_list(gem->levels[3], gem->levelmax[3], FILTERS, new_list[2], 
												  new_list3_count, new_list[3], dif_values4[i4],dif_values4[i4+1]);
					else 
						new_list4_count = make_filters_list(gem->levels[3], gem->levelmax[3], FILTERS, new_list[2], 
												  new_list3_count, new_list[3], dif_values4[i4],0x00000000);

					// new_list4[0] is best ! (by building style)
					tmp_db3[i4].lower_border = dif_values4[i4];
					tmp_db3[i4].nextlevel = FILTERS[new_list[3][0]].priority;
			/*		printf("%u\n",tmp_db3[i4].nextlevel);*/

				}
				
				/*            update link from third level to optimized forth level              */
				/* ------------------------- OPTIMIZE FORTH LEVEL ------------------------------ */
				tmp_last = optimize_last_level(tmp_db3,tmp_opt,num_dif_values4,&optimize_count);
				memcpy(GEM_ptr, tmp_last, sizeof(struct gem_level)*optimize_count); 
				tmp_db2[i3].size = optimize_count;
				tmp_db2[i3].nextlevel = (struct gem_level *)GEM_ptr-(struct gem_level *)&tmp_db2[i3];
				(struct gem_level*)GEM_ptr += optimize_count;
				
				/* ------------------counters-------------- */
				counter1  += sizeof(struct gem_level)*optimize_count;
				/* ---------------------------------------- */
				
			}

			/* update link from second level */
			tmp_db1[i2].nextlevel = tmp_db2-&tmp_db1[i2];
			tmp_db1[i2].size = num_dif_values3;
			
		}

	}

	free(dif_values1); 
	free(dif_values2); 
	free(dif_values3); 
	free(dif_values4); 
	free(tmp_db3);
	free(tmp_opt);

	printf("\b\b\b\b");

    fprintf(stdout, "end building:\nsize = head + body = %u + %u = %u\n",
    		sizeof(struct gem_head),gem->size,sizeof(struct gem_head)+gem->size);

	return SRCH_DB;

}


/* GEM  */
int
iptc_build_gem(const IPT_CHAINLABEL chain,
			TC_HANDLE_T *handle)
{
	struct gem_head gem;
	unsigned int startindex, endindex, i;
	struct chain_cache *c;
	STRUCT_ENTRY *e;
	STRUCT_IPINFO *ipinfo;
	STRUCT_TCPINFO *tcpinfo;
	struct gem_head *gemdb;

	struct _filter FILTERS[MAX_FILTER_NUM];

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}
	
	startindex = entry2index(*handle, c->start);
	endindex = entry2index(*handle, c->end);
	
    fprintf(stdout, "building from rules: %u - %u\n",startindex, endindex);
	
		// initial filter list - only needed protocol
	for(i = 0; i < endindex - startindex; i++)
	{
		e = index2entry( *handle, startindex+i );
		ipinfo = get_ip_info(e);
		if( ipinfo->proto == 6 /*tcp protocol*/ )
		{
		//	printf("SRC:");
			TC_GET_IP_ADDR(ipinfo->src,ipinfo->smsk,&FILTERS[i].l_item[0],&FILTERS[i].r_item[0]);
		//	printf("DST:");
			TC_GET_IP_ADDR(ipinfo->dst,ipinfo->dmsk,&FILTERS[i].l_item[1],&FILTERS[i].r_item[1]);
			tcpinfo = (struct ipt_tcp *)((STRUCT_ENTRY_MATCH*)e->elems)->data;
			FILTERS[i].l_item[2] = tcpinfo->spts[0];
			FILTERS[i].r_item[2] = tcpinfo->spts[1];
			FILTERS[i].l_item[3] = tcpinfo->dpts[0];
			FILTERS[i].r_item[3] = tcpinfo->dpts[1];
			FILTERS[i].protocol = 6; /*TCP*/
			FILTERS[i].policy = e->target_offset;
			FILTERS[i].priority = entry2offset(*handle, e); /*startindex + i*/;
		//	printf("FILTERS: %u-%u,%u-%u,%u-%u,%u-%u, %u\n",
		//		FILTERS[i].l_item[0],FILTERS[i].r_item[0],FILTERS[i].l_item[1],FILTERS[i].r_item[1],
		//		FILTERS[i].l_item[2],FILTERS[i].r_item[2],FILTERS[i].l_item[3],FILTERS[i].r_item[3],
		//		FILTERS[i].priority);
		}
	}
    fprintf(stdout, "FILTERS CREATED\n");

	(*handle)->gemdb = index2offset( *handle, startindex );
	
	gem.order = 3201;
	
	level_decode( gem.order, gem.levels, gem.levelmax );
	
	fprintf(stdout, "Starting size estimate with: %u rules\n", endindex - startindex);
	
	gem.size = gem_size_estimate( FILTERS, &gem, endindex - startindex );
	
	(*handle)->gemsize = gem.size;
	
	gemdb = create_srch_db( FILTERS, &gem, endindex - startindex );
	
	fprintf(stdout, "order = %u,first level size: %u\n",gemdb->order, gemdb->level[0].size);
	insert_gemdb( gemdb, gem.size, handle);
	
	set_changed(*handle);
	
	return 1;
}

/* Zeroes the counters in a chain. */
int
TC_ZERO_ENTRIES(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int i, end;
	struct chain_cache *c;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	i = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	for (; i <= end; i++) {
		if ((*handle)->counter_map[i].maptype ==COUNTER_MAP_NORMAL_MAP)
			(*handle)->counter_map[i].maptype = COUNTER_MAP_ZEROED;
	}
	set_changed(*handle);

	return 1;
}

STRUCT_COUNTERS *
TC_READ_COUNTER(const IPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e;
	struct chain_cache *c;
	unsigned int chainindex, end;

	iptc_fn = TC_READ_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return NULL;
	}

	e = index2entry(*handle, chainindex + rulenum);

	return &e->counters;
}

int
TC_ZERO_COUNTER(const IPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e;
	struct chain_cache *c;
	unsigned int chainindex, end;
	
	iptc_fn = TC_ZERO_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, chainindex + rulenum);

	if ((*handle)->counter_map[chainindex + rulenum].maptype
			== COUNTER_MAP_NORMAL_MAP) {
		(*handle)->counter_map[chainindex + rulenum].maptype
			 = COUNTER_MAP_ZEROED;
	}

	set_changed(*handle);

	return 1;
}

int 
TC_SET_COUNTER(const IPT_CHAINLABEL chain,
	       unsigned int rulenum,
	       STRUCT_COUNTERS *counters,
	       TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e;
	struct chain_cache *c;
	unsigned int chainindex, end;

	iptc_fn = TC_SET_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, chainindex + rulenum);

	(*handle)->counter_map[chainindex + rulenum].maptype
		= COUNTER_MAP_SET;

	memcpy(&e->counters, counters, sizeof(STRUCT_COUNTERS));

	set_changed(*handle);

	return 1;
}

/* Creates a new chain. */
/* To create a chain, create two rules: error node and unconditional
 * return. */
int
TC_CREATE_CHAIN(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	int ret;
	struct {
		STRUCT_ENTRY head;
		struct ipt_error_target name;
		STRUCT_ENTRY ret;
		STRUCT_STANDARD_TARGET target;
	} newc;

	iptc_fn = TC_CREATE_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (find_label(chain, *handle)
	    || strcmp(chain, LABEL_DROP) == 0
	    || strcmp(chain, LABEL_ACCEPT) == 0
	    || strcmp(chain, LABEL_QUEUE) == 0
	    || strcmp(chain, LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (strlen(chain)+1 > sizeof(IPT_CHAINLABEL)) {
		errno = EINVAL;
		return 0;
	}

	memset(&newc, 0, sizeof(newc));
	newc.head.target_offset = sizeof(STRUCT_ENTRY);
	newc.head.next_offset
		= sizeof(STRUCT_ENTRY)
		+ ALIGN(sizeof(struct ipt_error_target));
	strcpy(newc.name.t.u.user.name, ERROR_TARGET);
	newc.name.t.u.target_size = ALIGN(sizeof(struct ipt_error_target));
	strcpy(newc.name.error, chain);

	newc.ret.target_offset = sizeof(STRUCT_ENTRY);
	newc.ret.next_offset
		= sizeof(STRUCT_ENTRY)
		+ ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	strcpy(newc.target.target.u.user.name, STANDARD_TARGET);
	newc.target.target.u.target_size
		= ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	newc.target.verdict = RETURN;

	/* Add just before terminal entry */
	ret = insert_rules(2, sizeof(newc), &newc.head,
			   index2offset(*handle, (*handle)->new_number - 1),
			   (*handle)->new_number - 1,
			   0, handle);
	return ret;
}

static int
count_ref(STRUCT_ENTRY *e, unsigned int offset, unsigned int *ref)
{
	STRUCT_STANDARD_TARGET *t;

	if (strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET) == 0) {
		t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

		if (t->verdict == offset)
			(*ref)++;
	}

	return 0;
}

/* Get the number of references to this chain. */
int
TC_GET_REFERENCES(unsigned int *ref, const IPT_CHAINLABEL chain,
		  TC_HANDLE_T *handle)
{
	struct chain_cache *c;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	*ref = 0;
	ENTRY_ITERATE((*handle)->entries.entrytable,
		      (*handle)->entries.size,
		      count_ref, entry2offset(*handle, c->start), ref);
	return 1;
}

/* Deletes a chain. */
int
TC_DELETE_CHAIN(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int labelidx, labeloff;
	unsigned int references;
	struct chain_cache *c;
	int ret;

	if (!TC_GET_REFERENCES(&references, chain, handle))
		return 0;

	iptc_fn = TC_DELETE_CHAIN;

	if (TC_BUILTIN(chain, *handle)) {
		errno = EINVAL;
		return 0;
	}

	if (references > 0) {
		errno = EMLINK;
		return 0;
	}

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if ((void *)c->start != c->end) {
		errno = ENOTEMPTY;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, c->start) - 1;
	labeloff = index2offset(*handle, labelidx);

	ret = delete_rules(2,
			   get_entry(*handle, labeloff)->next_offset
			   + c->start->next_offset,
			   labeloff, labelidx, handle);
	return ret;
}

/* Renames a chain. */
int TC_RENAME_CHAIN(const IPT_CHAINLABEL oldname,
		    const IPT_CHAINLABEL newname,
		    TC_HANDLE_T *handle)
{
	unsigned int labeloff, labelidx;
	struct chain_cache *c;
	struct ipt_error_target *t;

	iptc_fn = TC_RENAME_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (find_label(newname, *handle)
	    || strcmp(newname, LABEL_DROP) == 0
	    || strcmp(newname, LABEL_ACCEPT) == 0
	    || strcmp(newname, LABEL_QUEUE) == 0
	    || strcmp(newname, LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (!(c = find_label(oldname, *handle))
	    || TC_BUILTIN(oldname, *handle)) {
		errno = ENOENT;
		return 0;
	}

	if (strlen(newname)+1 > sizeof(IPT_CHAINLABEL)) {
		errno = EINVAL;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, c->start) - 1;
	labeloff = index2offset(*handle, labelidx);

	t = (struct ipt_error_target *)
		GET_TARGET(get_entry(*handle, labeloff));

	memset(t->error, 0, sizeof(t->error));
	strcpy(t->error, newname);
	set_changed(*handle);

	return 1;
}

/* Sets the policy on a built-in chain. */
int
TC_SET_POLICY(const IPT_CHAINLABEL chain,
	      const IPT_CHAINLABEL policy,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	unsigned int hook;
	unsigned int policyoff, ctrindex;
	STRUCT_ENTRY *e;
	STRUCT_STANDARD_TARGET *t;

	iptc_fn = TC_SET_POLICY;
	/* Figure out which chain. */
	hook = TC_BUILTIN(chain, *handle);
	if (hook == 0) {
		errno = ENOENT;
		return 0;
	} else
		hook--;

	policyoff = get_chain_end(*handle, (*handle)->info.hook_entry[hook]);
	if (policyoff != (*handle)->info.underflow[hook]) {
		printf("ERROR: Policy for `%s' offset %u != underflow %u\n",
		       chain, policyoff, (*handle)->info.underflow[hook]);
		return 0;
	}

	e = get_entry(*handle, policyoff);
	t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

	if (strcmp(policy, LABEL_ACCEPT) == 0)
		t->verdict = -NF_ACCEPT - 1;
	else if (strcmp(policy, LABEL_DROP) == 0)
		t->verdict = -NF_DROP - 1;
	else {
		errno = EINVAL;
		return 0;
	}

	ctrindex = entry2index(*handle, e);

	if (counters) {
		/* set byte and packet counters */
		memcpy(&e->counters, counters, sizeof(STRUCT_COUNTERS));

		(*handle)->counter_map[ctrindex].maptype
			= COUNTER_MAP_SET;

	} else {
		(*handle)->counter_map[ctrindex]
			= ((struct counter_map){ COUNTER_MAP_NOMAP, 0 });
	}

	set_changed(*handle);

	return 1;
}

/* Without this, on gcc 2.7.2.3, we get:
   libiptc.c: In function `TC_COMMIT':
   libiptc.c:833: fixed or forbidden register was spilled.
   This may be due to a compiler bug or to impossible asm
   statements or clauses.
*/
static void
subtract_counters(STRUCT_COUNTERS *answer,
		  const STRUCT_COUNTERS *a,
		  const STRUCT_COUNTERS *b)
{
	answer->pcnt = a->pcnt - b->pcnt;
	answer->bcnt = a->bcnt - b->bcnt;
}

int
TC_COMMIT(TC_HANDLE_T *handle)
{
	/* Replace, then map back the counters. */
	STRUCT_REPLACE *repl;
	/*struct ipt_replace *repl;*/
	STRUCT_COUNTERS_INFO *newcounters;
	unsigned int i;
	unsigned int gemdb_size = 0;
	
	size_t counterlen
		= sizeof(STRUCT_COUNTERS_INFO)
		+ sizeof(STRUCT_COUNTERS) * (*handle)->new_number;

	CHECK(*handle);
#if 0
	TC_DUMP_ENTRIES(*handle);
#endif

	/* Don't commit if nothing changed. */
	if (!(*handle)->changed)
		goto finished;

	if((*handle)->gemsize) gemdb_size = sizeof(struct gem_head) + (*handle)->gemsize;
	repl = malloc(sizeof(*repl) + (*handle)->entries.size + gemdb_size);
	if (!repl) {
		errno = ENOMEM;
		return 0;
	}

	/* These are the old counters we will get from kernel */
	repl->counters = malloc(sizeof(STRUCT_COUNTERS)
				* (*handle)->info.num_entries);
	if (!repl->counters) {
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	/* These are the counters we're going to put back, later. */
	newcounters = malloc(counterlen);
	if (!newcounters) {
		free(repl->counters);
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	strcpy(repl->name, (*handle)->info.name);
	repl->num_entries = (*handle)->new_number;
	repl->size = (*handle)->entries.size;
	memcpy(repl->hook_entry, (*handle)->info.hook_entry,
	       sizeof(repl->hook_entry));
	memcpy(repl->underflow, (*handle)->info.underflow,
	       sizeof(repl->underflow));
		   
	repl->gemdb = (*handle)->gemdb;
	repl->gemsize = (*handle)->gemsize;
	
	repl->num_counters = (*handle)->info.num_entries;
	repl->valid_hooks = (*handle)->info.valid_hooks;
	memcpy(repl->entries, (*handle)->entries.entrytable,
	       (*handle)->entries.size + gemdb_size);

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_REPLACE, repl,
		       sizeof(*repl) + (*handle)->entries.size) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	/* Put counters back. */
	strcpy(newcounters->name, (*handle)->info.name);
	newcounters->num_counters = (*handle)->new_number;
	for (i = 0; i < (*handle)->new_number; i++) {
		unsigned int mappos = (*handle)->counter_map[i].mappos;
		switch ((*handle)->counter_map[i].maptype) {
		case COUNTER_MAP_NOMAP:
			newcounters->counters[i]
				= ((STRUCT_COUNTERS){ 0, 0 });
			break;

		case COUNTER_MAP_NORMAL_MAP:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: X + Y + Z.
			 * => Add in X + Y
			 * => Add in replacement read.
			 */
			newcounters->counters[i] = repl->counters[mappos];
			break;

		case COUNTER_MAP_ZEROED:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: Y + Z.
			 * => Add in Y.
			 * => Add in (replacement read - original read).
			 */
			subtract_counters(&newcounters->counters[i],
					  &repl->counters[mappos],
					  &index2entry(*handle, i)->counters);
			break;

		case COUNTER_MAP_SET:
			/* Want to set counter (iptables-restore) */

			memcpy(&newcounters->counters[i],
			       &index2entry(*handle, i)->counters,
			       sizeof(STRUCT_COUNTERS));

			break;
		}
	}

#ifdef KERNEL_64_USERSPACE_32
	{
		/* Kernel will think that pointer should be 64-bits, and get
		   padding.  So we accomodate here (assumption: alignment of
		   `counters' is on 64-bit boundary). */
		u_int64_t *kernptr = (u_int64_t *)&newcounters->counters;
		if ((unsigned long)&newcounters->counters % 8 != 0) {
			fprintf(stderr,
				"counters alignment incorrect! Mail rusty!\n");
			abort();
		}
		*kernptr = newcounters->counters;
	}
#endif /* KERNEL_64_USERSPACE_32 */

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_ADD_COUNTERS,
		       newcounters, counterlen) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	free(repl->counters);
	free(repl);
	free(newcounters);

 finished:
	if ((*handle)->cache_chain_heads)
		free((*handle)->cache_chain_heads);
	free(*handle);
	*handle = NULL;
	return 1;
}

/* Get raw socket. */
int
TC_GET_RAW_SOCKET()
{
	return sockfd;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *
TC_STRERROR(int err)
{
	unsigned int i;
	struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table [] =
	  { { TC_INIT, EPERM, "Permission denied (you must be root)" },
	    { TC_INIT, EINVAL, "Module is wrong version" },
	    { TC_INIT, ENOENT, 
		    "Table does not exist (do you need to insmod?)" },
	    { TC_DELETE_CHAIN, ENOTEMPTY, "Chain is not empty" },
	    { TC_DELETE_CHAIN, EINVAL, "Can't delete built-in chain" },
	    { TC_DELETE_CHAIN, EMLINK,
	      "Can't delete chain with references left" },
	    { TC_CREATE_CHAIN, EEXIST, "Chain already exists" },
	    { TC_INSERT_ENTRY, E2BIG, "Index of insertion too big" },
	    { TC_REPLACE_ENTRY, E2BIG, "Index of replacement too big" },
	    { TC_DELETE_NUM_ENTRY, E2BIG, "Index of deletion too big" },
	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_INSERT_ENTRY, ELOOP, "Loop found in table" },
	    { TC_INSERT_ENTRY, EINVAL, "Target problem" },
	    /* EINVAL for CHECK probably means bad interface. */
	    { TC_CHECK_PACKET, EINVAL,
	      "Bad arguments (does that interface exist?)" },
	    { TC_CHECK_PACKET, ENOSYS,
	      "Checking will most likely never get implemented" },
	    /* ENOENT for DELETE probably means no matching rule */
	    { TC_DELETE_ENTRY, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { TC_SET_POLICY, ENOENT,
	      "Bad built-in chain name" },
	    { TC_SET_POLICY, EINVAL,
	      "Bad policy name" },

	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == iptc_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
