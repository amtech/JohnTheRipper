/*
 * This software is Copyright (c) 2017 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifdef _OPENMP
#include <omp.h>

#include "john.h"
#include "options.h"
#include "logger.h"
#include "formats.h"
#include "timer.h"
#include "memdbg.h"

//#define OMP_DEBUG
#define SAMPLE_TIME 0.010  /* Seconds to test speed (10 ms) */
#define REQ_GAIN 1.05      /* Minimum boost to consider a better scale */
#define MAX_TUNE_TIME 0.1  /* If we're slower than 100 ms, stop here */
#define MAX_NO_PROGRESS 3  /* Don't bother trying higher scale if this many
                              doubles did no good */

extern volatile int bench_running;

int omp_autotune(struct fmt_main *format, struct db_main *db)
{
	static struct fmt_main *fmt;
	static int omp_autotune_running;
	static int mkpc;
	int threads = omp_get_max_threads();
	int best_scale = 1, scale = 1;
	int best_cps = 0;
	int no_progress = 0;
	int min_crypts = 0;
	int tune_cost;
	void *salt;
	char key[] = "tune0000";
	sTimer timer;
	double duration;

	if (omp_autotune_running) {
#ifdef OMP_DEBUG
		if (john_main_process && options.verbosity == VERB_MAX)
			fprintf(stderr, "(kpc %d return %d)\n", fmt->params.max_keys_per_crypt, fmt->params.max_keys_per_crypt / mkpc);
#endif
		return fmt->params.max_keys_per_crypt / mkpc;
	} else if (threads == 1) {
#ifdef OMP_DEBUG
		if (john_main_process && options.verbosity == VERB_MAX)
			fprintf(stderr, "(return 1)\n");
#endif
		return 1;
	}

#ifdef OMP_DEBUG
	if (john_main_process && options.verbosity == VERB_MAX)
		fprintf(stderr, "\nautotune called from %s()\n", format ? "init" : "reset");
#endif

	if (!db) {
		fmt = format;
		mkpc = fmt->params.max_keys_per_crypt;
		fmt->params.min_keys_per_crypt *= threads;
		fmt->params.max_keys_per_crypt *= threads;
#ifdef OMP_DEBUG
		if (john_main_process && options.verbosity == VERB_MAX)
			fprintf(stderr, "%s initial mkpc %d\n", fmt->params.label, mkpc);
#endif
		return threads;
	}

	if (john_main_process &&
	    options.verbosity > VERB_DEFAULT && bench_running)
		fprintf(stderr, "\n");

	omp_autotune_running = 1;

	// Find most expensive salt, for auto-tune
	{
		struct db_main *tune_db = db->real ? db->real : db;
		struct db_salt *s = tune_db->salts;

		tune_cost = MIN(tune_db->max_cost[0], options.loader.max_cost[0]);

		while (s->next && s->cost[0] < tune_cost)
			s = s->next;
		salt = s->salt;
	}

	if (john_main_process && options.verbosity == VERB_MAX)
		fprintf(stderr, "%s OMP autotune using %s db with cost 1 of %d\n",
		        fmt->params.label, db->real ? "real" : "test", tune_cost);

	sTimer_Init(&timer);
	do {
		int i;
		int this_kpc = mkpc * threads * scale;
		int cps, crypts = 0;

		fmt->params.max_keys_per_crypt = this_kpc;

		// Release old buffers
		fmt->methods.done();

		// Set up buffers for this test
		fmt->methods.init(fmt);

		// Load keys
		fmt->methods.clear_keys();
		for (i = 0; i < this_kpc; i++) {
			key[4] = '0' + (i / 1000) % 10;
			key[5] = '0' + (i / 100) % 10;
			key[6] = '0' + (i / 10) % 10;
			key[7] = '0' + i % 10;
			fmt->methods.set_key(key, i);
		}

		fmt->methods.set_salt(salt);

		sTimer_Start(&timer, 1);
		do {
			int count = this_kpc;

			fmt->methods.crypt_all(&count, NULL);
			crypts += count;
		} while (crypts < min_crypts || sTimer_GetSecs(&timer) < SAMPLE_TIME);
		sTimer_Stop(&timer);

		duration = sTimer_GetSecs(&timer);
		cps = crypts / duration;

		if (john_main_process && options.verbosity == VERB_MAX)
			fprintf(stderr, "scale %d: %d (%d) crypts in %f seconds, %d c/s",
			        scale, crypts, this_kpc, duration, (int)(crypts / duration));

		if (cps >= (best_cps * REQ_GAIN)) {
			if (john_main_process && options.verbosity == VERB_MAX)
				fprintf(stderr, " +\n");
			best_cps = cps;
			best_scale = scale;
			no_progress = 0;
		}
		else {
			if (john_main_process && options.verbosity == VERB_MAX)
				fprintf(stderr, "\n");
			no_progress++;
		}

		min_crypts = crypts;

		if (duration > MAX_TUNE_TIME || no_progress > MAX_NO_PROGRESS)
			break;

		// Double each time
		scale *= 2;
	} while (1);

	if (john_main_process && options.verbosity > VERB_DEFAULT)
		fprintf(stderr, "Autotune found best speed at OMP scale of %d\n",
		        best_scale);
	log_event("Autotune found best speed at OMP scale of %d", best_scale);

	fmt->params.max_keys_per_crypt = mkpc * threads * best_scale;

	if (best_scale != scale) {
		// Release old buffers
		fmt->methods.done();

		// Set up buffers for chosen scale
		fmt->methods.init(fmt);
	}

	omp_autotune_running = 0;

#ifdef OMP_DEBUG
	if (john_main_process && options.verbosity == VERB_MAX)
		fprintf(stderr, "autotune return %dx%d=%d\n", threads, best_scale, threads * best_scale);
#endif
	return threads * best_scale;
}

#endif /* _OPENMP */
