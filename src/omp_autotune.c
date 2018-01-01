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

#define SAMPLE_TIME 0.020  /* Seconds to test speed (20 ms) */
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
	void *salt;
	char key[] = "testkey0";
	sTimer timer;
	double duration;

	if (threads == 1 || omp_autotune_running)
		return threads;

	if (!db) {
		fmt = format;
		mkpc = fmt->params.max_keys_per_crypt * threads;
		return threads;
	}

	if (john_main_process &&
	    options.verbosity > VERB_DEFAULT && bench_running)
		fprintf(stderr, "\n");

	omp_autotune_running = 1;
	if (john_main_process && options.verbosity == VERB_MAX)
		fprintf(stderr, "%s OMP autotune using %s db\n",
		        fmt->params.label, db->real ? "real" : "test");


	fmt->params.min_keys_per_crypt *= threads;

	// Find most expensive salt, for auto-tune
	{
		struct db_main *tune_db = db->real ? db->real : db;
		struct db_salt *s = tune_db->salts;

		while (s->next && s->cost[0] < tune_db->max_cost[0])
			s = s->next;
		salt = s->salt;
	}
	fmt->methods.set_salt(salt);

	sTimer_Init(&timer);

	do {
		int i;
		int this_kpc = mkpc * scale;
		int cps, crypts = 0;

		fmt->params.max_keys_per_crypt = this_kpc;

		// Release old buffers
		fmt->methods.done();

		// Set up buffers for this test
		fmt->methods.init(fmt);

		// Load keys
		fmt->methods.clear_keys();
		for (i = 0; i < this_kpc; i++) {
			key[6] = '0' + (i / 10) % 10;
			key[7] = '0' + i % 10;
			fmt->methods.set_key(key, i);
		}

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
			fprintf(stderr, "scale %d: %d crypts in %f seconds, %d c/s",
			        scale, crypts, duration, (int)(crypts / duration));

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

		// Double each time
		scale *= 2;
	} while (duration < MAX_TUNE_TIME && no_progress < MAX_NO_PROGRESS);

	//if (!fmt->methods.tunable_cost_value[0] || !db->real)
	//	dyna_salt_remove(salt);

	if (john_main_process && options.verbosity > VERB_DEFAULT)
		fprintf(stderr, "Autotune found best speed at OMP scale of %d\n",
		        best_scale);
	log_event("Autotune found best speed at OMP scale of %d", best_scale);

	threads *= best_scale;
	fmt->params.max_keys_per_crypt = mkpc * threads;

	// Release old buffers
	fmt->methods.done();

	// Set up buffers for chosen scale
	fmt->methods.init(fmt);

	omp_autotune_running = 0;

	return threads;
}

#endif /* _OPENMP */
