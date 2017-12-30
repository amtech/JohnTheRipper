/*
 * This software is Copyright (c) 2017 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifdef _OPENMP
#include <omp.h>
#endif

#include "john.h"
#include "options.h"
#include "logger.h"
#include "formats.h"
#include "timer.h"
#include "memdbg.h"

extern volatile int bench_running;

int omp_autotune(struct fmt_main *self)
{
	static int omp_autotune_running;
	int threads = omp_get_max_threads();
	int mkpc = self->params.max_keys_per_crypt * threads;
	int best_scale = 1, scale = 1;
	int best_cps = 0;
	int no_progress = 0;
	char key[] = "testkey0";
	sTimer timer;
	double duration;

	if (omp_autotune_running || threads == 1)
		return threads;

	omp_autotune_running = 1;

	self->params.min_keys_per_crypt *= threads;

	self->methods.set_salt(
		self->methods.salt(self->params.tests[0].ciphertext));

	sTimer_Init(&timer);

	if (john_main_process &&
	    options.verbosity > VERB_DEFAULT && bench_running)
		fprintf(stderr, "\n");

	do {
		int i;
		int this_kpc = mkpc * scale;
		int cps, crypts = 0;

		self->params.max_keys_per_crypt = this_kpc;

		// Set up buffers
		self->methods.init(self);

		// Load keys
		self->methods.clear_keys();
		for (i = 0; i < this_kpc; i++) {
			key[7] = '0' + i % 10;
			self->methods.set_key(key, i);
		}

		// Warm-up run
		{
			int count = this_kpc;

			self->methods.crypt_all(&count, NULL);
		}

		sTimer_Start(&timer, 1);
		do {
			int count = this_kpc;

			self->methods.crypt_all(&count, NULL);
			crypts += count;
		} while (sTimer_GetSecs(&timer) < 0.010);
		sTimer_Stop(&timer);

		// Release buffers
		self->methods.done();

		duration = sTimer_GetSecs(&timer);
		cps = crypts / duration;

		if (john_main_process && options.verbosity == VERB_MAX)
			fprintf(stderr, "scale %d: %d crypts in %f seconds, %d c/s",
			        scale, crypts, duration, (int)(crypts / duration));

		// Example, require 5% boost (because a low KPC has some advantages)
		if (cps >= (best_cps * 1.05)) {
			if (john_main_process && options.verbosity == VERB_MAX)
				fprintf(stderr, " +\n");
			best_cps = cps;
			best_scale = scale;
		}
		else {
			if (john_main_process && options.verbosity == VERB_MAX)
				fprintf(stderr, " -\n");
			no_progress++;
		}

		// Double each time
		scale *= 2;
	} while (duration < 0.1 && no_progress < 3);

	if (john_main_process && options.verbosity > VERB_DEFAULT)
		fprintf(stderr, "Autotune found best speed at OMP scale of %d\n",
		        best_scale);
	log_event("Autotune found best speed at OMP scale of %d", best_scale);

	omp_autotune_running = 0;

	threads *= best_scale;
	self->params.max_keys_per_crypt = mkpc * threads;

	return threads;
}
