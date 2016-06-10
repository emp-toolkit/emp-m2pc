#include <emp-tool/emp-tool.h>
#include "input-validity/iv.h"

double bench_iv(void * f1, void * f2, void* g, uint64_t len1, uint64_t len2, uint64_t len3, NetIO * io, uint64_t TIME, uint64_t party) {
	double t = 0;
	double t1 = wallClock();
	for(uint64_t k = 0; k < TIME; ++k) {
		if (party == ALICE) {
			bool * b = new bool[len1];
			for(uint64_t i = 0; i < len1; ++i)
				b[i] = true;
			io->set_nodelay();
			IV iv(io, party, len1, len2, len3);
			iv.checkf1Alice(b, f1);
			iv.checkf2Alice(f2);
			io->set_delay();
			iv.evalgAlice(g);
			delete []b;
		}
		else {
			bool * b = new bool[len2];
			for(uint64_t i = 0; i < len2; ++i)
				b[i] = true;
			bool * output = new bool[len3];
			IV iv(io, party, len1, len2, len3);
			io->set_nodelay();
			iv.checkf1Bob(f1);
			iv.checkf2Bob(b, f2);
			io->set_delay();
			iv.evalgBob(g, output);
			delete []b;
			delete[] output;
		}
	}
			double t4 = wallClock();
			t+=(t4-t1);
	return t/TIME;
}
