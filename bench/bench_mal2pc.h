#include <emp-tool/emp-tool.h>
#include "malicious/malicious.h"
#include <string>
using namespace std;

template<RTCktOpt rt = off>
double bench_mal2pc_all_online(void * f, uint64_t len1, uint64_t len2, uint64_t len3, NetIO * io, uint64_t TIME, uint64_t party) {
	double t = 0;
	bool * in1 = new bool[len1];
	for(uint64_t i = 0; i < len1; ++i)
		in1[i] = true;

	bool * in2 = new bool[len2];
	for(uint64_t i = 0; i < len2; ++i)
		in2[i] = true;

	bool * out = new bool[len3];

	for(uint64_t k = 0; k < TIME; ++k) {
		io->sync();
		double t1 = timeStamp();
		Malicious2PC <rt> mal(io, party, len1, len2, len3);
		bool res = false;
		if(party == ALICE) {
			mal.alice_run(f, in1);
		} else {
			res = mal.bob_run(f, in1, out);
		}
		t += (timeStamp() - t1);
		assert(!res);
	}
	return t/TIME;
}

template<RTCktOpt rt = off>
void bench_mal2pc_with_offline(double t[3], void * f, uint64_t len1, uint64_t len2, uint64_t len3, NetIO * io, uint64_t TIME, uint64_t party) {
	t[0]=t[1]=t[2] = 0;
	bool * in1 = new bool[len1];
	for(uint64_t i = 0; i < len1; ++i)
		in1[i] = true;

	bool * in2 = new bool[len2];
	for(uint64_t i = 0; i < len2; ++i)
		in2[i] = true;

	bool * out = new bool[len3];

	for(uint64_t k = 0; k < TIME; ++k) {
		bool res = false;
		bool res2 = false;
		io->sync();
		double t1 = timeStamp();
		Malicious2PC<RTCktOpt::off> mal(io, party, len1, len2, len3);
		if(party == ALICE) {
			mal.alice_offline(f);
			t[0] += (timeStamp() - t1);
			io->sync();
			t1 = timeStamp();
			mal.alice_online(f, in1);
			t[2] += (timeStamp() - t1);
		} else {
			res = mal.bob_offline(f);
			t[0] += (timeStamp() - t1);
			t1 = timeStamp();
			mal.bob_preload();
			t[1] += (timeStamp() - t1);
			io->sync();
			t1 = timeStamp();
			res2 = mal.bob_online(f, in2, out);
			t[2] += (timeStamp() - t1);
		}
		assert(!res);
		assert(!res2);
	}
	t[0]/=TIME;
	t[1]/=TIME;
	t[2]/=TIME;
}
