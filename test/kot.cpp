#include "malicious/kot.h"
#include <emp-ot>
#include <emp-tool>
#include <iostream>
using namespace std;

double test_ot(NetIO * io, int party, int TIME =1) {
	int l = 128, n = 5;
	block *m = new block[n], *r = new block[n];

	bool *delta = new bool[l];
	bool *delta2 = new bool[l];
	bool *omega = new bool[l];
	bool *I = new bool[n];
	bool *I2 = new bool[n];
	PRG prg(fix_key);
	prg.random_block(m, n);
	prg.random_bool(delta, l);
	prg.random_bool(omega, l);
	prg.random_bool(I, n);

	KOT * ot = new KOT(io, l, n);
	MOTExtension<NetIO> * mot = new MOTExtension<NetIO>(io);
	MOTExtension<NetIO> * cot = new MOTExtension<NetIO>(io, true);
	long long t1 = 0, t = 0;
	io->sync();
	io->set_nodelay();
	memcpy(omega, delta, l);
	for(int i = 0; i < TIME; ++i) {
//		t1 = timeStamp();
		if (party == ALICE) {
			ot->send(delta, m);
			ot->open_sender(delta, m, I, mot, cot);
		} else {
			ot->send();
			ot->open_recver(delta2, omega, r, I2, mot, cot);
		}
//		t += timeStamp()-t1;
		if(party == BOB) {
			assert(memcmp(I, I2, n) == 0);
			assert(memcmp(delta, delta2, n) == 0);
			if(memcmp(delta, omega, l) == 0) {
				for(int i = 0; i < n; ++i) {
						assert(memcmp(&m[i], &r[i], sizeof(block)) == 0);
				}
			} else {
				for(int i = 0; i < n; ++i) {
					if(I[i])
						assert(memcmp(&m[i], &r[i], sizeof(block)) == 0);
				}
			}
		}
	}

	delete ot;
	delete mot;
	delete cot;
	delete[] m;
	delete[] r;
	delete[] delta;
	delete[] delta2;
	delete[] omega;
	delete[] I2;
	delete[] I;
	return (double(t))/TIME;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	cout <<"test kot"<<test_ot(io, party)<<endl;
	delete io;
}
