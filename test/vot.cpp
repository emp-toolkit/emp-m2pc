#include "malicious/vot.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>
#include <iostream>
using namespace std;
using namespace emp;


double test_ot(NetIO * io, int party, int TIME =10) {
	int length = 40;
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	prg.random_bool(b, length);

	int32_t * sel = new int32_t[length];
	MOTExtension<NetIO> * mot = new MOTExtension<NetIO>(io);
	long long t1 = 0, t = 0;
	io->sync();
	io->set_nodelay();
	for(int i = 0; i < TIME; ++i) {
	VOT * ot = new VOT(io);
//		t1 = timeStamp();
		if (party == ALICE) {
			ot->send(b0, b1, length);
			ot->transfer(length, mot);
		} else {
			ot->send(length);
			ot->transfer(r, b, length, mot);
		}
		if(party == BOB) for(int i = 0; i < length; ++i) {
			if (b[i]) assert(block_cmp(&r[i], &b1[i], 1));
			else assert(block_cmp(&r[i], &b0[i], 1));
		}

		for(int i = 0; i < length; ++i) {
			if(i == 0)
				sel[i] = -1;
			else
			sel[i] = 1;
		}

		if(party == ALICE) {
			ot->open(sel, length);
		} else {
			assert(ot->open(sel, r, length));
			for(int i = 0; i < length; ++i) {
				if (sel[i] == 1) assert(block_cmp(&r[i], &b1[i], 1));
				else if(sel[i] == 0) assert(block_cmp(&r[i], &b0[i], 1));
			}

		}

//		t += timeStamp()-t1;
	delete ot;
	}

	delete mot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	delete[] sel;
	return (double(t))/TIME;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	cout <<"test vot"<<test_ot(io, party)<<endl;
	delete io;
}
