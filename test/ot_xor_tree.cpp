#include <emp-ot>
#include <emp-tool>
#include "malicious/xor_tree_naive.h"
#include <iostream>
using namespace std;
template<typename IO, template<typename> class T>
double test_ot(IO * io, int party, int length, T<IO>* ot = nullptr, int TIME = 10) {
	if(ot == nullptr) 
		ot = new T<IO>(io);
	block *b0 = new block[length], *b1 = new block[length], *r = new block[length];
	PRG prg(fix_key);
	prg.random_block(b0, length);
	prg.random_block(b1, length);
	bool *b = new bool[length];
	for(int i = 0; i < length; ++i) {
		b[i] = (rand()%2)==1;
	}

	long long t1 = 0, t = 0;
	for(int i = 0; i < TIME; ++i) {
		io->sync();
		auto start = clock_start();
		if (party == ALICE) {
			ot->send(b0, b1, length);
		} else {
			ot->recv(r, b, length);
		}
		t += time_from(start);
	}
	delete ot;
	delete[] b0;
	delete[] b1;
	delete[] r;
	delete[] b;
	return (double)t/TIME;
}
int main2(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	XorTree<40, 192> tree(65535, 40);
	MOTExtension<NetIO> * ot = new MOTExtension<NetIO>(io);
	double t2 = test_ot<NetIO, MOTExtension>(io, party, tree.output_size(), ot);
	block* blocks = new block[tree.input_size()];
	block* blocks2 = new block[tree.output_size()];
	auto start = clock_start();
	tree.circuit(blocks, blocks2);
	double t1  = 40*time_from(start);
	io->set_nodelay();
	cout <<t1<<"\t"<<t2<<"\t"<<t1+t2<<endl;
	delete io;
}
int main(int argc, char** argv) {
	int n[] = {128, 1024, 8192, 65536};
	int m[] = {448, 1384, 8632, 66096};
	for(int i = 0; i < 4; i++) {
		XorTree<> tree(n[i], 40);
		//	XorTreeNaive tree(n[i], m[i], 40);
		block* blocks = new block[tree.input_size()];
		block* blocks2 = new block[tree.output_size()];
		auto start = clock_start();
		tree.circuit(blocks, blocks2);
		double t1 = time_from(start);
		delete[] blocks;
		delete[] blocks2;
		cout << n[i]<<"\t"<<t1*40<<endl;
	}

	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	for(int i = 0; i<4; ++i) {
		MOTExtension<NetIO> * ot = new MOTExtension<NetIO>(io, 40);
		io->set_nodelay();
		double t3 = test_ot<NetIO, MOTExtension>(io, party, 2*n[i], ot);
		cout << n[i]<<"\t"<<t3<<endl;
	}
	delete io;
}
