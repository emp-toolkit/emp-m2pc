#include <emp-tool/emp-tool.h>
#include "input-validity/iv.h"
#include "bench/bench_input-check.h"
#include <iomanip>
static uint64_t len1 = 128;
static uint64_t len2 = 128;
static uint64_t len3 = 128;
static uint64_t f1_size = 1000;
static uint64_t g_size = 1000;
static char file[] = "circuits/files/AES-non-expanded.txt";
static CircuitFile cf(file);

void check(Bit * res, Bit * in) {
	res[0] = in[1];
	for(uint64_t i = 0; i < f1_size; ++i)
		res[0] = res[0] & in[0];
}

void compute1(Bit * res, Bit * in, Bit * in2) {
	res[0] = in2[1];
	for(uint64_t i = 0; i < g_size; ++i)
		res[0] = in[0] & in2[0];
}

void compute2(Bit * res, Bit * in, Bit * in2) {
	check(res, in);
	check(res, in2);
	res[0] = in2[1];
	for(uint64_t i = 0; i < g_size; ++i)
		res[0] = in[0] & in2[0];
}
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
	void * f1 = (void *)&check;
	void * g1 = (void *)&compute1;
	void * g2 = (void *)&compute2;

	uint64_t size_sig = 90825;
	for(int lognel = 5; lognel <= 15; lognel++) {
		uint64_t nel = 1<<lognel;
		g_size = lognel*(lognel-1)/4*nel*32;
		len1 = len2 = len3 = nel* (32+80);
		f1_size = nel * size_sig;
		int run = 2;
		double t1 = bench_iv(nullptr, nullptr, g2, len1, len2, len3, io, run, party);
		double t2 = bench_iv(f1, f1, g1, len1, len2, len3, io, run, party);
		if(party == BOB) 
			cout <<nel<<"\t"<<f1_size<<"\t"<<g_size<<"\t"<<len1<<"\t"<<t1<<"\t"<<t2<<endl;
	}
	delete io;
	return 0;	
}
