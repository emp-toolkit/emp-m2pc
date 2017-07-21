#include <emp-tool>
#include "malicious/malicious.h"
#include "bench/bench_mal2pc.h"
#include <iomanip>
static int64_t len1 = 128;
static int64_t len2 = 128;
static int64_t len3 = 128;
static int64_t f_size = 32768;

//#define CIRCUIT
//#define LEN1
#define LEN2
//#define LEN3

void compute(Bit * t, Bit * in, Bit * in2) {
	for(int i = 0; i < len3; ++i)
		t[i] = true;
	t[0] = in2[1];
	for(int64_t i = 0; i < f_size; ++i)
		t[0] = in[0] & in2[0];
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);

	void * f = (void *)&compute;
#ifdef LEN1
	cout <<"Len 1"<<endl;
	for(len1 = 128; len1 <= 1024*1024; len1*=2) {
		auto t = bench_mal2pc_all_online(f, len1, len2, len3, io, 2, party);
		if(party == BOB) 
			cout <<f_size<<"\t"<<len1<<"\t"<<len2<<"\t"<<len3<<"\t"<<t<<endl;
	}
len1=128;
#endif
#ifdef LEN2
	cout <<"Len 2"<<endl;
	for(len2 = 128; len2 <= 1024*1024; len2*=2) {
		auto t = bench_mal2pc_all_online(f, len1, len2, len3, io, 2, party);
		if(party == BOB) 
			cout <<f_size<<"\t"<<len1<<"\t"<<len2<<"\t"<<len3<<"\t"<<t<<endl;
	}
len2=128;
#endif
#ifdef LEN3
	cout <<"Len 3"<<endl;
	for(len3 = 128; len3 <= 1024*1024; len3*=2) {
		auto t = bench_mal2pc_all_online(f, len1, len2, len3, io, 2, party);
		if(party == BOB) 
			cout <<f_size<<"\t"<<len1<<"\t"<<len2<<"\t"<<len3<<"\t"<<t<<endl;
	}
len3=128;
#endif
#ifdef CIRCUIT
	cout <<"Circuit"<<endl;
	for(f_size = 1024; f_size <= 1024*1024*32; f_size*=2) {
		auto t = bench_mal2pc_all_online(f, len1, len2, len3, io, 2, party);
		if(party == BOB) 
			cout <<f_size<<"\t"<<len1<<"\t"<<len2<<"\t"<<len3<<"\t"<<t<<endl;
	}
#endif

	delete io;
	return 0;	
}
