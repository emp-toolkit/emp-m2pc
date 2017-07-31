#include <emp-tool/emp-tool.h>
#include "malicious/malicious.h"
#define AES
#ifdef AES
static char file[] = "circuits/files/AES-non-expanded.txt";
static int l1 = 128;
static int l2 = 128;
static int l3 = 128;
#endif
#ifdef SHA1
static char file[] = "circuits/files/sha-1.txt";
static int l1 = 512;
static int l2 = 512;
static int l3 = 160;
#endif
#ifdef ADD
static char file[] = "circuits/files/adder_32bit.txt";
static int l1 = 32;
static int l2 = 32;
static int l3 = 33;
#endif
static CircuitFile cf(file);
static int num_runs = 100;
void compute(Bit * res, Bit * in, Bit * in2) {
	cf.compute((block*)res, (block*)in, (block*)in2);
}

static string name[] = {"","setup","bobInput", "aliceInput", "gc", "recover"};
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);

	bool in[l1];bool * output = new bool[l3];

	for(int i = 0; i < l1; ++i)
		in[i] = true;//(i%2 == 0);

	void * func = (void*)(compute);

	double tt[] = {0,0,0,0,0,0};
	for (int k = 0; k < num_runs; ++k) {
		Malicious2PC<NetIO> mal(io, party, l1,l2,l3);
		double t[6];
		auto start = clock_start();
		t[0] = 0;
		if(party == ALICE) {
			mal.setupAlice();
			t[1]=time_from(start);
			mal.aliceInputAlice(in);
			t[2]=time_from(start);
			mal.bobInputAlice();
			t[3]=time_from(start);
			mal.gcAlice(func);
			t[4]=time_from(start);
			mal.recoverAlice();
			t[5]=time_from(start);
		}else {
			mal.setupBob();
			t[1]=time_from(start);
			assert(!mal.aliceInputBob());
			t[2]=time_from(start);
			assert(!mal.bobInputBob(in));
			t[3]=time_from(start);
			assert(!mal.gcBob(func, output));
			t[4]=time_from(start);
			assert(!mal.recoverBob());
			t[5]=time_from(start);
		}
		io->flush();
		for(int i = 1; i <=5; ++i)
			tt[i] += (t[i] - t[i-1]);

	}
	double total = 0;
	for(int i = 1; i <=5; ++i){
		cout <<party<<"\t\t"<<name[i]<<"\t\t"<<1000*(tt[i])/num_runs<<endl;
		total +=1000*(tt[i])/num_runs;
	}
	cout<<party<<"\t\t"<<total<<endl; 
	delete[] output;
	delete io;
}
