#include <emp-tool/emp-tool.h>
#include "malicious/malicious.h"
//#define AES
#ifndef EMP_CIRCUIT_PATH
	#define EMP_CIRCUIT_PATH wocao
#endif

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
#ifdef AES
static string file = circuit_file_location+"/AES-non-expanded.txt";
static int l1 = 128;
static int l2 = 128;
static int l3 = 128;
static CircuitFile cf(file.c_str());
void compute(Bit * res, Bit * in, Bit * in2) {
	cf.compute((block*)res, (block*)in, (block*)in2);
	//	res[0] = (in[0] == in2[0]);
}
#else
static string file = circuit_file_location+"/sha-1.txt";
static int l1 = 256;
static int l2 = 256;
static int l3 = 160;
static CircuitFile cf(file.c_str());
void compute(Bit * res, Bit * in, Bit * in2) {
	block * ipt = new block[512];
	memcpy(ipt, in, l1*sizeof(block));
	memcpy(ipt+l1, in2, l2*sizeof(block));
	cf.compute((block*)res, (block*)ipt, nullptr);
	//	res[0] = (in[0] == in2[0]);
}

#endif
static char out3[] = "bafbc2c87c33322603f38e06c3e0f79c1f1b1475";


int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	bool in[l1];bool * output = new bool[l3];
	for(int i = 0; i < l1; ++i)
		in[i] = true;//(i%2 == 0);
	void * f = (void*)(compute);
	Malicious2PC<RTCktOpt::off> mal(io, party, l1,l2,l3);
	double t1 = wallClock();
	if(party == ALICE) {
		//mal.alice_offline(f);
		//mal.alice_online(f, in);
			mal.alice_run(f, in);
	}else {
		//cout <<"offline "<<mal.bob_offline(f)<<endl;
		//mal.bob_preload();
		//cout <<"online "<<mal.bob_online(f, in, output)<<endl;
			cout << "run"<<mal.bob_run(f, in, output)<<endl;

#ifndef AES
		string a = hex_to_binary(string(out3));
		for (int i = 0; i < l3; ++i)
			assert(output[i] == (a[i]=='1'));
#endif
	}
	double t2 = wallClock() - t1;
	cout << "time "<<t2<<endl;
	delete[] output;
	delete io;
}

