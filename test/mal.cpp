#include <emp-tool>
#include "malicious/malicious2.h"
//#define AES

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

#ifdef AES
static string file = circuit_file_location+"/AES-non-expanded.txt";
static int l1 = 128;
static int l2 = 128;
static int l3 = 128;
void compute(Bit * res, Bit * in, Bit * in2) {
	CircuitFile cf(file.c_str());
	cf.compute((block*)res, (block*)in, (block*)in2);
	//	res[0] = (in[0] == in2[0]);
}
#else
static string file = circuit_file_location+"/sha-1.txt";
static int l1 = 256;
static int l2 = 256;
static int l3 = 160;
static CircuitFile sha(file.c_str());
void compute(Bit * res, Bit * in, Bit * in2) {
	CircuitFile cf(sha);
	block * ipt = new block[512];
	memcpy(ipt, in, l1*sizeof(block));
	memcpy(ipt+l1, in2, l2*sizeof(block));
//	for(int i = 0; i < 200; ++i)
	cf.compute((block*)res, (block*)ipt, nullptr);
	delete[] ipt;
	//	res[0] = (in[0] == in2[0]);
}

#endif
static char out3[] = "bafbc2c87c33322603f38e06c3e0f79c1f1b1475";


int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	NetIO ** ioes = Malicious2PC<>::create_io(io, 40, 10);
	bool in[l1];bool * output = new bool[l3];
	for(int i = 0; i < l1; ++i)
		in[i] = true;//(i%2 == 0);
	void * f = (void*)(compute);
	Malicious2PC<RTCktOpt::off> mal(io, party, l1,l2,l3, ioes);
	auto start = clock_start();
	if(party == ALICE) {
		//mal.alice_offline(f);
		//mal.alice_online(f, in);
			mal.alice_run(f, in);
	cout << "time "<<time_from(start)<<endl;

	}else {
		//cout <<"offline "<<mal.bob_offline(f)<<endl;
		//mal.bob_preload();
		//cout <<"online "<<mal.bob_online(f, in, output)<<endl;
		mal.bob_run(f, in, output);

	cout << "time "<<time_from(start)<<endl;

#ifdef AES
#else
		string a = hex_to_binary(string(out3));
		for (int i = 0; i < l3; ++i)
			if(output[i] != (a[i]=='1')) {
				error("incorrect results!");
			}
		cout <<"checked out!"<<endl;
#endif
	}
		delete[] output;
	delete io;
}
