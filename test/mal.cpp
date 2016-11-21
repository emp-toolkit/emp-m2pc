#include <emp-tool>
#include "malicious/malicious2.h"
#define AES

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static string file = circuit_file_location+"/AES-non-expanded.txt";
static int l1 = 128;
static int l2 = 128;
static int l3 = 128;
static CircuitFile cf(file.c_str());
void compute(Bit * res, Bit * in, Bit * in2) {
	for(int i = 0; i < 1; ++i)
		 res[i] = in[i] & in2[i];
//	cf.compute((block*)res, (block*)in, (block*)in2);
}


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
			mal.alice_run(f, in);
	}else {
			mal.bob_run(f, in, output);
	}
	double t2 = wallClock() - t1;
	cout << "time "<<t2<<endl;
	delete[] output;
	delete io;
}

