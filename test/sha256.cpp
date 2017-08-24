#include <emp-tool/emp-tool.h>
#include "malicious/malicious.h"
using namespace std;
using namespace emp;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static string file = circuit_file_location+"/sha-256.txt";
static int l1 = 256;
static int l2 = 256;
static int l3 = 256;
static CircuitFile cf(file.c_str());
void compute(Bit * res, Bit * in, Bit * in2) {
	cf.compute((block*)res, (block*)in, (block*)in2);
}

static char out3[] = "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8";

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, 2, &party, &port);

	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	bool in[l1];bool * output = new bool[l3];
	for(int i = 0; i < l1; ++i)
		in[i] = false;
	void * f = (void*)(compute);
	Malicious2PC<NetIO,RTCktOpt::off> mal(io, party, l1,l2,l3);
	auto start = clock_start();
	if(party == ALICE) {
		//		mal.alice_offline(f);
		//		mal.alice_online(f, in);
		mal.alice_run(f, in);
	}else {
		//	cout <<"offline "<<mal.bob_offline(f)<<endl;
		//	mal.bob_preload();
		//	cout <<"online "<<mal.bob_online(f, in, output)<<endl;
		cout << "run\t"<<mal.bob_run(f, in, output)<<endl;
		string a = hex_to_binary(string(out3));
		for (int i = 0; i < l3; ++i)
			if(output[i] != (a[i]=='1')) {
				error("WRONG ANS!\n");
			}
	}
	cout << "CORRECT, time "<<time_from(start)<<endl;
	delete[] output;
	delete io;
}
