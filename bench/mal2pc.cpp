#include <emp-tool/emp-tool.h>
#include "bench/bench_mal2pc.h"
#include <iomanip>
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

static CircuitFile *cf;
static int len1;
static int len2;
static int len3;
static NetIO *io;
static int runs = 20;
int port, party;
void compute(Bit * res, Bit * in, Bit * in2) {
	cf->compute((block*)res, (block*)in, (block*)in2);
}
void compute2(Bit * res, Bit * in, Bit * in2) {
	Bit * tin = new Bit[len1+len2];
	memcpy(tin, in, len1*16);
	memcpy(tin+len1, in2, len2*16);
	cf->compute((block*)res, (block*)tin, nullptr);
}

void bench_sha1() {
	len1 = 256;
	len2 = 256;
	len3 = 160;
	string file = circuit_file_location+"/sha-1.txt";
	cf = new CircuitFile(file.c_str());
	void * f = (void *)&compute2;
	cout <<bench_mal2pc_all_online<>(f, len1, len2, len3, io, runs, party)<<"\t";
	double t[3];
	bench_mal2pc_with_offline<>(t, f, len1, len2, len3, io, runs, party);
	cout << t[0]<<"\t"<<t[1]<<"\t"<<t[2];
	delete cf;
}

void bench_sha2() {
	len1 = 256;
	len2 = 256;
	len3 = 256;
	string file = circuit_file_location+"/sha-256.txt";
	cf = new CircuitFile(file.c_str());
	void * f = (void *)&compute2;
	cout <<bench_mal2pc_all_online<>(f, len1, len2, len3, io, runs, party)<<"\t";
	double t[3];
	bench_mal2pc_with_offline<>(t, f, len1, len2, len3, io, runs, party);
	cout << t[0]<<"\t"<<t[1]<<"\t"<<t[2];
	delete cf;
}

void bench_aes() {
	len1 = 128;
	len2 = 128;
	len3 = 128;
	string file = circuit_file_location+"/AES-non-expanded.txt";
	cf = new CircuitFile(file.c_str());
	void * f = (void *)&compute;
	cout <<bench_mal2pc_all_online<>(f, len1, len2, len3, io, runs, party)<<"\t";
	double t[3];
	bench_mal2pc_with_offline<>(t, f, len1, len2, len3, io, runs, party);
	cout << t[0]<<"\t"<<t[1]<<"\t"<<t[2];
	delete cf;
}

void bench_add() {
	len1 = 32;
	len2 = 32;
	len3 = 33;

	string file = circuit_file_location+"/adder_32bit.txt";
	cf = new CircuitFile(file.c_str());
	void * f = (void *)&compute;
	cout <<bench_mal2pc_all_online<>(f, len1, len2, len3, io, runs, party)<<"\t";
	double t[3];
	bench_mal2pc_with_offline<>(t, f, len1, len2, len3, io, runs, party);
	cout << t[0]<<"\t"<<t[1]<<"\t"<<t[2];
	delete cf;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
	cout << "ADD\t"; bench_add();
	cout <<endl;
	cout << "AES\t"; bench_aes();
	cout <<endl;
	cout << "SHA1\t"; bench_sha1();
	cout <<endl;
	cout << "SHA2\t"; bench_sha2();
	cout <<endl;
	delete io;
	return 0;	
}
