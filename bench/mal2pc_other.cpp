#include <emp-tool/emp-tool.h>
#include "malicious/malicious.h"
#include "bench/bench_mal2pc.h"
#include <string>
#include <iomanip>
static int len1;
static int len2;
static int len3;
static NetIO *io;
static int runs = 10;
int port, party;

void mult(block * out, const block * in, const block * in2) {
	Integer a(len1, in);
	Integer b(len2, in2);
	Integer c = a*b;
	memcpy(out, c.bits, len3*sizeof(block));
}
void modexp(block * out, const block * in, const block * in2) {
	Integer a(len1, in);
	Integer b(len2, in2);
	Integer c(len1, in);//(1ULL<<31)-1, len1);
	Integer d = a.modExp(b, c);
	memcpy(out, d.bits, len3*sizeof(block));
}
void sort_exp(block * out, const block * in, const block * in2) {
	Bit * tmp = new Bit[len1];
	for(int i = 0; i < len1; ++i)
		tmp[i] = in[i] ^ in2[i];
	Integer *A = new Integer[len1/32];
	for(int i = 0; i < len1/32; ++i)
		A[i] = Integer(32, &tmp[32*i]);
	sort(A, len1/32);
	for(int i = 0; i < len1/32; ++i)
		memcpy(out+i*32, A[i].bits, 32*sizeof(Bit));
}


void bench_mul() {
	len1 = 128;
	len2 = 128;
	len3 = 128;
	void * f = (void *)&mult;

	cout <<bench_mal2pc_all_online<RTCktOpt::on>(f, len1, len2, len3, io, runs, party)<<"\n";
}
void bench_modexp() {
	len1 = 16;
	len2 = 16;
	len3 = 16;
	void * f = (void *)&modexp;
	cout <<bench_mal2pc_all_online<RTCktOpt::on>(f, len1, len2, len3, io, runs, party)<<"\n";
}
void bench_sort(int n) {
	len1 = n*32;
	len2 = n*32;
	len3 = n*32;
	void * f = (void *)&sort_exp;
	cout <<bench_mal2pc_all_online<RTCktOpt::on>(f, len1, len2, len3, io, runs, party)<<"\n";
}


int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==ALICE ? nullptr:SERVER_IP, port);
#ifdef COUNT_IO
		io->counter = 0;
#endif
	cout << "Mul\t"; bench_mul();
#ifdef COUNT_IO
		cout << io->counter<<endl;
		io->counter = 0;
#endif
	cout << "ModExp\t"; bench_modexp();
#ifdef COUNT_IO
		cout << io->counter<<endl;
		io->counter = 0;
#endif
	cout << "Sort 1024\t"; bench_sort(1024);
#ifdef COUNT_IO
		cout << io->counter<<endl;
		io->counter = 0;
#endif
	cout << "Sort 4096\t"; bench_sort(4096);
#ifdef COUNT_IO
		cout << io->counter<<endl;
		io->counter = 0;
#endif
	delete io;
	return 0;	
}
