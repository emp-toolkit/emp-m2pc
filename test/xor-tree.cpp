#include <emp-tool/emp-tool.h>
#include <iostream>
using namespace emp;
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	PRG prg;
	XorTree<> xortree(1<<20);
	block * blocks = new block[xortree.output_size()];
	block * blocks2 = new block[xortree.input_size()];
	prg.random_block(blocks, xortree.output_size());
	auto start = clock_start();
	for(int i = 0; i < 20; ++i)
		xortree.circuit(blocks2, blocks);
	cout << time_from(start)/20<<endl;
}
