#include <emp-tool>
#include <iostream>

using namespace std;

int main(int argc, char** argv) {
	PRG prg;
	XorTree<> xortree(1<<20);
	block * blocks = new block[xortree.output_size()];
	block * blocks2 = new block[xortree.input_size()];
	prg.random_block(blocks, xortree.output_size());
	double t1 = timeStamp();
	for(int i = 0; i < 20; ++i)
		xortree.circuit(blocks2, blocks);
	cout << (timeStamp()-t1)/20<<endl;
}
