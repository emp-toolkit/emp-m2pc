#ifndef XORTREE_NAIVE_H__
#define XORTREE_NAIVE_H__
#include <emp-tool/emp-tool.h>

namespace emp {
class XorTreeNaive{public:
	int n, ssp,m;
	bool **M;
	XorTreeNaive(int n, int m, int ssp = 40) {
		this->n=n;
		this->m=m;
		this->ssp = ssp;
		M = new bool*[n];
		for(int i = 0; i < n; ++i) {
			M[i] = new bool[m];
		}
		for(int i = 0; i < n; ++i)
			for(int j = 0; j < m; ++j)
				M[i][j] = (rand()%2);
	}
	~XorTreeNaive(){
		for(int i = 0; i < n ; ++i)
			delete[] M[i];
		delete[] M;
	}
	void circuit(block* out, block * in) {
		for(int i = 0; i < n; ++i) {
			block res = zero_block();
			for(int j = 0; j < m; ++j) {
				if(M[i][j])
					res = xorBlocks(res, in[j]);

			}
			out[i] = xorBlocks(res, in[i+n]);
		}
	}

	void gen(bool* out, bool * in) {
		PRG prg(fix_key);
		prg.random_bool(out, n);

		for(int i = 0; i < n; ++i) {
			bool res = false;
			for(int j = 0; j < n; ++j) {
				if( M[i][j] == 1)
					res = res ^ (out[j]);
			}
			out[n+i] = res ^ in[i];
		}
	}
	int output_size() {
		return 2*n;
	}
	int input_size() {
		return n;
	}
};
}
#endif
