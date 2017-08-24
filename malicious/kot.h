#ifndef KOT_H__
#define KOT_H__

#include <emp-ot/emp-ot.h>
#include "malicious/vot.h"
namespace emp {
class KOT {public:
	int ssp, l, n;
	NetIO * io;
	VOT * vot;
	block * S0 = nullptr, *S1 = nullptr,
			* K0 = nullptr, *K1 = nullptr, 
			*com_msg = nullptr, *msked_msg = nullptr;
	block S, com_delta;
	Commitment COM;
	Com com; Decom decom;
	int * sel = nullptr;
	KOT(NetIO * io, int l, int n, int ssp = 40){
		this->l = l;
		this->n = n;
		this->io = io;
		this->ssp = ssp;
		vot = new VOT(io, ssp);
		sel = new int[n];
		S0 = new block[l];
		S1 = new block[l];
		K0 = new block[n];
		K1 = new block[n];
		com_msg = new block[n];
		msked_msg = new block[n];
		S = zero_block();
	}

	~KOT() {
		delete_array_null(S0);
		delete_array_null(S1);
		delete_array_null(K0);
		delete_array_null(K1);

		delete_array_null(com_msg);
		delete_array_null(msked_msg);
		delete_array_null(sel);

		delete vot;
	}
	PRG prg;
	PRP prp;
	void send(bool * delta, block * m) {
		prg.random_block(S0, l);
		prg.random_block(S1, l);
		prg.random_block(K0, n);
		prg.random_block(K1, n);
		for(int i = 0; i < l; ++i) {
			if(delta[i])
				S = xorBlocks(S, S1[i]);
			else
				S = xorBlocks(S, S0[i]);
		}
		K0[n-1] = S;
		for(int i = 0; i < n-1; ++i) {
			K0[n-1] = xorBlocks(K0[n-1], K0[i]);
		}
		vot->send(K0, K1, n);
		xorBlocks_arr(msked_msg, K1, m, n);
		memcpy(com_msg, msked_msg, n*sizeof(block));
		prp.permute_block(com_msg, n);
		xorBlocks_arr(com_msg, msked_msg, com_msg, n);
		io->send_block(com_msg, n);

		COM.commit(decom, com, delta, l);
		io->send_data(com, sizeof(com));
	}
	void send() {
		vot->send(n);
		io->recv_block(com_msg, n);
		io->recv_data(com, sizeof(com));
	}

	void open_sender(const bool * delta, const block * m, const bool * I, MOTExtension<NetIO> * ot, MOTExtension<NetIO> * cot) {
		cot->send(S0, S1, l);
		io->send_data(decom, sizeof(decom));
		io->send_data(delta, l);
		vot->transfer(n, ot);
		io->recv_data(com, sizeof(com));

		cot->open();

		for(int i = 0; i < n; ++i) sel[i] = 0;
		vot->open(sel, n);

		io->recv_data(decom, sizeof(decom));
		if(!COM.open(decom, com, &S, sizeof(block))){
			error("invalid commitment", __LINE__, __FILE__);
		}

		io->send_block(msked_msg, n);

		for(int i = 0; i < n; ++i) {
			if(I[i])	sel[i] = 1; 
			else sel[i] = -1;
		}
		vot->open(sel, n);	
	}	
	void open_recver(bool * delta, const bool * omega, block * m, bool * I, MOTExtension<NetIO> * ot, MOTExtension<NetIO> * cot) {
		cot->recv(S0, omega, l);//reusing mem S0
		io->recv_data(decom, sizeof(decom));
		memset(delta, 0, l);
		io->recv_data(delta, l);
		if (!COM.open(decom, com, delta, l)) {
			error("invalid commitment", __LINE__, __FILE__);
		}

		bool eq = true;
		for(int i = 0; i < l; ++i) {
			eq = eq and (delta[i] == omega[i]);
		}
		bool * c = new bool[n];
		for(int i = 0; i < n; ++i)
			c[i] = eq;

		block * K = new block[n];
		vot->transfer(K, c, n, ot);
		if(eq) {
			for(int i = 0; i < l; ++i)
				S = xorBlocks(S, S0[i]);
		} else {
			for(int i = 0; i < n; ++i)
				S = xorBlocks(S, K[i]);
		}

		COM.commit(decom, com, &S, sizeof(block));
		io->send_data(com, sizeof(com));

		cot->open(S1, omega, l);
		block S2 = zero_block();
		for(int i = 0; i < l; ++i) {
			if(omega[i] == delta[i])
				S2 = xorBlocks(S2, S0[i]);
			else
				S2 = xorBlocks(S2, S1[i]);
		}
		if(!block_cmp(&S2, &S, 1)) {
			error("inconsistent S", __LINE__, __FILE__);
		}

		vot->open(sel, K0, n);


		S2 = zero_block();
		for(int i = 0; i < n; ++i) {
			S2 = xorBlocks(S2, K0[i]);
		}

		if(!block_cmp(&S2, &S, 1)) {
			error("inconsistent S2", __LINE__, __FILE__);
		}
		io->send_data(decom, sizeof(decom));

		io->recv_block(msked_msg, n);
		block * com_msg2 = new block[n];
		memcpy(com_msg2, msked_msg, n*sizeof(block));
		prp.permute_block(com_msg2, n);
		xorBlocks_arr(com_msg2, msked_msg, com_msg2, n);
		if(!block_cmp(com_msg, com_msg2, n)) {
			error("invalid commitment", __LINE__, __FILE__);
		}
		if(eq) {
			xorBlocks_arr(m, msked_msg, K, n);
		}

		vot->open(sel, K1, n);
		if(!eq)
			xorBlocks_arr(m, msked_msg, K1, n);
		for(int i = 0; i < n; ++i)
			if(sel[i] == 1)
				I[i] = true;
			else I[i] = false;
		delete[] c;
		delete[] K;
		delete[] com_msg2;
	}
};
}
#endif// KOT_H__