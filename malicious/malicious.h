#ifndef MALICIOUS_2PC_H__
#define MALICIOUS_2PC_H__
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

namespace emp {
template<typename IO, RTCktOpt rt = RTCktOpt::off>
class Malicious2PC { public:
	string GC_FILE = "GC_FILE";
	IO * io;
	FileIO * fio;
	MemIO * mio;
	int party;
	int n1, n2, n3;
	PRG prg, *prgs;
	PRP prp;
	MOTExtension<IO> * ot;
	MOTExtension<IO> * cot;
	Commitment commitment;
	const int ssp = 40;
	XorTree<> * xortree;
	block *seed, *key, **seedB;
	bool * E = nullptr;
	block * gc_delta, *Delta_ib, Delta;
	bool * delta_bool;
	block * B = nullptr, *A = nullptr,* Z_bob = nullptr, *R = nullptr;
	char (*T_dgst)[Hash::DIGEST_SIZE] = nullptr;
	block recovered_delta;

	int PRF_A = 1;
	int PRF_B = 2;
	int PRF_R = 4;
	int PRF_PERMUTE = 6;
	int PRF_ST = 7;
	int PRF_OTHER = 8;
	eb_t Delta_eb;
	int P1cheat = false;
	const eb_t *gTbl;
	bn_t q, w;
	bn_t * s, *t;
	eb_t *C, *D, g1, h1;
	bn_t bn_r;
	eb_t g1Tbl[RLC_EB_TABLE_MAX];
	Malicious2PC(IO * io, int party, int n1, int _n2, int n3) {
		initialize_relic();
		this->n1 = n1;
		this->n3 = n3;
		this->io = io;
		this->party = party;
		xortree = new XorTree<>(_n2);	
		this->n2 = xortree->output_size();
		key = new block[ssp]; 
		seed = new block[ssp];
		seedB = new block*[2];
		seedB[0] = new block[n2]; 
		seedB[1] = new block[n2];
		ot = new MOTExtension<IO>(io);
		cot = new MOTExtension<IO>(io, true);
		prgs = new PRG[ssp];
		A = new block[ssp*n1];
		R = new block[n1*ssp];
		B = new block[ssp*n2];
		gc_delta = new block[ssp];
		Delta_ib = new block[n3];
		gTbl = eb_curve_get_tab();
		eb_curve_get_ord(q);
		C = new eb_t[ssp];
		D = new eb_t[ssp];
		s = new bn_t[ssp];
		t = new bn_t[ssp];
	}
	~Malicious2PC() {
		delete[] B;
		delete[] C;
		delete[] D;
		delete[] s;
		delete[] t;
		delete[] A;
		delete[] R;
		delete[] gc_delta;
		delete ot;
		delete cot;
		delete[] prgs;
		delete[] seedB[0];
		delete[] seedB[1];
		delete[] seedB;
		delete[] key;
		delete[] seed;
		delete xortree;
		delete[] Delta_ib;
		if(E!=nullptr)
			delete[] E;
		if(T_dgst != nullptr)
			delete[] T_dgst;
		if(Z_bob != nullptr)
			delete[] Z_bob;
	}

	void alice_offline(void * f){
		io->set_nodelay();
		setupAlice();
		io->set_delay();
		setupAliceGC(f);
	}
	bool bob_offline(void * f) {
		fio = new FileIO(GC_FILE.c_str(), false);
		io->set_nodelay();
		bool res = setupBob();
		bool res1 = setupBobGC(f);
		return res or res1;
	}
	void bob_preload(){
		int sent = fio->bytes_sent;
		delete fio;
		fio = new FileIO(GC_FILE.c_str(), true);
		mio = new MemIO(0);
		mio->load_from_file(fio, sent);
		delete fio;

	}
	void alice_online(void * f, bool * in) {
		io->set_nodelay();
		aliceInputAlice(in);
		bobInputAlice();
		gcOnlineAlice(f);
		recoverAlice();	
	}
	bool bob_online(void * f, bool * in, bool * out) {
		io->set_nodelay();
		bool res1 = aliceInputBob();
		bool res2 = bobInputBob(in);
		gcOnlineBob(f, out);
		bool res3 = recoverBob();	
		return res1 or res2 or res3;
	}
	void alice_run(void * f, bool * in) {
		io->set_nodelay();
		setupAlice();
		aliceInputAlice(in);
		bobInputAlice();
		io->set_delay();
		gcAlice(f);
		io->set_nodelay();
		recoverAlice();	
	}
	bool bob_run(void * f, bool * in, bool * out) {
		io->set_nodelay();
		bool res1 = setupBob();
		bool res2 = aliceInputBob();
		bool res3 = bobInputBob(in);
		bool res4 = gcBob(f, out);
		bool res5 = recoverBob();	
		return res1 or res2 or res3 or res4 or res5;
	}
	void setupAlice() {
		eb_t h,tmp;
		eb_t hTbl[RLC_EB_TABLE_MAX];
		io->recv_eb(&h, 1);
		eb_mul_pre(hTbl, h);
		prg.random_block(&Delta, 1);
		PRG prg_tmp(&Delta);
		prg_tmp.random_eb(Delta_eb);
		prg.random_block(key, ssp);
		prg.random_block(seed, ssp);
		prg.random_block(seedB[0], n2);
		prg.random_block(seedB[1], n2);
		block * b0 = new block[ssp+2*ot->l];
		block * b1 = new block[ssp+2*ot->l];
		memcpy(b0, seed, ssp*sizeof(block));
		memcpy(b1, key, ssp*sizeof(block));
		prg.random_block(b0+ssp, 2*ot->l);
		prg.random_block(b1+ssp, 2*ot->l);
		ot->send(b0, b1, ssp+2*ot->l);
		ot->setup_recv(b0+ssp, b1+ssp);
		cot->setup_recv(b0+ssp+ot->l, b1+ssp+ot->l);
		for(int j = 0; j < ssp; ++j) {
			prgs[j].reseed(&seed[j], PRF_OTHER);
			prgs[j].random_block(&gc_delta[j], 1);
			gc_delta[j] = make_delta(gc_delta[j]);
			prgs[j].reseed(&seed[j], PRF_ST);
			prgs[j].random_bn(s[j], t[j]);
			eb_mul_fix_norm(C[j], gTbl, s[j]);
			eb_mul_fix_norm(tmp, hTbl, t[j]);
			eb_add_norm(C[j], C[j], tmp);
			io->send_eb(&C[j], 1);
		}
		prg.random_block(Delta_ib, n3);

		//compute B labels
		block * tmp2 = new block[n2];
		for(int j = 0; j < ssp; ++j) {
			prgs[j].reseed(&seed[j], PRF_B);
			prgs[j].random_block(tmp2, n2);
			for(int i = 0; i < n2; ++i) {
				B[i*ssp+j] = tmp2[i];
			}
		}
		delete [] tmp2;
		//compute A labels
		for(int j = 0; j < ssp; ++j) {
			io->set_key(&key[j]);
			prgs[j].reseed(&seed[j], PRF_R);
			prgs[j].random_block(&R[j*n1], n1);

			prgs[j].reseed(&seed[j], PRF_A);
			prgs[j].random_block(&A[j*n1], n1);
		}

		io->recv_eb(&g1, 1);
		eb_mul_pre(g1Tbl, g1);
		for(int j = 0; j < ssp; ++j ) {
			eb_mul_fix_norm(D[j], g1Tbl, s[j]);
		}
		delete[] b0;
		delete[] b1;
	}

	bool setupBob() {
		bool cheat = false;
		eb_t h, tmp, C2;
		prg.random_bn(w);
		bn_mod(w,w,q);
		eb_mul_fix_norm(h, gTbl, w);
		eb_t hTbl[RLC_EB_TABLE_MAX];
		io->send_eb(&h, 1);
		eb_mul_pre(hTbl, h);
		block * bl = new block[ssp+2*ot->l];
		bool* bools = new bool[ssp+2*ot->l];
		E = new bool[ssp];
		prg.random_bool(bools, ssp+2*ot->l);
		memcpy(E, bools, ssp);

		ot->recv(bl, bools, ssp+2*ot->l);
		memcpy(key, bl, ssp*sizeof(block));
		ot->setup_send(bl+ssp, bools+ssp);
		cot->setup_send(bl+ssp+ot->l, bools+ssp+ot->l);
		for(int j = 0; j < ssp; ++j) {
			if(!E[j]) {
				prgs[j].reseed(&key[j], PRF_OTHER);
				prgs[j].random_block(&gc_delta[j], 1);
				gc_delta[j] = make_delta(gc_delta[j]);
			}
			io->recv_eb(&C[j], 1);
			if(!E[j]) {
				prgs[j].reseed(&key[j], PRF_ST);
				prgs[j].random_bn(s[j], t[j]);
				eb_mul_fix_norm(C2, gTbl, s[j]);
				eb_mul_fix_norm(tmp, hTbl, t[j]);
				eb_add_norm(C2, C2, tmp);
				if(eb_cmp(C2, C[j])!=RLC_EQ)
					cheat = true;
			}
		}
		prg.random_bn(bn_r);
		bn_mod(bn_r, bn_r, q);
		eb_mul_fix_norm(g1, gTbl, bn_r);
		io->send_eb(&g1, 1);
		eb_mul_pre(g1Tbl, g1);
		eb_mul_fix_norm(h1, g1Tbl, w);

		block * tmp2 = new block[n2];
		for(int j = 0; j < ssp; ++j) {
			if (!E[j]) {
				prgs[j].reseed(&key[j], PRF_B);
				prgs[j].random_block(tmp2, n2);
				for(int i = 0; i < n2; ++i) {
					B[i*ssp+j] = tmp2[i];
				}
			}
		}
		delete[] tmp2;

		for(int j = 0; j < ssp; ++j) {
			if(!E[j]) {
				prgs[j].reseed(&key[j], PRF_R);
				prgs[j].random_block(&R[j*n1], n1);

				prgs[j].reseed(&key[j], PRF_A);
				prgs[j].random_block(&A[j*n1], n1);
			} else {
			}
		}

		delete[] bools;
		delete[] bl;
		return cheat;
	}

	void setupAliceGC(void * f) {
		block * Bp = new block[xortree->input_size()];
		block* B_loc = new block[n2];
		block * Z = new block[n3];

		block (*T)[4] = new block[n3][4];
		block tmp[4];
		char dgst[Hash::DIGEST_SIZE];
		for(int j = 0; j < ssp; ++j) {
			for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*ssp+j];
			HalfGateGen<IO, rt> gc(io);
			gc.set_delta(gc_delta[j]);
			CircuitExecution::circ_exec = &gc;
			xortree->circuit(Bp, B_loc);
			run_function(f, Z, &A[j*n1], Bp);

			for(int i = 0; i < n3; ++i) {
				tmp[0] = tmp[1] = Z[i];
				tmp[2] = tmp[3] = xorBlocks(Z[i], gc_delta[j]);
				prp.H<4>(T[i], tmp, i*4);
				T[i][1] = xorBlocks(T[i][1], Delta_ib[i]); 
				T[i][3] = xorBlocks(T[i][3], Delta_ib[i]); 
				T[i][3] = xorBlocks(T[i][3], Delta);
			}
			io->set_key(&key[j]);
			io->send_block_enc((block *)T, 4*n3);

			Hash::hash_once(dgst, T, sizeof(block)*4*n3);
			io->send_data(dgst, Hash::DIGEST_SIZE);
		}
		delete[] Bp;
		delete[] B_loc;
		delete[] Z;
		delete[] T;
	}

	bool setupBobGC(void * f) {
		block * Bp = new block[xortree->input_size()];
		block* B_loc = new block[n2];
		block* Z = new block[n3];
		Z_bob = new block[n3*ssp];
		bool cheat = false;
		char dgst[Hash::DIGEST_SIZE];
		T_dgst = new char[ssp][Hash::DIGEST_SIZE];
		block * tmpA = new block[n1];
		block * tmpB = new block[xortree->input_size()];
		prg.random_block(tmpA, n1);
		prg.random_block(tmpB, xortree->input_size());
		block (*T)[4] = new block[n3][4];

		for(int j = 0; j < ssp; ++j) {
			for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*ssp+j];
			if (!E[j]) {
				CheckIO checkio(io);
				HalfGateGen<CheckIO, rt> gc(&checkio);
				gc.set_delta(gc_delta[j]);
				CircuitExecution::circ_exec= &gc;
				xortree->circuit(Bp, B_loc);
				run_function(f, &Z_bob[j*n3], &A[j*n1], Bp);
				if(!checkio.get_check_result())
					cheat = true;

				io->set_key(nullptr);
				io->recv_block_enc((block*)T, 4*n3);
				io->recv_data(T_dgst[j], Hash::DIGEST_SIZE);
			}
			else {
				HalfGateEva<IO, rt> gc(io);
				gc.set_file_io(fio);
				CircuitExecution::circ_exec = &gc;

				run_function(f, Z, tmpA, tmpB);

				io->set_key(&key[j]);
				io->recv_block_enc((block*)T, 4*n3);
				Hash::hash_once(dgst, T, sizeof(block)*4*n3);
				io->recv_data(T_dgst[j], Hash::DIGEST_SIZE);
				if(strncmp(dgst, T_dgst[j], Hash::DIGEST_SIZE)!=0)
					cheat = true;
				fio->send_block((block*)T, 4*n3);
			}
		}

		delete[] tmpA;
		delete[] tmpB;
		delete[] B_loc;
		delete[] Bp;
		delete[] Z;
		delete[] T;
		return cheat;
	}

	void gcOnlineAlice(void *f){ }
	void gcOnlineBob(void * f, bool * output) {
		block * Bp = new block[xortree->input_size()];
		block* B_loc = new block[n2];
		block* Z = new block[n3];
		block (*T)[4] = new block[n3][4];
		bool * tmp_output = new bool[n3];
		block * recover_delta = new block[n3];
		block * tmp_delta = new block[n3];
		bool output_set = false;
		for(int j = 0; j < ssp; ++j) {
			for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*ssp+j];
			if (!E[j]) {
			}
			else {
				HalfGateEva<MemIO, rt> gc(mio);
				CircuitExecution::circ_exec = &gc;
				xortree->circuit(Bp, B_loc);
				run_function(f, Z, &A[j*n1], Bp);
				mio->recv_block((block *)T, 4*n3);
				bool good_result = true;
				for(int i = 0; i < n3; ++i) {
					block HZ = prp.H(Z[i], 4*i); 
					block HZ2 = prp.H(Z[i], 4*i+2); 
					if(block_cmp(&T[i][0], &HZ, 1)) {
						tmp_output[i] = false;
						tmp_delta[i] = xorBlocks(T[i][2], prp.H(Z[i], 4*i+1));
					}
					else if(block_cmp(&T[i][2], &HZ2, 1)) {
						tmp_output[i] = true;
						tmp_delta[i] = xorBlocks(T[i][3], prp.H(Z[i], 4*i+3));
					}
					else {
						good_result = false;
						break;
					}
				}
				if (good_result and !output_set) {
					memcpy(output, tmp_output, n3);
					memcpy(recover_delta, tmp_delta, n3*sizeof(block));
					output_set = true;
				} else if(output_set) {
					for(int i = 0; i < n3; ++i)
						if(output[i] != tmp_output[i]) {
							recovered_delta = xorBlocks(tmp_delta[i], recover_delta[i]);
							P1cheat = true;
						}
				}
			}
		}

		delete[] B_loc;
		delete[] Bp;
		delete[] Z;
		delete[] tmp_output;
		delete[] tmp_delta;
		delete[] recover_delta;
		delete[] T;
	}


	void bobInputAlice() {
		block * tmp = new block[ssp];
		block * tmp2 = new block[ssp];
		ot->send(seedB[0], seedB[1], n2);
		for(int i = 0; i < n2; ++i) {
			for (int j = 0; j < ssp; ++j)
				tmp[j] = seedB[0][i];
			prp.Hn(tmp, tmp, i, ssp, tmp2);
			xorBlocks_arr(tmp, tmp, &B[i*ssp], ssp);
			io->send_block(tmp, ssp);

			for (int j = 0; j < ssp; ++j)
				tmp[j] = seedB[1][i];
			prp.Hn(tmp, tmp, i, ssp, tmp2);
			xorBlocks_arr(tmp, tmp, &B[i*ssp], ssp);
			xorBlocks_arr(tmp, tmp, gc_delta, ssp);
			io->send_block(tmp, ssp);
		}

		delete [] tmp;
		delete [] tmp2;
	}

	bool bobInputBob(bool * b) {
		block * tmp = new block[ssp];
		block * tmp3 = new block[ssp];
		block * tmp2 = new block[ssp];
		bool cheat = false;
		bool * xor_input = new bool[n2];
		xortree->gen(xor_input, b);
		ot->recv(seedB[0], xor_input, n2);

		for(int i = 0; i < n2; ++i) {
			if (xor_input[i]) {
				io->recv_block(tmp, ssp);
				io->recv_block(tmp3, ssp);
			} else  {
				io->recv_block(tmp3, ssp);
				io->recv_block(tmp, ssp);
			}
			for (int j = 0; j < ssp; ++j)
				tmp[j] = seedB[0][i];
			prp.Hn(tmp, tmp, i, ssp, tmp2);
			xorBlocks_arr(tmp3, tmp, tmp3, ssp);

			for(int j = 0; j < ssp; ++j) {
				if(!E[j]) {
					if (xor_input[i])
						tmp3[j] = xorBlocks(tmp3[j], gc_delta[j]);
					if (!block_cmp(&B[i*ssp+j], &tmp3[j], 1))
						cheat = true;
				} else {
					B[i*ssp+j] = tmp3[j];
				}
			}
		}
		delete[] tmp;
		delete[] tmp2;
		delete[] tmp3;
		delete[] xor_input;
		return cheat;
	}

	void aliceInputAlice(bool * b) {
		block * X = new block[n1+ot->l];
		block * tmp = new block[n1];
		uint8_t * permute = new uint8_t[n1];
		bool *b_ot = new bool[ot->l];
		prg.random_bool(b_ot, ot->l);

		cot->recv(X, b, n1);
		ot->recv(X+n1, b_ot, ot->l);
		ot->setup_send(X+n1, b_ot);

		for(int j = 0; j < ssp; ++j) {
			io->set_key(&key[j]);
			prgs[j].reseed(&seed[j], PRF_R);
			prgs[j].random_block(&R[j*n1], n1);
			xorBlocks_arr(tmp, &R[j*n1], X, n1);
			io->send_block_enc(tmp, n1);

			prgs[j].reseed(&seed[j], PRF_A);
			prgs[j].random_block(&A[j*n1], n1);
			for(int i = 0; i < n1; ++i) {
				if(b[i])
					tmp[i] = xorBlocks(A[j*n1+i], gc_delta[j]);
				else 
					tmp[i] = A[j*n1+i];
			}
			io->send_block_enc(tmp, n1);
		}

		cot->open(tmp, b, n1);
		xorBlocks_arr(X, X, tmp, n1);	

		block T[2];
		block out[2][2];
		for(int j = 0; j < ssp; ++j) {
			prgs[j].reseed(&seed[j], PRF_PERMUTE);
			prgs[j].random_data(permute, n1);
			for(int i = 0; i < n1; ++i) {
				T[0] = R[j*n1+i];
				T[1] = A[j*n1+i];
				prp.H<2>(out[0], T, i*2);

				T[0] = xorBlocks(T[0], X[i]);
				T[1] = xorBlocks(T[1], gc_delta[j]);
				prp.H<2>(out[1], T, i*2);

				int ind = permute[i]%2;
				io->send_block(out[ind], 2);
				io->send_block(out[1-ind], 2);
			}
		}
		delete[] X;
		delete[] tmp;
		delete[] permute;
		delete[] b_ot;
	}

	bool aliceInputBob() {
		block * X0 = new block[n1+ot->l];
		block * X1 = new block[n1+ot->l];
		block * X0xorX1 = new block[n1];
		block * tmp = new block[n1];
		bool cheat = false;
		prg.random_block(X0, n1+ot->l);
		prg.random_block(X1, n1+ot->l);
		xorBlocks_arr(X0xorX1, X0, X1, n1);
		cot->send(X0, X1, n1);
		ot->send(X0+n1, X1+n1, ot->l);
		ot->setup_recv(X0+n1, X1+n1);

		for(int j = 0; j < ssp; ++j) {
			if(!E[j]) {
				io->set_key(nullptr);
				io->recv_block_enc(tmp, n1);
				io->recv_block_enc(tmp, n1);
			} else {
				io->set_key(&key[j]);
				io->recv_block_enc(&R[j*n1], n1);
				io->recv_block_enc(&A[j*n1], n1);
			}
		}
		cot->open();

		uint8_t * permute = new uint8_t[n1];
		block T[2];
		block out[2][2];
		block out2[2][2];
		for(int j = 0; j < ssp; ++j) {
			if(!E[j]) {
				prgs[j].reseed(&key[j], PRF_PERMUTE);
				prgs[j].random_data(permute, n1);
				for(int i = 0; i < n1; ++i) {
					T[0] = R[j*n1+i];
					T[1] = A[j*n1+i];
					prp.H<2>(out[0], T, i*2);

					T[0] = xorBlocks(T[0], X0xorX1[i]);
					T[1] = xorBlocks(T[1], gc_delta[j]);
					prp.H<2>(out[1], T, i*2);

					int ind = permute[i]%2;
					io->recv_block(out2[ind], 2);
					io->recv_block(out2[1-ind], 2);
					if (!block_cmp(out[0], out2[0], 2))
						cheat = true;
					if (!block_cmp(out[1], out2[1], 2))
						cheat = true;
				}
			} else {
				for(int i = 0; i < n1; ++i) {
					T[0] = xorBlocks(R[j*n1+i], X0[i]);
					T[1] = A[j*n1+i];
					prp.H<2>(out[0], T, i*2);

					io->recv_block(out2[0], 2);
					io->recv_block(out2[1], 2);
					if( (!block_cmp(out[0], out2[0], 2)) and
							(!block_cmp(out[0], out2[1], 2)))
						cheat = true;
				}
			}
		}
		delete[] X0;
		delete[] X1;
		delete[] X0xorX1;
		delete[] tmp;
		delete[] permute;
		return cheat;
	}
	void gcAlice(void * f) {
		block * Bp = new block[xortree->input_size()];
		block* B_loc = new block[n2];
		block * Z = new block[n3];

		block tmp[4];
		block (*T)[4] = new block[n3][4];
		char dgst[Hash::DIGEST_SIZE];
		for(int j = 0; j < ssp; ++j) {
			for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*ssp+j];
			HalfGateGen<IO, rt> gc(io);
			gc.set_delta(gc_delta[j]);
			CircuitExecution::circ_exec = &gc;
			xortree->circuit(Bp, B_loc);

			run_function(f, Z, &A[j*n1], Bp);
			for(int i = 0; i < n3; ++i) {
				tmp[0] = tmp[1] = Z[i];
				tmp[2] = tmp[3] = xorBlocks(Z[i], gc_delta[j]);
				prp.H<4>(T[i], tmp, i*4);
				T[i][1] = xorBlocks(T[i][1], Delta_ib[i]); 
				T[i][3] = xorBlocks(T[i][3], Delta_ib[i]); 
				T[i][3] = xorBlocks(T[i][3], Delta);
			}
			io->set_key(&key[j]);
			io->send_block_enc((block *)T, 4*n3);

			Hash::hash_once(dgst, T, sizeof(block)*4*n3);
			io->send_data(dgst, Hash::DIGEST_SIZE);
		}
		delete[] Bp;
		delete[] B_loc;
		delete[] Z;
		delete[] T;
	}

	bool gcBob(void * f, bool * output) {
		block * Bp = new block[xortree->input_size()];
		block* B_loc = new block[n2];
		block* Z = new block[n3];
		Z_bob = new block[n3*ssp];
		bool cheat = false;
		T_dgst = new char[ssp][Hash::DIGEST_SIZE];

		block (*T)[4] = new block[n3][4];

		bool * tmp_output = new bool[n3];
		block * recover_delta = new block[n3];
		block * tmp_delta = new block[n3];
		char dgst[Hash::DIGEST_SIZE];
		bool output_set = false;
		for(int j = 0; j < ssp; ++j) {
			for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*ssp+j];
			if (!E[j]) {
				CheckIO checkio(io);
				HalfGateGen<CheckIO, rt> gc(&checkio);
				gc.set_delta(gc_delta[j]);
				CircuitExecution::circ_exec = &gc;
				xortree->circuit(Bp, B_loc);
				run_function(f, &Z_bob[j*n3], &A[j*n1], Bp);
				if(!checkio.get_check_result())
					cheat = true;

				io->set_key(nullptr);
				io->recv_block_enc((block*)T, 4*n3);
				io->recv_data(T_dgst[j], Hash::DIGEST_SIZE);
			}
			else {
				HalfGateEva<IO,rt> gc(io);
				CircuitExecution::circ_exec = &gc;
				xortree->circuit(Bp, B_loc);
				run_function(f, Z, &A[j*n1], Bp);
				io->set_key(&key[j]);
				io->recv_block_enc((block *)T, 4*n3);
				bool good_result = true;
				for(int i = 0; i < n3; ++i) {
					block HZ = prp.H(Z[i], 4*i); 
					block HZ2 = prp.H(Z[i], 4*i+2); 
					if(block_cmp(&T[i][0], &HZ, 1)) {
						tmp_output[i] = false;
						tmp_delta[i] = xorBlocks(T[i][2], prp.H(Z[i], 4*i+1));
					}
					else if(block_cmp(&T[i][2], &HZ2, 1)) {
						tmp_output[i] = true;
						tmp_delta[i] = xorBlocks(T[i][3], prp.H(Z[i], 4*i+3));
					}
					else {
						good_result = false;
						break;
					}
				}
				if (good_result and !output_set) {
					memcpy(output, tmp_output, n3);
					memcpy(recover_delta, tmp_delta, n3*sizeof(block));
					output_set = true;
				} else if(output_set) {
					for(int i = 0; i < n3; ++i)
						if(output[i] != tmp_output[i]) {
							recovered_delta = xorBlocks(tmp_delta[i], recover_delta[i]);
							P1cheat = true;
						}
				}
				Hash::hash_once(dgst, T, sizeof(block)*4*n3);
				io->recv_data(T_dgst[j], Hash::DIGEST_SIZE);
				if(strncmp(dgst, T_dgst[j], Hash::DIGEST_SIZE)!=0)
					cheat = true;
			}
		}

		delete[] B_loc;
		delete[] Bp;
		delete[] Z;
		delete[] tmp_output;
		delete[] tmp_delta;
		delete[] recover_delta;
		delete[] T;
		return cheat;
	}

	void recoverAlice() {
		eb_t tmp;
		eb_t h1Tbl[RLC_EB_TABLE_MAX];
		io->recv_eb(&h1, 1);
		io->send_block(&Delta, 1);
		io->send_block(Delta_ib, n3);
		eb_sub_norm(h1,h1,Delta_eb);
		eb_mul_pre(h1Tbl, h1);
		for(int j = 0; j < ssp; ++j ) {
			eb_mul_fix_norm(tmp, h1Tbl, t[j]);
			eb_add_norm(D[j], D[j], tmp);
			block b = seed[j];
			b = xorBlocks(b, KDF(D[j]));
			io->send_block(&b, 1);
		}
	}

	bool recoverBob() {
		bool cheat = false;
		eb_t Omega, D, tmp;
		if(P1cheat) {
			PRG prg_tmp(&recovered_delta);
			prg_tmp.random_eb(&Omega);
			eb_add_norm(h1, h1, Omega);
		}
		io->send_eb(&h1, 1);
		io->recv_block(&Delta, 1);
		PRG prg_tmp(&Delta);
		prg_tmp.random_eb(&Delta_eb);
		eb_t h1Tbl[RLC_EB_TABLE_MAX];
		eb_sub_norm(h1,h1,Delta_eb);
		eb_mul_pre(h1Tbl, h1);

		io->recv_block(Delta_ib, n3);
		char dgst[Hash::DIGEST_SIZE];block tmp2[4];
		block (*T)[4] = new block[n3][4];
		for(int j = 0; j < ssp; ++j) {
			if(!E[j]) {
				eb_mul_fix_norm(D, g1Tbl, s[j]);
				eb_mul_fix_norm(tmp, h1Tbl, t[j]);
				eb_add_norm(D, D, tmp);
				block b = key[j];
				b = xorBlocks(b, KDF(D));
				block b2;
				io->recv_block(&b2, 1);
				if(!block_cmp(&b, &b2, 1))
					cheat = true;

				for(int i = 0; i < n3; ++i) {
					tmp2[0] = tmp2[1] = Z_bob[j*n3+i];
					tmp2[2] = tmp2[3] = xorBlocks(Z_bob[j*n3+i], gc_delta[j]);
					prp.H<4>(T[i], tmp2, i*4);
					T[i][1] = xorBlocks(T[i][1], Delta_ib[i]); 
					T[i][3] = xorBlocks(T[i][3], Delta_ib[i]); 
					T[i][3] = xorBlocks(T[i][3], Delta);
				}
				Hash::hash_once(dgst, T, sizeof(block)*4*n3);
				if(strncmp(T_dgst[j], dgst, Hash::DIGEST_SIZE)!=0)
					cheat = true;
			} else {
				eb_mul_norm(C[j], C[j], bn_r);
				io->recv_block(&seed[j], 1);
				seed[j] = xorBlocks(seed[j], KDF(C[j]));
			}
		}
		delete[] T;
		return cheat;
	}
};
}
#endif// MALICIOUS_H__

