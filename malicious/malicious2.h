#ifndef MALICIOUS_2PC_H__
#define MALICIOUS_2PC_H__
#include "malicious/kot.h"
#include <emp-tool>
#include <emp-ot>
#include <thread>
#include "malicious/ThreadPool.h"
template<RTCktOpt rt = RTCktOpt::on>
class Malicious2PC { public:
	NetIO * io;
	NetIO** ioes;
	int n1, n2, n3, ssp, party, G, eval, baseot_size, baseot_cap;
	char (*comT)[20] = nullptr, (*hashGC)[20] = nullptr;
	bool * E = nullptr, *baseot_sel, delta_bool[128], omega_set = false;
	XorTree<> * xortree;
	PRG prg, *prgs;
	PRP prp, *prps;
	Commitment commitment;

	MOTExtension<NetIO> * ot, * cot;
	KOT * kot;
	block *seed = nullptr, *key = nullptr,
			*keyorseed = nullptr, *gc_delta = nullptr,
			* B = nullptr,  *A = nullptr,
			*R = nullptr, *baseot_seed0, *baseot_seed1,
			* Delta0 = nullptr, Delta,
			* Z = nullptr, (*T)[2] = nullptr, 
			Omega, (*H)[2] = nullptr,
			* X0 = nullptr, *X1 = nullptr,  ** scratch = nullptr;
	const int NUM_THREADS = 2;
	const static int PRG_GC = 1,  PRF_R = 2, PRF_PERMUTE = 3;
	ThreadPool *pool;

	static int num_garble(int ssp, int eval) {
		if(ssp == 40) {
			if(eval == 5)return 669;
			if(eval == 6)return 307;
			if(eval == 7)return 181;
			if(eval == 8)return 124;
			if(eval == 9)return 95;
			if(eval == 10)return 78;
			if(eval == 11)return 67;
			if(eval == 12)return 59;
			if(eval == 13)return 54;
			if(eval == 14)return 51;
			if(eval == 15)return 49;
			if(eval == 16)return 47;
			if(eval == 17)return 45;
			if(eval == 18)return 45;
			if(eval == 19)return 44;
			if(eval == 20)return 40;
		}
		return ssp;
	}
	static NetIO** create_io(NetIO * io, int ssp, int eval) {
		NetIO** res = new NetIO*[eval];
		for(int i = 0; i < eval; ++i) {
			res[i] = new NetIO(io->is_server?nullptr:io->addr.c_str(), io->port+1+i, true);
		}
		return res;	
	}
	void pick_random_set(bool * ccset) {
		for(int i = 0; i < G; ++i)ccset[i] = false;
		int cnt = 0, pos;
		while(cnt < eval) {
			prg.random_data(&pos, 4);
			pos = (pos < 0) ? -1*pos : pos;
			pos = pos % G;
			if(!ccset[pos]) {
				cnt ++;
				ccset[pos] = true;
			}
		}
	}
	void block_to_bool(bool * b, block blk) {
		uint64_t * num = (uint64_t*)(&blk);
		int64_to_bool(b, num[0], 64);
		int64_to_bool(b+64, num[1], 64);
	}

	Malicious2PC(NetIO * io, int party, int n1, int _n2, int n3, NetIO ** ioes, int eval = 10, int ssp = 40) {
		pool = new ThreadPool(NUM_THREADS);
		this->eval = eval;
		G = num_garble(ssp, eval);
		this->n1 = n1;
		this->n3 = n3;
		this->io = io;
		this->ioes = ioes;
		this->ssp = ssp;
		this->party = party;
		xortree = new XorTree<>(_n2);	
		this->n2 = xortree->output_size();
		key = new block[G]; 
		seed = new block[G];
		keyorseed = new block[G];

		hashGC = new char[G][20];
		gc_delta = new block[G];

		E = new bool[G];
		ot = new MOTExtension<NetIO>(io);
		cot = new MOTExtension<NetIO>(io, true);
		kot = new KOT(io, 128, G, ssp);
		prgs = new PRG[G];
		prps = new PRP[G];
		A = new block[G*n1];
		Z = new block[G*n3];
		R = new block[G*n1];
		B = new block[G*n2];
		T = new block[G*n3][2];
		H = new block[n3][2];
		X0 = new block[n1];
		X1 = new block[n1];

		Delta0 = new block[n3];
		comT = new char[G][20];
		baseot_size = 0;
		baseot_cap = 3*ot->l;
		baseot_seed0 = new block[baseot_cap];
		baseot_seed1 = new block[baseot_cap];
		baseot_sel = new bool[baseot_cap];

		int scratch_size = max(2*n2, 3*n3);
		scratch_size = max(scratch_size, n1);
		scratch = new block*[G];
		for(int i = 0; i < G; ++i)
			scratch[i] = new block[scratch_size];
	}
	~Malicious2PC() {
		delete_array_null(key);
		delete_array_null(seed);
		delete_array_null(keyorseed);
		delete_array_null(gc_delta);
		delete_array_null(prgs);
		delete xortree;

		delete_array_null(E);
		delete_array_null(A);
		delete_array_null(Z);
		delete_array_null(R);
		delete_array_null(B);
		delete_array_null(T);
		delete_array_null(H);
		delete_array_null(X0);
		delete_array_null(X1);
		delete_array_null(Delta0);
		delete_array_null(comT);
		delete_array_null(hashGC);
		delete_array_null(baseot_seed0);
		delete_array_null(baseot_seed1);
		delete_array_null(baseot_sel);
		for(int i = 0; i < NUM_THREADS; ++i)
			delete_array_null(scratch[i]);
		delete_array_null(scratch);
		delete ot;
		delete cot;
		delete kot;
		delete pool;
	}
	void alice_run(void * f, bool * in) {
		io->set_nodelay();
		setupAlice();
		io->flush();
		setupGCAlice(f);
		aliceInputAlice(in);
		bobInputAlice();
		gcAlice(f);
		recoverAlice();	
	}
	void bob_run(void * f, bool * in, bool * out) {
		io->set_nodelay();
		setupBob();
		io->flush();
		setupGCBob(f);
		aliceInputBob();
		bobInputBob(in);
		gcBob(f, out);
		recoverBob();
	}
	void setupAlice() {
		block * b0 = new block[G+baseot_cap];
		block * b1 = new block[G+baseot_cap];

		prg.random_block(&Delta, 1);
		block_to_bool(delta_bool, Delta);
		prg.random_block(b0, G+baseot_cap);
		prg.random_block(b1, G+baseot_cap);

		ot->send(b0, b1, G+baseot_cap);
		memcpy(seed, b0, G*sizeof(block));
		memcpy(key, b1, G*sizeof(block));
		memcpy(baseot_seed0, b0+G, baseot_cap*sizeof(block));
		memcpy(baseot_seed1, b1+G, baseot_cap*sizeof(block));
		prg.random_block(Delta0, n3);
		for(int i = 0; i < n3; ++i) {
			H[i][0] = Delta0[i];
			H[i][1] = xorBlocks(Delta0[i], Delta);
		}
		prp.Hn((block*)H, (block*)H, 0, n3*2);

		io->send_block((block *)H, n3*2);
		kot->send(delta_bool, seed);
		delete[] b0;
		delete[] b1;
	}

	void setupBob() {
		block * blks = new block[G+baseot_cap];
		bool* sel = new bool[G+baseot_cap];
		pick_random_set(E);
		prg.random_bool(sel, baseot_cap+G);
		memcpy(sel, E, G);

		ot->recv(blks, sel, G+baseot_cap);
		memcpy(baseot_sel, sel+G, baseot_cap);
		memcpy(keyorseed, blks, G*sizeof(block));
		memcpy(baseot_seed0, blks+G, baseot_cap*sizeof(block));

		io->recv_block((block*)H, n3*2);
		kot->send();
		delete[] blks;
		delete[] sel;
	}

	void setupGCAlice(void * f) {
		vector<future<void>> res;
		for(int j = 0; j < G; j++) {
			res.push_back(pool->enqueue([this, f, j]() {
				garbleNhash(hashGC[j], seed[j], f, j, comT[j]);
			}));
		}
		for(size_t j = 0; j < res.size(); ++j)
			res[j].get();
		io->send_data(hashGC, 20*G);
		io->send_data(comT, 20*G);
	}

	void setupGCBob(void * f) {
		vector<future<void>> res;
		char (*hashGC2)[20] = new char[G][20];
		for(int j = 0; j < G; ++j) {
			if(!E[j]) {
				res.push_back(pool->enqueue([this, f, j, hashGC2]() {
					garbleNhash(hashGC2[j], keyorseed[j], f, j, nullptr);
				}));
			}
		}
		for(size_t j = 0; j < res.size(); ++j)
			res[j].get();
		io->recv_data(hashGC, 20*G);
		for(int j = 0; j < G; ++j) {
			if(!E[j]) {
				if(memcmp(hashGC[j], hashGC2[j], 20)!=0 ) {
					error("cheat");
				}
			}
		}
		io->recv_data(comT, 20*G);
		delete[] hashGC2;
	}

	void garbleNhash(char h[20], block seedj, void * f, int j, char * h2) {
		prgs[j].reseed(&seedj, PRG_GC);
		prgs[j].random_block(&gc_delta[j], 1);
		gc_delta[j] = GarbleCircuit::make_delta(gc_delta[j]);
		prgs[j].random_block(&A[j*n1], n1);
		prgs[j].random_block(scratch[j], n2);
		for(int i = 0; i < n2; ++i) {
			B[i*G+j] = scratch[j][i];
		}

		HashIO hashio(io);
		HalfGateGen<HashIO, rt> gc(&hashio);
		gc.set_delta(gc_delta[j]);
		local_gc = &gc;
		xortree->circuit(scratch[j]+n2, scratch[j]);
		run_function(f, &Z[j*n3], &A[j*n1], scratch[j]+n2);
		hashio.get_digest(h);
		if(h2 != nullptr) {
			computeTranslationTable(h2, j);
		} 
	}

	void computeTranslationTable(char hashT[20], int j) {
		block *H0 = scratch[j];
		block *H1 = H0 + n3;
		block *tmp = H1 + n3;
		memcpy(H0, &Z[j*n3], sizeof(block)*n3);
		xorBlocks_arr(H1, H0, gc_delta[j], n3);
		prps[j].Hn(H0, H0, 0, n3, tmp);
		prps[j].Hn(H1, H1, 0, n3, tmp);
		xorBlocks_arr(H1, H1, Delta, n3);
		for(int i = 0; i <n3; ++i) {
			T[j*n3+i][0] = xorBlocks(H0[i], Delta0[i]);
			T[j*n3+i][1] = xorBlocks(H1[i], Delta0[i]);
		}

		Hash::hash_once(hashT, T[j*n3], sizeof(block)*2*n3);
	}
	void bobInputAlice() {
		block * tmp = new block[G];
		ot->setup_send(baseot_seed0+baseot_size, baseot_sel+baseot_size);
		baseot_size +=ot->l;
		block * seedB0 = new block[n2];
		block * seedB1 = new block[n2];
		prg.random_block(seedB0, n2);
		prg.random_block(seedB1, n2);
		ot->send(seedB0, seedB1, n2);
		
		AES_KEY aes_key;
		for(int i = 0; i < n2; ++i) {
			AES_set_encrypt_key(seedB0[i], &aes_key);
			memcpy(tmp, &B[i*G], G*sizeof(block));
			AES_ecb_encrypt_blks(tmp, G, &aes_key);
			io->send_block(tmp, G);

			AES_set_encrypt_key(seedB1[i], &aes_key);
			xorBlocks_arr(tmp, &B[i*G], gc_delta, G);
			AES_ecb_encrypt_blks(tmp, G, &aes_key);
			io->send_block(tmp, G);
		}
		delete [] tmp;
		delete[] seedB0;
		delete[] seedB1;
	}

	void bobInputBob(bool * b) {
		block * tmp = new block[G];
		block * tmp2 = new block[G];
		bool * xor_input = new bool[n2];
		xortree->gen(xor_input, b);
		block * seedB = new block[n2];

		ot->setup_recv(baseot_seed0+baseot_size, baseot_seed1+baseot_size);

		baseot_size +=ot->l;
		ot->recv(seedB, xor_input, n2);

		for(int i = 0; i < n2; ++i) {
			if (xor_input[i]) {
				io->recv_block(tmp2, G);
				io->recv_block(tmp, G);
			} else  {
				io->recv_block(tmp, G);
				io->recv_block(tmp2, G);
			}
			AES_KEY aes_key;
			AES_set_decrypt_key(seedB[i], &aes_key);
			AES_ecb_decrypt_blks(tmp, G, &aes_key);

			for(int j = 0; j < G; ++j) {
				if(!E[j]) {
					if (xor_input[i])
						tmp[j] = xorBlocks(tmp[j], gc_delta[j]);
					if (!block_cmp(&B[i*G+j], &tmp[j], 1)) {
						error("cheat bob input");
					}
				} else {
					B[i*G+j] = tmp[j];
				}
			}
		}
		delete[] tmp;
		delete[] tmp2;
		delete[] xor_input;
		delete[] seedB;
	}
	void aliceInputAlice(bool * b) {
		block * X = new block[n1];
		block * tmp = new block[n1];
		uint8_t * permute = new uint8_t[n1];

		cot->setup_recv(baseot_seed0+baseot_size, baseot_seed1+baseot_size);
		baseot_size+=ot->l;
		cot->recv(X, b, n1);
		ot->setup_recv(baseot_seed0+baseot_size, baseot_seed1+baseot_size);
		baseot_size+=ot->l;

		prg.random_bool(baseot_sel, baseot_cap);
		ot->recv(baseot_seed0, baseot_sel, baseot_cap);
		baseot_size = 0;

		for(int j = 0; j < G; ++j) {
			io->set_key(&key[j]);
			prgs[j].reseed(&seed[j], PRF_R);
			prgs[j].random_block(&R[j*n1], n1);
			xorBlocks_arr(tmp, &R[j*n1], X, n1);
			io->send_block_enc(tmp, n1);

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

		block tmp2[2];
		block out[2][2];
		for(int j = 0; j < G; ++j) {
			prgs[j].reseed(&seed[j], PRF_PERMUTE);
			prgs[j].random_data(permute, n1);
			for(int i = 0; i < n1; ++i) {
				tmp2[0] = R[j*n1+i];
				tmp2[1] = A[j*n1+i];
				prp.H<2>(out[0], tmp2, i*2);

				tmp2[0] = xorBlocks(tmp2[0], X[i]);
				tmp2[1] = xorBlocks(tmp2[1], gc_delta[j]);
				prp.H<2>(out[1], tmp2, i*2);

				int ind = permute[i]%2;
				io->send_block(out[ind], 2);
				io->send_block(out[1-ind], 2);
			}
		}
		delete[] X;
		delete[] tmp;
		delete[] permute;
	}

	void  aliceInputBob() {
		block * X0xorX1 = new block[n1];
		block * tmp = new block[n1];
		prg.random_block(X0, n1);
		prg.random_block(X1, n1);
		xorBlocks_arr(X0xorX1, X0, X1, n1);

		cot->setup_send(baseot_seed0+baseot_size, baseot_sel+baseot_size);
		baseot_size += ot->l;
		cot->send(X0, X1, n1);
		ot->setup_send(baseot_seed0+baseot_size, baseot_sel+baseot_size);
		baseot_size += ot->l;
		prg.random_block(baseot_seed0, baseot_cap);
		prg.random_block(baseot_seed1, baseot_cap);
		ot->send(baseot_seed0, baseot_seed1, baseot_cap);
		baseot_size = 0;

		for(int j = 0; j < G; ++j) {
			if(!E[j]) {
				io->set_key(nullptr);
				prgs[j].reseed(&keyorseed[j], PRF_R);
				prgs[j].random_block(&R[j*n1], n1);
				io->recv_block_enc(tmp, n1);
				io->recv_block_enc(tmp, n1);
			} else {
				io->set_key(&keyorseed[j]);
				io->recv_block_enc(&R[j*n1], n1);
				io->recv_block_enc(&A[j*n1], n1);
			}
		}
		cot->open();

		uint8_t * permute = new uint8_t[n1];
		block tmp2[2];
		block out[2][2];
		block out2[2][2];
		for(int j = 0; j < G; ++j) {
			if(!E[j]) {
				prgs[j].reseed(&keyorseed[j], PRF_PERMUTE);
				prgs[j].random_data(permute, n1);
				for(int i = 0; i < n1; ++i) {
					tmp2[0] = R[j*n1+i];
					tmp2[1] = A[j*n1+i];
					prp.H<2>(out[0], tmp2, i*2);

					tmp2[0] = xorBlocks(tmp2[0], X0xorX1[i]);
					tmp2[1] = xorBlocks(tmp2[1], gc_delta[j]);
					prp.H<2>(out[1], tmp2, i*2);

					int ind = permute[i]%2;
					io->recv_block(out2[ind], 2);
					io->recv_block(out2[1-ind], 2);
					if ( (!block_cmp(out[0], out2[0], 2)) or
							(!block_cmp(out[1], out2[1], 2)) ) {
						error("invalid check commitments!");
					}
				}
			} else {
				for(int i = 0; i < n1; ++i) {
					tmp2[0] = xorBlocks(R[j*n1+i], X0[i]);
					tmp2[1] = A[j*n1+i];
					prp.H<2>(out[0], tmp2, i*2);

					io->recv_block(out2[0], 2);
					io->recv_block(out2[1], 2);
					if( (!block_cmp(out[0], out2[0], 2)) and
							(!block_cmp(out[0], out2[1], 2))) {
						error("invalid eval commitments!");
					}
				}
			}
		}
		delete[] X0xorX1;
		delete[] tmp;
		delete[] permute;
	}
	void gcAlice(void * f) {
		io->recv_data(E, G);
		io->recv_block(keyorseed, G);
		for(int j = 0; j < G; ++j) {
			if(E[j]) {
				if(!block_cmp(&keyorseed[j], &key[j], 1)) {
					error("bad key!");
				}
			} else {
				if(!block_cmp(&keyorseed[j], &seed[j], 1)) {
					error("bad seed!");
				}
			}
		}

		vector<future<void>> futures;
		int s =0;
		for(int j = 0; j < G; ++j) {
			if (E[j]) {
				futures.push_back(pool->enqueue(&Malicious2PC::OnlineGarble, this, s, f, j));
				++s;
			}
		}
		for(size_t j = 0; j < futures.size(); ++j) {
			futures[j].get();//thds[j].join();
		}
	}
	void OnlineGarble(int id, void *f, int j) {
		block * Bp = scratch[id]+n2;
		block * B_loc = scratch[id];
		for(int i = 0; i < n2; ++i)
				B_loc[i] = B[i*G+j];
		if (party == ALICE) {
			HalfGateGen<NetIO, rt> gc(ioes[id]);
			gc.set_delta(gc_delta[j]);
			local_gc = &gc;
			xortree->circuit(Bp, B_loc);
			run_function(f, &Z[j*n3], &A[j*n1], Bp);
			ioes[id]->send_block((block *)T[j*n3], 2*n3);
		} else {
			char dgst[20];
			HashIO hashio(ioes[id]);
			HalfGateEva<HashIO,rt> gc(&hashio);
			local_gc = &gc;
			xortree->circuit(Bp, B_loc);
			run_function(f, &Z[j*n3], &A[j*n1], Bp);

			hashio.get_digest(dgst);
			if(memcmp(dgst, hashGC[j], 20)!= 0) {
				error("bad GC commitment!");
			}
			ioes[id]->recv_block((block *)T[j*n3], 2*n3);
			Hash::hash_once(dgst, T[j*n3], sizeof(block)*2*n3);
			if(memcmp(dgst, comT[j], 20)!=0) {
				error("bad comT");
			}
		}
		ioes[id]->flush();
	}

	void gcBob(void * f, bool * output) {
		block * recovered_delta = new block[n3];
		bool * output_set = new bool[n3];
		memset(output_set, false, n3);


		io->send_data(E, G);
		io->send_block(keyorseed, G);	
		io->flush();
		vector<future<void>> futures;
		int s =0;

		for(int j = 0; j < G; ++j)
			if (E[j]) {
				futures.push_back(pool->enqueue( &Malicious2PC::OnlineGarble, this, s, f, j));
				++s;
			}
		for(size_t j = 0; j < futures.size(); ++j) {
			futures[j].get();
		}

		for(int j = 0; j < G; ++j) {
			if (E[j]) {
				for(int i = 0; i < n3; ++i) {
					block result[2], result2[2];
					memcpy(result, T[j*n3+i], sizeof(block)*2);
					result[0] = xorBlocks(result[0], prp.H(Z[j*n3+i], i));
					result[1] = xorBlocks(result[1], prp.H(Z[j*n3+i], i));

					prp.H<2>(result2, result, i*2);
					if(block_cmp(&H[i][0], &result2[0], 1)) {
						output[i] = false;
						if(!output_set[i])
							recovered_delta[i] =  result[0];
						else if(output[i] == true) {
							Omega = xorBlocks(recovered_delta[i], result[0]);
							omega_set = true;
						}
					}
					else if(block_cmp(&H[i][1], &result2[1], 1)) {
						output[i] = true;
						if(!output_set[i])
							recovered_delta[i] =  result[1];
						else if(output[i] == false) {
							Omega = xorBlocks(recovered_delta[i], result[1]);
							omega_set = true;
						}
					}
				}
			}
		}

		delete[] output_set;
		delete[] recovered_delta;
	}

	void recoverAlice() {
		io->recv_data(E,G);
		io->recv_block(keyorseed,G);
		for(int i = 0; i < G; ++i) {
			if(E[i]) {
				if(!block_cmp(&keyorseed[i], &key[i], 1))
					error("bad E!");
			} else {
				if(!block_cmp(&keyorseed[i], &seed[i], 1))
					error("bad E!");
			}
		}
		cot->setup_send(baseot_seed0+baseot_size, baseot_sel+baseot_size);
		baseot_size += ot->l;
		ot->setup_send(baseot_seed0+baseot_size, baseot_sel+baseot_size);
		baseot_size += ot->l;

		kot->open_sender(delta_bool, seed, E, ot, cot);
		io->send_block(Delta0, n3);
	}

	void recoverBob(bool * alice = nullptr) {
		io->send_data(E, G);
		io->send_block(keyorseed, G);
		bool *omega_bool = new bool[128];
		//		MOTExtension ot2(io), cot2(io, true);
		block_to_bool(omega_bool, Omega);
		cot->setup_recv(baseot_seed0+baseot_size, baseot_seed1+baseot_size);
		baseot_size+=ot->l;
		ot->setup_recv(baseot_seed0+baseot_size, baseot_seed1+baseot_size);
		baseot_size+=ot->l;

		kot->open_recver(delta_bool, omega_bool, seed, E, ot, cot);
		Delta = bool_to128(delta_bool);

		io->recv_block(Delta0, n3);
		bool * alice_input = new bool[n1];
		char h2[20];
		block * tmp = new block[n1];
		for(int j = 0; j < G; ++j) {
			if(!E[j]) {
				computeTranslationTable(h2, j);
				if(memcmp(h2, comT[j],20)!=0) {
					error("bad T!");
				}
			} else {
				if(omega_set) {
					prgs[j].reseed(&seed[j], PRF_R);
					prgs[j].random_block(tmp, n1);
					for(int i = 0; i < n1; ++i) {
						block RR[2];
						RR[0] = xorBlocks(tmp[i], X0[i]);
						RR[1] = xorBlocks(tmp[i], X1[i]);
						if(block_cmp(&RR[0], &R[j*n1+i],1))
							alice_input[i] = 0;
						if(block_cmp(&RR[1], &R[j*n1+i],1))
							alice_input[i] = 1;
					}
				}
			}
		}
		if(alice!= nullptr)
			memcpy(alice, alice_input, n1);
		delete[] alice_input;
		delete[] tmp;
		delete[] omega_bool;
	}
};
#endif// MALICIOUS_H__

