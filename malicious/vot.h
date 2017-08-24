#ifndef VOT_H__
#define VOT_H__

#include <emp-ot/emp-ot.h>

namespace emp {
class VOT {public:
	int ssp;
	NetIO * io;
	VOT(NetIO * io, int ssp = 40){
		this->io = io;
		this->ssp = ssp;
	}

	~VOT() {
		delete_array_null(s);
		delete_array_null(hash);
	}
	PRG prg;
	PRP prp;
	block (*s)[2][2] = nullptr;
	block (*hash)[2][2] = nullptr;

	void send(block* m0, block*m1, int length) {
		s = new block[length*ssp][2][2];
		hash = new block[length*ssp][2][2];
		block (*delta)[2] = new block[length][2];
		prg.random_block((block*)s, length*ssp*4);
		prg.random_block((block*)delta, length*2);
		for(int i = 0; i < length; ++i) {
			block tmp0 = m0[i];
			block tmp1 = xorBlocks(m1[i],delta[i][1]);
			int j = 0;
			for(; j < ssp-1; ++j) {
				tmp0 = xorBlocks(tmp0, s[i*ssp+j][0][0]);
				s[i*ssp+j][0][1] = xorBlocks(s[i*ssp+j][0][0], delta[i][0]);
				tmp1 = xorBlocks(tmp1, s[i*ssp+j][1][0]);
				s[i*ssp+j][1][1] = xorBlocks(s[i*ssp+j][1][0], delta[i][1]);
			}
			s[i*ssp+j][0][0] = tmp0;
			s[i*ssp+j][1][0] = tmp1;
			s[i*ssp+j][0][1] = xorBlocks(s[i*ssp+j][0][0], delta[i][0]);
			s[i*ssp+j][1][1] = xorBlocks(s[i*ssp+j][1][0], delta[i][1]);	
		}
		memcpy(hash, s, sizeof(block)*length*ssp*4);
		// computing hash using H(x) = Enc_IV(x)\xor x
		prp.permute_block((block *)hash, length*ssp*4);
		xorBlocks_arr((block *)hash, (block *)hash, (block *)s, length*ssp*4);
		io->send_block((block*)hash, length*ssp*4);
		delete[] delta;
	}
	void send(int length) {
		hash = new block[length*ssp][2][2];
		io->recv_block((block *)hash, length*ssp*4);
	}

	void transfer(int length, MOTExtension<NetIO>* ot) {
		block * seed0 = new block[length*ssp];
		block * seed1 = new block[length*ssp];
		prg.random_block(seed0, length*ssp);
		prg.random_block(seed1, length*ssp);
		ot->send(seed0, seed1, length*ssp);
		AES_KEY key;
		for(int i = 0; i < length; ++i) 
			for(int j = 0; j < ssp; ++j) {
				block tmp[2];
				tmp[0] = s[i*ssp+j][0][0];
				tmp[1] = s[i*ssp+j][1][0];
				AES_set_encrypt_key(seed0[i*ssp+j], &key);
				AES_ecb_encrypt_blks(tmp, 2, &key);
				io->send_block(tmp, 2);

				tmp[0] = s[i*ssp+j][0][1];
				tmp[1] = s[i*ssp+j][1][1];
				AES_set_encrypt_key(seed1[i*ssp+j], &key);
				AES_ecb_encrypt_blks(tmp, 2, &key);
				io->send_block(tmp, 2);
			}
		delete[] seed0;
		delete[] seed1;
	}
	void transfer(block * m, bool* x, int length, MOTExtension<NetIO> * ot) {
		bool * xp = new bool[length*ssp];
		block * seed = new block[length*ssp];
		prg.random_bool(xp, length*ssp);
		for(int i = 0; i < length; ++i) {
			int j = 0;
			bool tmp = x[i];
			for(; j<ssp-1; ++j) {
				tmp = (tmp != xp[i*ssp+j]);
			}
			xp[i*ssp+j] = tmp;
		}
		ot->recv(seed, xp, length*ssp);
		memset(m, 0, length*sizeof(block));
		AES_KEY key;
		for(int i = 0; i < length; ++i)
			for(int j = 0; j < ssp; ++j) {
				block tmp[2], tmp2[2];
				io->recv_block(tmp, 2);

				if(xp[i*ssp+j]) {
					io->recv_block(tmp, 2);
				} 

				AES_set_decrypt_key(seed[i*ssp+j], &key);
				AES_ecb_decrypt_blks(tmp, 2, &key);//tmp=[s_{i,0,xp[i]}, s_{i,1,xp[i]}]i
				memcpy(tmp2, tmp, 2*sizeof(block));
				prp.permute_block(tmp2, 2);
				xorBlocks_arr(tmp2, tmp2, tmp, 2);
				int index = xp[i*ssp+j]?1:0;
				if (!block_cmp(&tmp2[0], &hash[i*ssp+j][0][index], 1)
						or !block_cmp(&tmp2[1], &hash[i*ssp+j][1][index], 1)) {
					error("invalid commitment");
				}
				m[i] = xorBlocks(m[i], tmp[x[i]]);
				if(!xp[i*ssp+j]) {
					io->recv_block(tmp, 2);
				}
			}
		delete[] xp;
		delete[] seed;
	}	
	void open(int * S, int length) {
		io->send_data(S, length*sizeof(int));
		for(int i = 0; i < length; ++i) {
			if (S[i] != -1) {
				for(int j = 0; j < ssp; ++j) {
					io->send_block(s[i*ssp+j][S[i]], 2);
				}
			}
		}
	}
	bool open(int * S, block * m, int length) {
		io->recv_data(S, length*sizeof(int));
		block (*tmp1)[2] = new block[length*ssp][2];
		block (*tmp2)[2] = new block[length*ssp][2];
		for(int i = 0; i < length; ++i) {
			m[i] = zero_block();
			if (S[i] != -1) {
				for(int j = 0; j < ssp; ++j) {
					io->recv_block(tmp1[i*ssp+j], 2);
					m[i] = xorBlocks(m[i], tmp1[i*ssp+j][0]);
				}
				if(S[i] == 1)
					m[i] = xorBlocks(m[i], xorBlocks(tmp1[i*ssp][0], tmp1[i*ssp][1]));
			}
		}

		memcpy(tmp2, tmp1, length*ssp*2*sizeof(block));
		prp.permute_block((block*)tmp2, length*ssp*2);
		xorBlocks_arr((block *)tmp2, (block *)tmp2, (block *)tmp1, length*ssp*2);
		for(int i = 0; i < length; ++i) {
			if(S[i] != -1) {
			block delta = xorBlocks(tmp1[i*ssp][0], tmp1[i*ssp][1]);
			for(int j = 0; j < ssp; ++j) {
				if(!block_cmp(tmp2[i*ssp+j], hash[i*ssp+j][S[i]], 2)) {
					error("invalid commitment");
				}
				block delta2 = xorBlocks(tmp1[i*ssp+j][0], tmp1[i*ssp+j][1]);
				if(!block_cmp(&delta, &delta2, 1)) {
					error("invalid message");
				}
			}
			}
		}
		delete[] tmp1;
		delete[] tmp2;
		return true;
	}
};
}
#endif// VOT_H__