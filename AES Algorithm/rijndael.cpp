#include "rijndael.h"

/*
 * nr: number of rounds  轮数
 * nb: number of columns comprising the state, nb = 4 dwords (16 bytes) 
 * nk: number of 32-bit words comprising cipher key, nk = 4, 6, 8 (KeyLength/(4*8))
 */
// 在AES中，state初始状态表的分组大小固定4个一组
int g_aes_nb[] = {
	/* AES_CYPHER_128 */ 4,
	/* AES_CYPHER_192 */ 4,
	/* AES_CYPHER_256 */ 4
};

// 轮函数的循环次数会因为state的长度不同，会变
int g_aes_rounds[] = {
	/* AES_CYPHER_128 */ 10,
	/* AES_CYPHER_192 */ 12,
	/* AES_
	CYPHER_256 */ 14
};
int g_aes_nk[] = {
	/* AES_CYPHER_128 */  4,
	/* AES_CYPHER_192 */  6,
	/* AES_CYPHER_256 */  8,
};
uint8_t aes_xtime(uint8_t x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
uint8_t aes_xtimes(uint8_t x, int ts)
{
	while (ts-- > 0) {
		x = aes_xtime(x);
	}

	return x;
}

uint32_t aes_swap_dword(uint32_t val)
{
	return (((val & 0x000000FF) << 24) |
		((val & 0x0000FF00) << 8) |
		((val & 0x00FF0000) >> 8) |
		((val & 0xFF000000) >> 24));
}
uint32_t aes_sub_dword(uint32_t val)
{
	uint32_t tmp = 0;

	tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 0) & 0xFF))) << 0;
	tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 8) & 0xFF))) << 8;
	tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 16) & 0xFF))) << 16;
	tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 24) & 0xFF))) << 24;

	return tmp;
}
/*
 * aes Rcon:
 *
 * WARNING: Rcon is designed starting from 1 to 15, not 0 to 14.
 *          FIPS-197 Page 9: "note that i starts at 1, not 0"
 *
 * i    |   0     1     2     3     4     5     6     7     8     9    10    11    12    13    14
 * -----+------------------------------------------------------------------------------------------
 *      | [01]  [02]  [04]  [08]  [10]  [20]  [40]  [80]  [1b]  [36]  [6c]  [d8]  [ab]  [4d]  [9a]
 * RCON | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 */

static const uint32_t g_aes_rcon[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000
};
uint8_t aes_mul(uint8_t x, uint8_t y)
{
	/*
	 * encrypt: y has only 2 bits: can be 1, 2 or 3
	 * decrypt: y could be any value of 9, b, d, or e
	 */

	return (
		(((y >> 0) & 1) * aes_xtimes(x, 0)) ^
		(((y >> 1) & 1) * aes_xtimes(x, 1)) ^
		(((y >> 2) & 1) * aes_xtimes(x, 2)) ^
		(((y >> 3) & 1) * aes_xtimes(x, 3)) ^
		(((y >> 4) & 1) * aes_xtimes(x, 4)) ^
		(((y >> 5) & 1) * aes_xtimes(x, 5)) ^
		(((y >> 6) & 1) * aes_xtimes(x, 6)) ^
		(((y >> 7) & 1) * aes_xtimes(x, 7)));
}
uint8_t aes_sub_sbox(uint8_t val)
{
	return g_aes_sbox[val];
}

uint32_t aes_rot_dword(uint32_t val)
{
	uint32_t tmp = val;

	return (val >> 8) | ((tmp & 0xFF) << 24);
}

void aes_dump(const char* msg, uint8_t* data, int len)
{
	int i;
	printf("%8.8s:", msg);
	for (i = 0; i < len; i++) {
		printf(" %2.2x", data[i]);
	}
	printf("\n");
}

// 4*4的state，与S盒一一对应(state的某个位置的值，是S盒的索引)，进行替换
void aes_sub_bytes(AES_CYPHER_T mode, uint8_t* state) {
	int i, j;
	for (i = 0; i < g_aes_nb[mode]; i++)
	{
		for ( j = 0; j < 4; j++)
		{
			state[j + i * 4] = aes_sub_sbox(state[j + i * 4]);
		}
	}
}

// 行位移，左移，0行左移0 以此类推
void aes_shift_rows(AES_CYPHER_T mode, uint8_t* state) {
	uint8_t* s = state;
	int i, j, r;

	for ( i = 0; i < g_aes_nb[mode]; i++)
	{
		for ( j = 0; j < i; j++)
		{
			uint8_t tmp = s[i];
			for ( r = 0; r < g_aes_nb[mode]; r++)
			{
				// 二维数组只是一维数组的每一行个数乘以在当前行的具体位置
				s[i + r * 4] = s[i + (r + 1) * 4];
			}
			s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
		}
	}
}
// 列混淆：整了个表C用来跟state进行xor 和乘
void aes_mix_columns(AES_CYPHER_T mode, uint8_t* state) {
	// 常矩阵C
	uint8_t y[16] = { 2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2 };
	uint8_t s[4];
	int i, j, r;
	for ( i = 0; i < g_aes_nb[mode]; i++)
	{
		for ( r = 0; r < 4; r++)
		{
			s[r] = 0;
			for ( j = 0; j < 4; j++)
			{
				s[r] = s[r] ^ aes_mul(state[i * 4 + j], y[r * 4 + j]);
			}
		}
		for ( r = 0; r < 4; r++)
		{
			state[i * 4 + r] = s[r];
		}
	}
}
// 将轮密钥简单地与状态进行逐比特异或
void aes_add_round_key(AES_CYPHER_T mode, uint8_t* state,
	uint8_t* round, int nr) {
	uint32_t* w = (uint32_t *)round;
	uint32_t* s = (uint32_t*)state;
	int i;
	for ( i = 0; i < g_aes_nb[mode]; i++)
	{
		s[i] ^=w[nr * g_aes_nb[mode] + i];
	}
}
// 密钥扩展，对密钥操作。这个步骤也是有好几步的，但对于AES来说，
void aes_key_expansion(AES_CYPHER_T mode, uint8_t* key, uint8_t* round)
{
	uint32_t* w = (uint32_t*)round;
	uint32_t  t;
	int      i = 0;

	printf("Key Expansion:\n");
	do 
	{
		w[i] = *((uint32_t*)&key[i * 4 + 0]);
		printf("    %2.2d:  rs: %8.8x\n", i, aes_swap_dword(w[i]));
	}
	while (++i < g_aes_nk[mode]);

	do {
		printf("    %2.2d: ", i);
		if ((i % g_aes_nk[mode]) == 0) {
			t = aes_rot_dword(w[i - 1]);
			printf(" rot: %8.8x", aes_swap_dword(t));
			t = aes_sub_dword(t);
			printf(" sub: %8.8x", aes_swap_dword(t));
			printf(" rcon: %8.8x", g_aes_rcon[i / g_aes_nk[mode] - 1]);
			t = t ^ aes_swap_dword(g_aes_rcon[i / g_aes_nk[mode] - 1]);
			printf(" xor: %8.8x", t);
		}
		else if (g_aes_nk[mode] > 6 && (i % g_aes_nk[mode]) == 4) {
			t = aes_sub_dword(w[i - 1]);
			printf(" sub: %8.8x", aes_swap_dword(t));
		}
		else {
			t = w[i - 1];
			printf(" equ: %8.8x", aes_swap_dword(t));
		}
		w[i] = w[i - g_aes_nk[mode]] ^ t;
		printf(" rs: %8.8x\n", aes_swap_dword(w[i]));
	} 
	while (++i < g_aes_nb[mode] * (g_aes_rounds[mode] + 1));

	/* key can be discarded (or zeroed) from memory */
}
/// <summary>
/// 参数：
/// 1.加密模式
/// 2.加密数据
/// 3.长度
/// 4.密钥
/// </summary>
/// <returns></returns>
int aes_encrypt(AES_CYPHER_T mode,uint8_t *data,int len,uint8_t *key) {
	// 轮密钥 用户规定的初始密钥
	uint8_t w[4 * 4 * 15] = { 0 }; 
	// 初始状态state，即输入
	uint8_t s[4 * 4] = { 0 };

	int nr, i, j;

	// 密钥扩展：将用户的密钥进行生成多组轮密钥
	// 因此，对用户输入也操作，用户规定的密钥也操作，牛
	aes_key_expansion(mode, key, w);

	// 轮函数
	// 在AES种，分组大小是固定为4的
	// 而密钥长度是不同的，因此导致的轮数不同
	for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {

		// 初始化操作，即将data中的值逐个放入state中
		// 可以放在一个函数中，会根据模式不同而会有更多操作（这里是放在函数前，共通的部分都放在这一块中）
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
		{
			s[j] = data[i + j];
		}

		// 开始轮函数操作
		// nr是指不同长度下的轮数
		for (nr = 0; nr <= g_aes_rounds[mode]; nr++) {
			printf("round %d: \n", nr);
			aes_dump("input", s, 4 * g_aes_nb[mode]);

			// 当nr=0时，即首轮，就不做里边的操作了，这确实也是一种代码实现
			if (nr > 0)  // 这是中间的轮数
			{
				// 字节替换
				aes_sub_bytes(mode, s);
				aes_dump(" sub", s, 4 * g_aes_nb[mode]);
				// 行位移
				aes_shift_rows(mode, s);
				aes_dump(" shift", s, 4 * g_aes_nb[mode]);

				// 在最后一轮是不需要列混淆的，反过来说：判断是否nr小于轮数，
				// 小于的话就需要列混淆
				if (nr < g_aes_rounds[mode]) {
					// 列混淆
					aes_mix_columns(mode, s);
					aes_dump(" mix", s, 4 * g_aes_nb[mode]);
				}
			}
			// 轮密钥加
			aes_add_round_key(mode, s, w, nr);
			aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);
			aes_dump("  state", s, 4 * g_aes_nb[mode]);
		}
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
		{
			data[i + j] = s[j];
		}
		printf("Output:\n");
		aes_dump("cypher", &data[i], 4 * g_aes_nb[mode]);

	}

	return 0;
}

// ecb模式是没有什么变化的
int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t* data, int len, uint8_t* key)
{
	return aes_encrypt(mode, data, len, key);
}

// cbc模式 在前边多了部分异或操作，其他没啥
int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t* data, int len, uint8_t* key, uint8_t* iv) {
	uint8_t w[4 * 4 * 15] = { 0 };
	uint8_t s[4 * 4] = { 0 };
	uint8_t v[4 * 4] = { 0 };

	int nr, i, j;

	aes_key_expansion(mode, key, w);

	memcpy(v, iv, sizeof(v));

	for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {

		/* init state from user buffer (plaintext) */
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
			s[j] = data[i + j] ^ v[j];
		// 开始轮函数操作
	// nr是指不同长度下的轮数
		for (nr = 0; nr <= g_aes_rounds[mode]; nr++) {
			printf("round %d: \n", nr);
			aes_dump("input", s, 4 * g_aes_nb[mode]);

			// 当nr=0时，即首轮，就不做里边的操作了，这确实也是一种代码实现
			if (nr > 0)  // 这是中间的轮数
			{
				// 字节替换
				aes_sub_bytes(mode, s);
				aes_dump(" sub", s, 4 * g_aes_nb[mode]);
				// 行位移
				aes_shift_rows(mode, s);
				aes_dump(" shift", s, 4 * g_aes_nb[mode]);

				// 在最后一轮是不需要列混淆的，反过来说：判断是否nr小于轮数，
				// 小于的话就需要列混淆
				if (nr < g_aes_rounds[mode]) {
					// 列混淆
					aes_mix_columns(mode, s);
					aes_dump(" mix", s, 4 * g_aes_nb[mode]);
				}
			}
			// 轮密钥加
			aes_add_round_key(mode, s, w, nr);
			aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);
			aes_dump("  state", s, 4 * g_aes_nb[mode]);
		}
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
		{
			data[i + j] = s[j];
		}
		printf("Output:\n");
		aes_dump("cypher", &data[i], 4 * g_aes_nb[mode]);

	}

	return 0;
}
void inv_shift_rows(AES_CYPHER_T mode, uint8_t* state)
{
	uint8_t* s = (uint8_t*)state;
	int i, j, r;

	for (i = 1; i < g_aes_nb[mode]; i++) {
		for (j = 0; j < g_aes_nb[mode] - i; j++) {
			uint8_t tmp = s[i];
			for (r = 0; r < g_aes_nb[mode]; r++) {
				s[i + r * 4] = s[i + (r + 1) * 4];
			}
			s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
		}
	}
}

uint8_t inv_sub_sbox(uint8_t val)
{
	return g_inv_sbox[val];
}


void inv_sub_bytes(AES_CYPHER_T mode, uint8_t* state)
{
	int i, j;

	for (i = 0; i < g_aes_nb[mode]; i++) {
		for (j = 0; j < 4; j++) {
			state[i * 4 + j] = inv_sub_sbox(state[i * 4 + j]);
		}
	}
}

void inv_mix_columns(AES_CYPHER_T mode, uint8_t* state)
{
	uint8_t y[16] = { 0x0e, 0x0b, 0x0d, 0x09,  0x09, 0x0e, 0x0b, 0x0d,
					  0x0d, 0x09, 0x0e, 0x0b,  0x0b, 0x0d, 0x09, 0x0e };
	uint8_t s[4];
	int i, j, r;

	for (i = 0; i < g_aes_nb[mode]; i++) {
		for (r = 0; r < 4; r++) {
			s[r] = 0;
			for (j = 0; j < 4; j++) {
				s[r] = s[r] ^ aes_mul(state[i * 4 + j], y[r * 4 + j]);
			}
		}
		for (r = 0; r < 4; r++) {
			state[i * 4 + r] = s[r];
		}
	}
}

int aes_decrypt(AES_CYPHER_T mode, uint8_t* data, int len, uint8_t* key)
{
	uint8_t w[4 * 4 * 15] = { 0 }; /* round key */
	uint8_t s[4 * 4] = { 0 }; /* state */

	int nr, i, j;

	/* key expansion */
	aes_key_expansion(mode, key, w);

	/* start data cypher loop over input buffer */
	for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {

		printf("Decrypting block at %u ...\n", i);

		/* init state from user buffer (cyphertext) */
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
			s[j] = data[i + j];

		/* start AES cypher loop over all AES rounds */
		for (nr = g_aes_rounds[mode]; nr >= 0; nr--) {

			printf(" Round %d:\n", nr);
			aes_dump("input", s, 4 * g_aes_nb[mode]);

			/* do AddRoundKey */
			aes_add_round_key(mode, s, w, nr);
			aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);


			if (nr > 0) {

				if (nr < g_aes_rounds[mode]) {
					aes_dump("  mix", s, 4 * g_aes_nb[mode]);
					/* do MixColumns */
					inv_mix_columns(mode, s);
				}

				/* do ShiftRows */
				aes_dump("  shift", s, 4 * g_aes_nb[mode]);
				inv_shift_rows(mode, s);

				/* do SubBytes */
				aes_dump("  sub", s, 4 * g_aes_nb[mode]);
				inv_sub_bytes(mode, s);
			}

			aes_dump("  state", s, 4 * g_aes_nb[mode]);
		}

		/* save state (cypher) to user buffer */
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
			data[i + j] = s[j];
		printf("Output:\n");
		aes_dump("plain", &data[i], 4 * g_aes_nb[mode]);
	}

	return 0;
}

int aes_decrypt_ecb(AES_CYPHER_T mode, uint8_t* data, int len, uint8_t* key)
{
	return aes_decrypt(mode, data, len, key);
}

int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t* data, int len, uint8_t* key, uint8_t* iv)
{
	uint8_t w[4 * 4 * 15] = { 0 }; /* round key */
	uint8_t s[4 * 4] = { 0 }; /* state */
	uint8_t v[4 * 4] = { 0 }; /* iv */


	int nr, i, j;

	/* key expansion */
	aes_key_expansion(mode, key, w);

	memcpy(v, iv, sizeof(v));

	/* start data cypher loop over input buffer */
	for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {


		/* init state from user buffer (cyphertext) */
		for (j = 0; j < 4 * g_aes_nb[mode]; j++)
			s[j] = data[i + j];

		/* start AES cypher loop over all AES rounds */
		for (nr = g_aes_rounds[mode]; nr >= 0; nr--) {

			aes_dump("input", s, 4 * g_aes_nb[mode]);

			/* do AddRoundKey */
			aes_add_round_key(mode, s, w, nr);
			aes_dump("  round", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);


			if (nr > 0) {

				if (nr < g_aes_rounds[mode]) {
					aes_dump("  mix", s, 4 * g_aes_nb[mode]);
					/* do MixColumns */
					inv_mix_columns(mode, s);
				}

				/* do ShiftRows */
				aes_dump("  shift", s, 4 * g_aes_nb[mode]);
				inv_shift_rows(mode, s);

				/* do SubBytes */
				aes_dump("  sub", s, 4 * g_aes_nb[mode]);
				inv_sub_bytes(mode, s);
			}

			aes_dump("  state", s, 4 * g_aes_nb[mode]);
		}

		/* save state (cypher) to user buffer */
		for (j = 0; j < 4 * g_aes_nb[mode]; j++) {
			uint8_t p = s[j] ^ v[j];
			v[j] = data[i + j];
			data[i + j] = p;
		}
	}

	return 0;
}
void aes_cypher_128_test()
{
#if 1
	uint8_t buf[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
#else
	uint8_t buf[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
					  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
					  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif
	printf("\nAES_CYPHER_128 encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_encrypt(AES_CYPHER_128, buf, sizeof(buf), key);

	/*printf("\nAES_CYPHER_128 decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_decrypt(AES_CYPHER_128, buf, sizeof(buf), key);*/
}
void aes_cypher_192_test()
{
	uint8_t buf[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	printf("\nAES_CYPHER_192 encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_encrypt(AES_CYPHER_192, buf, sizeof(buf), key);

	printf("\nAES_CYPHER_192 decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_decrypt(AES_CYPHER_192, buf, sizeof(buf), key);
}

void aes_cypher_256_test()
{
	uint8_t buf[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
					  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	printf("\nAES_CYPHER_256 encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_encrypt(AES_CYPHER_256, buf, sizeof(buf), key);

	printf("\nAES_CYPHER_256 decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", buf, sizeof(buf));
	aes_dump("key ", key, sizeof(key));
	aes_decrypt(AES_CYPHER_256, buf, sizeof(buf), key);
}
int main() {
	aes_cypher_128_test();
	
	return 0;

}
