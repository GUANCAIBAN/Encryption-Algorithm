#include <stdio.h>
#include <stdbool.h>
#include <stdint.h> 
#include <string.h>
#include <iostream>

using namespace std;

void TeaEncrypt(unsigned int* v, unsigned int* key) {
	// 根据图走一遍，就是这个过程
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;  // 固定常量 算法特征
	for (size_t i = 0; i < 32; i++)  // 32次迭代，但里边有两个加密，所以64轮
	{
		sum += delta;
		v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
		v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
	}
	v[0] = v0; // 最终结果赋值
	v[1] = v1;
}

void TeaDecrypt(unsigned int* v, unsigned int* key) {
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;
	// 解密操作倒着来。从后边开始执行，加了什么，减回去就可以了
	v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
	v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
	sum -= delta;
}

//void XTeaEncrypt(unsigned int* v, unsigned int* key) {
//	unsigned int v0 = v[0],
//		v1 = v[1],
//		sum = 0,
//		delta = 0x9e3779b9;  // 固定常量 算法特征
//	for (size_t i = 0; i < 32; i++)
//	{
//		
//		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]); // subkey 
//		//                                                           后边这部分单看图应该还需要点其他的
//		sum += delta; // 换到中间了
//		v1 += (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11] & 3);
//	}
//	v[0] = v0;
//	v[1] = v1;
//}

//void XTeaDecrypt(unsigned int* v, unsigned int* key) {
//	unsigned int v0 = v[0],
//		v1 = v[1],
//		sum = 0,
//		delta = 0x9e3779b9;  // 固定常量 算法特征
//	for (size_t i = 0; i < 32; i++)
//	{
//
//		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11] & 3); // subkey 
//		//                                                           后边这部分单看图应该还需要点其他的
//		sum -= delta; // 换到中间了
//		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
//	}
//	v[0] = v0;
//	v[1] = v1;
//}
// 将其中的一部分直接define了
// 这个没有理解那个图，那个图比较麻烦。不过总体来说哦 都是一些部分的变化会不同吧。

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
void btea(uint32_t* v, int n, uint32_t const key[4])
{
	unsigned int DELTA = 0x9e3779b9;
	uint32_t y, z, sum;
	unsigned p, rounds, e;
	if (n > 1) /* Coding Part */
	{
		rounds = 6 + 52 / n;
		sum = 0;
		z = v[n - 1];
		do
		{
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p = 0; p < n - 1; p++)
			{
				y = v[p + 1];
				z = v[p] += MX;
			}
			y = v[0];
			z = v[n - 1] += MX;
		} while (--rounds);
	}
	else if (n < -1) /* Decoding Part */
	{
		n = -n;
		rounds = 6 + 52 / n;
		sum = rounds * DELTA;
		y = v[0];
		do
		{
			e = (sum >> 2) & 3;
			for (p = n - 1; p > 0; p--)
			{
				z = v[p - 1];
				y = v[p] -= MX;
			}
			z = v[n - 1];
			y = v[0] -= MX;
			sum -= DELTA;
		} while (--rounds);
	}
}
//#define MX \
//  ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))
//bool btea(unsigned int* v, int n, unsigned int* k) {
//	unsigned int z = v[n - 1], y = v[0], sum = 0, e, DELTA = 0x33445566;
//	unsigned int p, q;
//	if (n > 1) { /* Coding Part */
//		q = 6 + 52 / n;
//		while (q-- > 0) {
//			sum += DELTA;
//			e = (sum >> 2) & 3;
//			for (p = 0; p < n - 1; p++)
//				y = v[p + 1], z = v[p] += MX;
//			y = v[0];
//			z = v[n - 1] += MX;
//		}
//		return 0;
//	}
//	else if (n < -1) { /* Decoding Part */
//		n = -n;
//		q = 6 + 52 / n;
//		sum = q * DELTA;
//		while (sum != 0) {
//			e = (sum >> 2) & 3;
//			for (p = n - 1; p > 0; p--)
//				z = v[p - 1], y = v[p] -= MX;
//			z = v[n - 1];
//			y = v[0] -= MX;
//			sum -= DELTA;
//		}
//		return 0;
//	}
//	return 1;
//}
// 这个是魔改的算法，然后是能直接用的
void mogaiXXTeaDecrypt(int n, uint32_t* v, uint32_t const key[4])
{
	uint32_t y, z, sum;
	unsigned p, rounds, e;
	uint32_t DELTA = 0x33445566;
	rounds = 6 + 52 / n;
	sum = rounds * DELTA;
	y = v[0];
	do {
		e = (sum >> 2) & 3;
		for (p = n - 1; p > 0; p--)
		{
			z = v[p - 1];
			y = v[p] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^
				y) + (key[(p & 3) ^ e] ^ z)));
		}
		z = v[n - 1];
		y = v[0] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y)
			+ (key[(p & 3) ^ e] ^ z)));
		sum -= DELTA;
	} while (--rounds);
}



int main(int argc, char const* argv[])
{	// v为要加密的数据是两个32位无符号整数  v的个数影响轮数n  各个v就有几轮n
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位 
	// test - 
//	unsigned int v[] = { 0x5c, 0xab, 0x3c, 0x99,  0x29, 0xe1, 0x40, 0x3f,
//						 0xde, 0x91, 0x77, 0x77,  0xa6, 0xfe, 0x7d, 0x73, 
//						 0xe6, 0x59, 0xcf, 0xec,  0xe3, 0x4c, 0x60, 0xc9, 
//						 0xa5, 0xc0, 0x82, 0x96,  0x1e, 0x2a, 0x6f, 0x55,
//0 }, key[4] = { 14000, 79894, 16, 123123 };
//	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int输入格式
//	//TeaEncrypt(v, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	//TeaDecrypt(v, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int输入格式
//	// XTeaEncrypt(v, key);			// 这处的算法有点异常，可能是溢出吧
//	//printf("%u,%u\n", v[0], v[1]);
//	// XTeaDecrypt(v, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	//printf("%u,%u\n", v[0], v[1]);
//	//btea(v, 2, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	btea((uint32_t*)v, -8, key);
//	puts((char*)v);
//	getchar();
//	// printf("%x,%x\n", v[0], v[1]);

	// XXTEA的解密示例 之前的代码不知道哪有问题，先这样吧
	/*uint8_t enc_data[] = { 0x5c, 0xab, 0x3c, 0x99, 0x29, 0xe1, 0x40, 0x3f,
0xde, 0x91, 0x77, 0x77, 0xa6, 0xfe, 0x7d, 0x73, 0xe6, 0x59, 0xcf, 0xec,
0xe3, 0x4c, 0x60, 0xc9, 0xa5, 0xc0, 0x82, 0x96, 0x1e, 0x2a, 0x6f, 0x55,
0 };
	uint32_t key[] = { 14000, 79894, 16, 123123 };

	mogaiXXTeaDecrypt(8, (uint32_t*)enc_data, key);*/

	// puts((char*)enc_data); //9b34a61df773acf0e4dec25ea5fb0e29 

	// 下边是找到的一个btea的使用的例子，且算法参数有所改变 这个答案错
	uint32_t cipher[] = { 0, 0 };
	/*uint32_t enc_data[] = { 0x5cab3c99, 0x29e1403f,
0xde917777, 0xa6fe7d73, 0xe659cfec, 0xe34c60c9, 
0xa5c08296, 0x1e2a6f55,
0 };*/
	uint32_t enc_data[] = { 0x993cab5c,0x3f50e129,
0x777791de, 0x737dfea6, 0xeccf59e6, 0xc9604ce3,
0x9682c0a5, 0x556f2a1e,
0 };
	int i = 0;
	uint32_t key[] = { 14000, 79894, 16, 123123 };

	
	btea(enc_data, -8, key);
	
	puts((char*)enc_data);
	
	return 0;
}