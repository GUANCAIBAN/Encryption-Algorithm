#include <stdio.h>
#include <stdbool.h>
#include <stdint.h> 
#include <string.h>
#include <iostream>

using namespace std;

void TeaEncrypt(unsigned int* v, unsigned int* key) {
	// ����ͼ��һ�飬�����������
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;  // �̶����� �㷨����
	for (size_t i = 0; i < 32; i++)  // 32�ε�������������������ܣ�����64��
	{
		sum += delta;
		v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
		v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
	}
	v[0] = v0; // ���ս����ֵ
	v[1] = v1;
}

void TeaDecrypt(unsigned int* v, unsigned int* key) {
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;
	// ���ܲ������������Ӻ�߿�ʼִ�У�����ʲô������ȥ�Ϳ�����
	v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
	v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
	sum -= delta;
}

//void XTeaEncrypt(unsigned int* v, unsigned int* key) {
//	unsigned int v0 = v[0],
//		v1 = v[1],
//		sum = 0,
//		delta = 0x9e3779b9;  // �̶����� �㷨����
//	for (size_t i = 0; i < 32; i++)
//	{
//		
//		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]); // subkey 
//		//                                                           ����ⲿ�ֵ���ͼӦ�û���Ҫ��������
//		sum += delta; // �����м���
//		v1 += (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11] & 3);
//	}
//	v[0] = v0;
//	v[1] = v1;
//}

//void XTeaDecrypt(unsigned int* v, unsigned int* key) {
//	unsigned int v0 = v[0],
//		v1 = v[1],
//		sum = 0,
//		delta = 0x9e3779b9;  // �̶����� �㷨����
//	for (size_t i = 0; i < 32; i++)
//	{
//
//		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11] & 3); // subkey 
//		//                                                           ����ⲿ�ֵ���ͼӦ�û���Ҫ��������
//		sum -= delta; // �����м���
//		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
//	}
//	v[0] = v0;
//	v[1] = v1;
//}
// �����е�һ����ֱ��define��
// ���û������Ǹ�ͼ���Ǹ�ͼ�Ƚ��鷳������������˵Ŷ ����һЩ���ֵı仯�᲻ͬ�ɡ�

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
// �����ħ�ĵ��㷨��Ȼ������ֱ���õ�
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
{	// vΪҪ���ܵ�����������32λ�޷�������  v�ĸ���Ӱ������n  ����v���м���n
    // kΪ���ܽ�����Կ��Ϊ4��32λ�޷�������������Կ����Ϊ128λ 
	// test - 
//	unsigned int v[] = { 0x5c, 0xab, 0x3c, 0x99,  0x29, 0xe1, 0x40, 0x3f,
//						 0xde, 0x91, 0x77, 0x77,  0xa6, 0xfe, 0x7d, 0x73, 
//						 0xe6, 0x59, 0xcf, 0xec,  0xe3, 0x4c, 0x60, 0xc9, 
//						 0xa5, 0xc0, 0x82, 0x96,  0x1e, 0x2a, 0x6f, 0x55,
//0 }, key[4] = { 14000, 79894, 16, 123123 };
//	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int�����ʽ
//	//TeaEncrypt(v, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	//TeaDecrypt(v, key);
//	//printf("%u,%u\n", v[0], v[1]);
//	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int�����ʽ
//	// XTeaEncrypt(v, key);			// �⴦���㷨�е��쳣�������������
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

	// XXTEA�Ľ���ʾ�� ֮ǰ�Ĵ��벻֪���������⣬��������
	/*uint8_t enc_data[] = { 0x5c, 0xab, 0x3c, 0x99, 0x29, 0xe1, 0x40, 0x3f,
0xde, 0x91, 0x77, 0x77, 0xa6, 0xfe, 0x7d, 0x73, 0xe6, 0x59, 0xcf, 0xec,
0xe3, 0x4c, 0x60, 0xc9, 0xa5, 0xc0, 0x82, 0x96, 0x1e, 0x2a, 0x6f, 0x55,
0 };
	uint32_t key[] = { 14000, 79894, 16, 123123 };

	mogaiXXTeaDecrypt(8, (uint32_t*)enc_data, key);*/

	// puts((char*)enc_data); //9b34a61df773acf0e4dec25ea5fb0e29 

	// �±����ҵ���һ��btea��ʹ�õ����ӣ����㷨���������ı� ����𰸴�
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