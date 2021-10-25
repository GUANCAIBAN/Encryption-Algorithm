#include <stdio.h>
#include <stdbool.h>
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

void XTeaEncrypt(unsigned int* v, unsigned int* key) {
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;  // �̶����� �㷨����
	for (size_t i = 0; i < 32; i++)
	{
		
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]); // subkey 
		//                                                           ����ⲿ�ֵ���ͼӦ�û���Ҫ��������
		sum += delta; // �����м���
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11]&3);
	}
	v[0] = v0;
	v[1] = v1;
}

void XTeaDecrypt(unsigned int* v, unsigned int* key) {
	unsigned int v0 = v[0],
		v1 = v[1],
		sum = 0,
		delta = 0x9e3779b9;  // �̶����� �㷨����
	for (size_t i = 0; i < 32; i++)
	{

		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v1) ^ (sum + key[sum >> 11] & 3); // subkey 
		//                                                           ����ⲿ�ֵ���ͼӦ�û���Ҫ��������
		sum -= delta; // �����м���
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
	}
	v[0] = v0;
	v[1] = v1;
}
// �����е�һ����ֱ��define��
// ���û������Ǹ�ͼ���Ǹ�ͼ�Ƚ��鷳������������˵Ŷ ����һЩ���ֵı仯�᲻ͬ�ɡ�
#define MX \
  ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))
bool btea(unsigned int* v, int n, unsigned int* k) {
	unsigned int z = v[n - 1], y = v[0], sum = 0, e, DELTA = 0x9e3779b9;
	unsigned int p, q;
	if (n > 1) { /* Coding Part */
		q = 6 + 52 / n;
		while (q-- > 0) {
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p = 0; p < n - 1; p++)
				y = v[p + 1], z = v[p] += MX;
			y = v[0];
			z = v[n - 1] += MX;
		}
		return 0;
	}
	else if (n < -1) { /* Decoding Part */
		n = -n;
		q = 6 + 52 / n;
		sum = q * DELTA;
		while (sum != 0) {
			e = (sum >> 2) & 3;
			for (p = n - 1; p > 0; p--)
				z = v[p - 1], y = v[p] -= MX;
			z = v[n - 1];
			y = v[0] -= MX;
			sum -= DELTA;
		}
		return 0;
	}
	return 1;
}



int main(int argc, char const* argv[])
{	// vΪҪ���ܵ�����������32λ�޷�������  
    // kΪ���ܽ�����Կ��Ϊ4��32λ�޷�������������Կ����Ϊ128λ 
	//test
	unsigned int v[2] = { 1,2 }, key[4] = { 1,2,3,4 };
	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int�����ʽ
	//TeaEncrypt(v, key);
	//printf("%u,%u\n", v[0], v[1]);
	//TeaDecrypt(v, key);
	//printf("%u,%u\n", v[0], v[1]);
	//printf("%u,%u\n", v[0], v[1]); // %u - unsigned int�����ʽ
	//XTeaEncrypt(v, key);			// �⴦���㷨�е��쳣�������������
	//printf("%u,%u\n", v[0], v[1]);
	//XTeaDecrypt(v, key);
	//printf("%u,%u\n", v[0], v[1]);
	printf("%u,%u\n", v[0], v[1]);
	btea(v, 2, key);
	printf("%u,%u\n", v[0], v[1]);
	btea(v, -2, key);
	printf("%u,%u\n", v[0], v[1]);
	return 0;
}