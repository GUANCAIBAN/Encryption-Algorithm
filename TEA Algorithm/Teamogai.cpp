/*
魔改TEA
虎符CTF2022的题目 the_shellcode
其中有一个是魔改的TEA，和一个base变换
*/

#include <stdio.h>
#include <stdint.h>
#include <cstdint>

#define DELTA 0x9e3779b9
// 魔改了这里的>>5成了>>6
#define MX (((z>>6^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z))) 
#define ROR(x, n) (((x) >> n) & 0xFF) | ((x) << (8 - n) & 0xFF)

// 题目中的码表
char baseTable[] =
{
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x3E, 0x42, 0x42, 0x42, 0x3F, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x42, 0x42,
  0x42, 0x41, 0x42, 0x42, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x1A, 0x1B, 0x1C,
  0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
  0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
  0x31, 0x32, 0x33, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  0x42, 0x42, 0x42, 0x42, 0x42, 0x42
};

void xxteaDecode(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n < -1)      /* Decoding Part */
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

int FindIndex(int x)
{
    int i;

    for (i = 0; i < 256; i++)
        if (baseTable[i] == x)
            return i;
}

void BaseDecode(unsigned char* flag, int len, unsigned char* input)
{
    int i, j;

    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        input[j] = (flag[i] >> 2) & 0x3F;
        input[j + 1] = ((flag[i] & 0x3) << 4) | (flag[i + 1] & 0xF0) >> 4;
        input[j + 2] = ((flag[i + 1] & 0xF) << 2) | (flag[i + 2] & 0xC0) >> 6;
        input[j + 3] = flag[i + 2] & 0x3F;
    }
    for (i = 0; i < len / 3 * 4; i++)
        input[i] = FindIndex(input[i]);
}

int main()
{
    // 数据的写法，一直没弄过来
    uint32_t v[] =
    {
        0x4B6B89A1, 0x74C15453, 0x4092A06E, 0x429B0C07, 0x40281E84, 0x8B5B44C9, 0x66FEB37B, 0x3C77A603,
        0x79C5892D, 0x0D7ADA97, 0x1D51AA56, 0x02D4D703, 0x4FA526BA, 0x32FAD64A, 0x0C0F6091, 0x562B7593,
        0xDB9ADD67, 0x76165563, 0xA5F79315, 0x3AEB991D, 0x1AB721D4, 0xAACD9D2C, 0x825C2B27, 0x76A7761A,
        0xB4005F18, 0x117F3763, 0x512CC540, 0xC594A16F, 0xD0E24F8C, 0x9CA3E2E9, 0x0A9CC2D5, 0x4629E61D,
        0x637129E3, 0xCA4E8AD7, 0xF5DFAF71, 0x474E68AB, 0x542FBC3A, 0xD6741617, 0xAD0DBBE5, 0x62F7BBE3,
        0xC8D68C07, 0x880E950E, 0xF80F25BA, 0x767A264C, 0x9A7CE014, 0x5C8BC9EE, 0x5D9EF7D4, 0xB999ACDE,
        0xB2EC8E13, 0xEE68232D, 0x927C5FCE, 0xC9E3A85D, 0xAC74B56B, 0x42B6E712, 0xCD2898DA, 0xFCF11C58,
        0xF57075EE, 0x5076E678, 0xD4D66A35, 0x95105AB9, 0x1BB04403, 0xB240B959, 0x7B4E261A, 0x23D129D8,
        0xF5E752CD, 0x4EA78F70
    };
    uint32_t const k[4] = { 116, 111, 114, 97 }; // 密钥
    int n = 66;
    int i;

    xxteaDecode(v, -n, k);
    for (i = 0; i < 66; i++)
        printf("0x%X, ", v[i]);

    puts("\n");

    unsigned char* t = (unsigned char*)v;
    unsigned char baseCode[66 * 4];

    for (i = 0; i < 66 * 4; i++)
    {
        baseCode[i] = ROR(t[i], 3);
        printf("0x%X, ", baseCode[i]);
    }

    puts("\n");

    char input[352];
    BaseDecode(baseCode, 66 * 4, input);
    for (i = 0; i < 352; i++) {
        printf("%c", input[i]);
    }
    //YPxoTHcmBzPSZItSMItSDItSFItyKA+3SiYz/zPArDxhfAIsIMHPDQP44vBSV4tSEItCPAPCi0B4hcAPhL4AAAADwlCLSBiLWCAD2oP5AA+EqQAAAEmLNIsD8jP/M8Cswc8NA/g6xHX0A3wkBDt8JAx12TP/M8mDwlAPtgQKwc8NA/hBg/kOdfHBzw1XM/8zyYtUJDxSD7YcDrhnZmZm9+vR+ovCwegfA8KNBIAr2FoPtgQKK8PBzw0D+EGD+Q511MHPDTs8JHQWaCVzAACLxGhubwAAVFCLXCRI/9PrFGglcwAAi8RoeWVzAFRQi1wkSP/TWFhYWFhYWFhYYcNYX1qLEukL////

    return 0;
}