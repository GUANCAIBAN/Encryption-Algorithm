/*
Salsa20是一种流式对称加密算法（流就是逐位加密，），类似于Chacha20，算法性能相比AES能够快3倍，在其官方网站上也是强调速度
https://cr.yp.to/salsa20.html

随机字节流和xor操作实现加解密，其中随机字节流很关键

*/

#include<iostream>
#include "Salsa20.h"

void setIVVector(const unsigned char* vector)
{
    if (vector == nullptr)
        return;

    m_vector[6] = convert(&vector[0]);
    m_vector[7] = convert(&vector[4]);
    m_vector[8] = m_vector[9] = 0;
}

void setKey(const unsigned char* key)
{
    static const char constants[] = "expand 32-byte k";

    if (key == nullptr)
        return;

    m_vector[0] = convert(reinterpret_cast<const unsigned char*>(&constants[0]));
    m_vector[1] = convert(&key[0]);
    m_vector[2] = convert(&key[4]);
    m_vector[3] = convert(&key[8]);
    m_vector[4] = convert(&key[12]);
    m_vector[5] = convert(reinterpret_cast<const unsigned char*>(&constants[4]));

    m_vector[6] = m_vector[7] = m_vector[8] = m_vector[9] = 0;

    m_vector[10] = convert(reinterpret_cast<const unsigned char*>(&constants[8]));
    m_vector[11] = convert(&key[16]);
    m_vector[12] = convert(&key[20]);
    m_vector[13] = convert(&key[24]);
    m_vector[14] = convert(&key[28]);
    m_vector[15] = convert(reinterpret_cast<const unsigned char*>(&constants[12]));
}

unsigned int rotate(unsigned int value,unsigned int numBits) 
{
	return (value << numBits) | (value >> (32 - numBits));
}

unsigned int convert(const unsigned char* array)
{
	return ((static_cast<unsigned int>(array[0]) << 0) |
		(static_cast<unsigned int>(array[1]) << 8) |
		(static_cast<unsigned int>(array[2]) << 16) |
		(static_cast<unsigned int>(array[3]) << 24));
}

void convert(unsigned int value,unsigned char *array)
{
    array[0] = static_cast<unsigned char>(value >> 0);
    array[1] = static_cast<unsigned char>(value >> 8);
    array[2] = static_cast<unsigned char>(value >> 16);
    array[3] = static_cast<unsigned char>(value >> 24);
}


void generateKeyStream(unsigned char out[])  // 关键的随机密钥流产生
{
    unsigned int x[VECTOR_SIZE];

    for (size_t idx = 0; idx < VECTOR_SIZE; idx++)
        x[idx] = m_vector[idx];

    for (size_t i = 20; i > 0; i -= 2)
    {
        x[4] ^= rotate(static_cast<unsigned int>(x[0] + x[12]), 7);
        x[8] ^= rotate(static_cast<unsigned int>(x[4] + x[0]), 9);
        x[12] ^= rotate(static_cast<unsigned int>(x[8] + x[4]), 13);
        x[0] ^= rotate(static_cast<unsigned int>(x[12] + x[8]), 18);
        x[9] ^= rotate(static_cast<unsigned int>(x[5] + x[1]), 7);
        x[13] ^= rotate(static_cast<unsigned int>(x[9] + x[5]), 9);
        x[1] ^= rotate(static_cast<unsigned int>(x[13] + x[9]), 13);
        x[5] ^= rotate(static_cast<unsigned int>(x[1] + x[13]), 18);
        x[14] ^= rotate(static_cast<unsigned int>(x[10] + x[6]), 7);
        x[2] ^= rotate(static_cast<unsigned int>(x[14] + x[10]), 9);
        x[6] ^= rotate(static_cast<unsigned int>(x[2] + x[14]), 13);
        x[10] ^= rotate(static_cast<unsigned int>(x[6] + x[2]), 18);
        x[3] ^= rotate(static_cast<unsigned int>(x[15] + x[11]), 7);
        x[7] ^= rotate(static_cast<unsigned int>(x[3] + x[15]), 9);
        x[11] ^= rotate(static_cast<unsigned int>(x[7] + x[3]), 13);
        x[15] ^= rotate(static_cast<unsigned int>(x[11] + x[7]), 18);
        x[1] ^= rotate(static_cast<unsigned int>(x[0] + x[3]), 7);
        x[2] ^= rotate(static_cast<unsigned int>(x[1] + x[0]), 9);
        x[3] ^= rotate(static_cast<unsigned int>(x[2] + x[1]), 13);
        x[0] ^= rotate(static_cast<unsigned int>(x[3] + x[2]), 18);
        x[6] ^= rotate(static_cast<unsigned int>(x[5] + x[4]), 7);
        x[7] ^= rotate(static_cast<unsigned int>(x[6] + x[5]), 9);
        x[4] ^= rotate(static_cast<unsigned int>(x[7] + x[6]), 13);
        x[5] ^= rotate(static_cast<unsigned int>(x[4] + x[7]), 18);
        x[11] ^= rotate(static_cast<unsigned int>(x[10] + x[9]), 7);
        x[8] ^= rotate(static_cast<unsigned int>(x[11] + x[10]), 9);
        x[9] ^= rotate(static_cast<unsigned int>(x[8] + x[11]), 13);
        x[10] ^= rotate(static_cast<unsigned int>(x[9] + x[8]), 18);
        x[12] ^= rotate(static_cast<unsigned int>(x[15] + x[14]), 7);
        x[13] ^= rotate(static_cast<unsigned int>(x[12] + x[15]), 9);
        x[14] ^= rotate(static_cast<unsigned int>(x[13] + x[12]), 13);
        x[15] ^= rotate(static_cast<unsigned int>(x[14] + x[13]), 18);
    }
    for (size_t i = 0; i < VECTOR_SIZE; ++i)
    {
        x[i] += m_vector[i];
        convert(x[i], &out[4 * i]);
    }

    ++m_vector[8];
    m_vector[9] += m_vector[8] == 0 ? 1 : 0;

}
// 参数 原数据 加密后的目标数据 
void encrypt_message(const char* p_src, char* p_dest, size_t data_size)
{
    unsigned char keyStream[BLOCK_SIZE];
    size_t numBytesToProcess = 0;

    while (data_size != 0)
    {
        generateKeyStream(keyStream); // 产生随机字节流
        numBytesToProcess = ((data_size >= BLOCK_SIZE) ? BLOCK_SIZE : data_size);
        
        for (size_t idx = 0; idx < numBytesToProcess; idx++)
        {
            *(p_dest++) = keyStream[idx] ^ *(p_src++);  // 这里就用上 随机字节流 xor 
        }
    }
}

void decrypt_message(const char* p_src, char* p_dest, size_t data_size)
{
    unsigned char keyStream[BLOCK_SIZE];
    size_t numBytesToProcess = 0;

    while (data_size != 0)
    {
        generateKeyStream(keyStream); // 产生随机字节流
        numBytesToProcess = ((data_size >= BLOCK_SIZE) ? BLOCK_SIZE : data_size);

        for (size_t idx = 0; idx < numBytesToProcess; idx++)
        {
            *(p_dest++) = keyStream[idx] ^ *(p_src++);  // 最后一步是xor 加解密并无区别
        }
    }
}

int main() 
{
    char* s; 
    char sa[18]  = "abcdefghijilkyoui";
    s = sa;
    char* d;
    char dd[17] = "";
    d = dd;
    encrypt_message(s, d, 17);
    printf("%s", d);

}