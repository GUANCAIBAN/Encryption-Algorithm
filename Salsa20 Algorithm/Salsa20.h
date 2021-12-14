#pragma once

#define IV_SIZE  8
#define VECTOR_SIZE 16
#define KEY_SIZE  32
#define BLOCK_SIZE  64
#define READ_BLOCK_SIZE  4096
unsigned int m_vector[VECTOR_SIZE];

unsigned int rotate(unsigned int value, unsigned int numBits); // 一个关键函数
void convert(unsigned int value,unsigned char *array);  // int 转 char
unsigned int convert(const unsigned char *array);
void generateKeyStream(unsigned char out[BLOCK_SIZE]); // 关键的随机字节流


void setIVVector(const unsigned char* vector);
void setKey(const unsigned char* key);

void encrypt_message(const char* p_src, char* p_dest, size_t data_size);
void decrypt_message(const char* p_src, char* p_dest, size_t data_size);

