

// 几个加密算法 其中Tea和XTea是理解的，XXTea（即btea）相对不理解
void TeaDecrypt(unsigned int* v, unsigned int* key);
void TeaEncrypt(unsigned int* v, unsigned int* key);
void XTeaEncrypt(unsigned int* v, unsigned int* key);
void XTeaDecrypt(unsigned int* v, unsigned int* key);
bool btea(unsigned int* v, int n, unsigned int* k);