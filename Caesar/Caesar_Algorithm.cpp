/*
字母表一共有26个英文字母，我们选择凯撒密码实现一个加密时，我们需要将某个明文字母做N位偏移得到密文，这个N最多为26，
而且偏移为26时和偏移为0时一样，明文和密文对应相等，实际上可以说最大的偏移量为25，
这里的偏移量是这个加密解密算法的核心，即秘钥
*/
#include <iostream>
#include <string>
#include <stdlib.h>
void Encrypt(std::string& text, int shift) 
{
	using namespace std;
	int length = text.length();
	for (int i = 0; i < length; i++)
	{   // 都不用提供字母表，直接按ascii码表的顺序，可以直接进行替换，shift就是key，即加密者所确定的移位
		if (text[i] >='A' && text[i]<='Z')
		{
			text[i] = (text[i] + shift > 'Z') ? (text[i] + shift) - 26 : (text[i] + shift);
		}
		else if (text[i] >= 'a' && text[i] <= 'z')
		{
			text[i] = (text[i] + shift > 'z') ? (text[i] + shift) - 26 : (text[i] + shift);
		}
	}
}

void Decrypt(std::string& text, int shift)
{
	using namespace std;
	int length = text.length();
	for (int i = 0; i < length; i++) {
		if (text[i] >= 'A' && text[i] <= 'Z')
			text[i] = (text[i] - shift < 'A') ? (text[i] - shift) + 26 : (text[i] - shift);
		else if (text[i] >= 'a' && text[i] <= 'z')
			text[i] = (text[i] - shift < 'a') ? (text[i] - shift) + 26 : (text[i] - shift);
	}
}

int main(int argc, char* argv[]) {
    using namespace std;

    // check arguments
    if (argc != 3) {
        cout << "Not enough arguments.\n./cipher -direction <shift amount>\n";
        cout << "-direction\n\t-e: Encrypt\n\t-d: Decrypt\n";
        return 1;
    }

    // check direction
    int direction = 0;
    if (strcmp(argv[1], "-e") == 0)
        direction = 1;
    else if (strcmp(argv[1], "-d") == 0)
        direction = -1;
    else {
        cout << "Invalid direction.\n";
        return 2;
    }

    // convert shift amount to an integer
    int shift = atoi(argv[2]);

    // get string to encrypt
    string text;
    cout << "> ";
    getline(cin, text);

    if (direction == 1)
        Encrypt(text, shift);
    else  // if(direction == -1)
        Decrypt(text, shift);

    cout << text << endl;

    return 0;
}