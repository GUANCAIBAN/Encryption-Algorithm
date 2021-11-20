/*
��ĸ��һ����26��Ӣ����ĸ������ѡ��������ʵ��һ������ʱ��������Ҫ��ĳ��������ĸ��Nλƫ�Ƶõ����ģ����N���Ϊ26��
����ƫ��Ϊ26ʱ��ƫ��Ϊ0ʱһ�������ĺ����Ķ�Ӧ��ȣ�ʵ���Ͽ���˵����ƫ����Ϊ25��
�����ƫ������������ܽ����㷨�ĺ��ģ�����Կ
*/
#include <iostream>
#include <string>
#include <stdlib.h>
void Encrypt(std::string& text, int shift) 
{
	using namespace std;
	int length = text.length();
	for (int i = 0; i < length; i++)
	{   // �������ṩ��ĸ��ֱ�Ӱ�ascii����˳�򣬿���ֱ�ӽ����滻��shift����key������������ȷ������λ
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