#include <cctype>
#include <iostream>
#include <string>

/**
 * \brief	Apply the ROT13 algorithm to a string.
 * \param source Source text to apply the algorithm to.
 * \return	The transformed text is returned.
 *
 * ���ǿ����ı���
ROT5��ֻ�����ֽ��б��룬��������ǰ���ĵ�5�������滻��ǰ���֣����統ǰΪ0���������5����ǰΪ1���������6��

ROT13��ֻ����ĸ���б��룬����ĸ��ǰ���ĵ�13����ĸ�滻��ǰ��ĸ�����統ǰΪA���������N����ǰΪB���������O��

ROT18����ROT5��ROT13�����һ������ΪROT18��

ROT47�������֡���ĸ�����÷��Ž��б��룬��ASCIIֵ����λ���滻�����ַ�ASCIIֵ��ǰ���ĵ�47λ��Ӧ�ַ��滻��ǰ�ַ������統ǰΪСд��ĸz��������ɴ�д��ĸK����ǰΪ����0��������ɷ���_������ROT47������ַ���ASCIIֵ��Χ��33��126������ο�ASCII���롣
 */
std::string ROT13(std::string source)
{
	std::string transformed;
	for (size_t i = 0; i < source.size(); ++i) { // û�б��룬��13�ļӼ�
		if (isalpha(source[i])) {
			if ((tolower(source[i]) - 'a') < 14)
				transformed.append(1, source[i] + 13);
			else
				transformed.append(1, source[i] - 13);
		}
		else {
			transformed.append(1, source[i]);
		}
	}
	return transformed;
}

std::string ROT47(std::string s)
{
	// ��һ�ѱ����������
	std::string s1 = "!\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	std::string s2 = "PQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO";

	std::string ret = "";
	for (unsigned int i = 0; i < s.size(); i++)
	{
		std::size_t pos = s1.find(s[i]);
		ret += s2[pos];
	}

	return ret;
}

int main()
{
	std::string source,source1;
	std::cout << "Enter the source text: " << std::flush;
	std::getline(std::cin, source);
	std::cout << "Result: " << ROT13(source) << std::endl;
	std::cout << "Enter the source text: " << std::flush;
	std::getline(std::cin, source1);
	std::cout << "Result: " << ROT47(source1) << std::endl;
	return 0;
}