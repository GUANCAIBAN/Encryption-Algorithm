#include <cctype>
#include <iostream>
#include <string>

/**
 * \brief	Apply the ROT13 algorithm to a string.
 * \param source Source text to apply the algorithm to.
 * \return	The transformed text is returned.
 *
 * 都是凯撒的变种
ROT5：只对数字进行编码，将数字往前数的第5个数字替换当前数字，例如当前为0，编码后变成5，当前为1，编码后变成6。

ROT13：只对字母进行编码，将字母往前数的第13个字母替换当前字母，例如当前为A，编码后变成N，当前为B，编码后变成O。

ROT18：将ROT5和ROT13组合在一起，命名为ROT18。

ROT47：对数字、字母、常用符号进行编码，按ASCII值进行位置替换，将字符ASCII值往前数的第47位对应字符替换当前字符，例如当前为小写字母z，编码后变成大写字母K，当前为数字0，编码后变成符号_。用于ROT47编码的字符其ASCII值范围是33－126，具体参考ASCII编码。
 */
std::string ROT13(std::string source)
{
	std::string transformed;
	for (size_t i = 0; i < source.size(); ++i) { // 没有编码，有13的加减
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
	// 有一堆编码的内容在
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