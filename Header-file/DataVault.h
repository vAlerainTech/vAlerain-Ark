#include <iostream>
#include <chrono>
#include <string>
#include <algorithm>

class BigNumber {
private:
    std::string num;

public:
    BigNumber() : num("0") {}
    BigNumber(const std::string& str) : num(str) {}

    BigNumber operator*(const BigNumber& other) const {
        std::string result(num.length() + other.num.length(), '0');

        for (int i = num.length() - 1; i >= 0; i--) {
            int carry = 0;
            int digit1 = num[i] - '0';

            for (int j = other.num.length() - 1; j >= 0; j--) {
                int digit2 = other.num[j] - '0';
                int product = digit1 * digit2 + (result[i + j + 1] - '0') + carry;
                carry = product / 10;
                product %= 10;
                result[i + j + 1] = product + '0';
            }

            result[i] += carry;
        }

        result.erase(0, result.find_first_not_of('0'));
        return result.empty() ? BigNumber("0") : BigNumber(result);
    }
};