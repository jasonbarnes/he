#ifndef __HE_FLOAT_H__
#define __HE_FLOAT_H__

#include <cstdlib>
#include <cstdio>
#include <deque>
#include <cmath>
#include <cstring>

#define HE_MANT 23
#define HE_EXPO 8

using namespace std;

class HE_float{
	public:
	deque<int> mant;
	deque<int> expo;
	int sign;
	int mant_bits;
	int expo_bits;
	float orig_value;
	float final_value;
	HE_float();
	HE_float(float in);
	void encode();
	void decode();
	float extract();
	void operator=(const HE_float &in);
	HE_float operator+(const HE_float &in);
	HE_float operator-(const HE_float &in);
	HE_float operator*(const HE_float &in);
	HE_float operator/(const HE_float &in);//!!!
	HE_float operator>(const HE_float &in);
	HE_float operator<(const HE_float &in);
};

deque<int> bitwiseAnd(deque<int> a, deque<int> b);
deque<int> leftShift(deque<int> a, int shift);
deque<int> rightShift(deque<int> a, int shift);

#endif
