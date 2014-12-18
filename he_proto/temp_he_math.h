#ifndef __HE_MATH_H__
#define __HE_MATH_H__

#include <cstdlib>
#include <cstdio>
#include <vector>
#include <cmath>

#define DEFAULT_BITS 16
#define DEFAULT_SLOTS 16
#define DEFAULT_WHOLE 8
#define DEFAULT_FRAC 8

typedef int P_int;
typedef P_int E_val;

using namespace std;

class HE_fix{
	private:
	vector<int> p_data;
	vector<E_val> e_data;
	int bits;
	int slots;
	int whole;
	int frac;
	public:
	E_val encrypt(int value);
	int decrypt(E_val value);
	void encode(double value);
	double decode();
	
	//Instantiation
	HE_fix(){
		bits = DEFAULT_BITS;
		slots = DEFAULT_SLOTS;
		whole = DEFAULT_WHOLE;
		frac = DEFAULT_FRAC;
		this->encode(0.0);
	}
	HE_fix(int in_bits , int in_slots, int in_whole, int in_frac){
		bits = in_bits;
		slots = in_slots;
		whole = in_whole;
		frac = in_frac;
		this->encode(0.0);
	}
	HE_fix(double in_value){
		bits = DEFAULT_BITS;
		slots = DEFAULT_SLOTS;
		whole = DEFAULT_WHOLE;
		frac = DEFAULT_FRAC;
		this->encode(in_value);
	}
	HE_fix(double in_value, int in_bits, int in_slots, int in_whole, int in_frac){
		bits = in_bits;
		slots = in_slots;
		whole = in_whole;
		frac = in_frac;
		this->encode(in_value);
	}
	
	void operator=(const HE_fix &in_value);
	HE_fix operator+(const HE_fix &in_value);
	HE_fix operator-(const HE_fix &in_value);
	HE_fix operator*(const HE_fix &in_value);
	HE_fix left_shift_const(int in_value);
	HE_fix right_shift_const(int in_value);
	void left_shift_self();
	void right_shift_self();
};

#endif
