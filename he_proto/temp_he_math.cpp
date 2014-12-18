#include "he_math.h"

E_val HE_fix::encrypt(int value){
	//TODO: Convert to helib
	return value;
}

int HE_fix::decrypt(E_val value){
	//TODO: Convert to helib
	return value;
}

void HE_fix::encode(double value){
	this->p_data.clear();
	this->e_data.clear();
	int isNegative;
	if(value < 0){
		isNegative = 1;
		value = abs(value);
	}
	else{
		isNegative = 0;
	}
	double whole_part;
	double frac_part;
	frac_part = modf(value, &whole_part);
	int whole_part_int = (int)whole_part;
	vector<int> frac_array;
	int i;
	if(frac+whole > slots){
		printf("More fractional and whole bits than slots\n");
		return;
	}
	for(i=0 ; i < this->frac ; i++){
		if(frac_part >= pow(2, -1.0*(i+1))){
			frac_array.push_back(1);
			frac_part -= pow(2, -1.0*(i+1));
		}
		else{
			frac_array.push_back(0);
		}
	}
	for(i=this->frac - 1 ; i >= 0 ; i--){
		p_data.push_back(frac_array[i]);
	}
	for(i=0 ; i < this->whole ; i++){
		if(whole_part_int & (1 << i)){
			p_data.push_back(1);
		}
		else{
			p_data.push_back(0);
		}
	}
	for(i=0 ; i < slots - (whole+frac) ; i++){
		p_data.push_back(0);
	}
	if(p_data.size() != this->slots){
		printf("Something went wrong, p_data.size() != this->slots\n");
		return;
	}
	for(i=0 ; i < this->slots ; i++){
		p_data[i] ^= isNegative;
	}
	int carry=0;
	int in_bit=1;
	int out_bit;
	if(isNegative){
		for(i=0 ; i < this->slots ; i++){
			out_bit = carry ^ p_data[i] ^ in_bit;
			carry = (p_data[i] & in_bit)|(carry & (p_data[i] ^ in_bit));
			p_data[i] = out_bit;
			in_bit = 0;
		}
	}
	/*
	for(i=this->slots-1 ; i >= 0 ; i--){
		printf("%d ", p_data[i]);
	}
	printf("\n");
	*/

	/*
	At this point, the plaintext array is fully calculated.  Now we just have to encrypt
	it and we're done.
	*/
	for(i=0 ; i < this->slots ; i++){
		e_data.push_back(this->encrypt(p_data[i]));
	}
	return;
}

double HE_fix::decode(){
	vector<int> out_data;
	int i;
	for(i=0 ; i < this->slots ; i++){
		out_data.push_back(this->decrypt(e_data[i]));
	}
	/*
	We've recovered the plaintext, now we need to reinterpret it.
	*/
	long long int out_bits=(long long int)0;
	for(i=0 ; i < this->slots ; i++){
		out_bits += (out_data[i] << i);
	}
	out_bits = (out_bits << (sizeof(long long int)*8)-slots) >> ((sizeof(long long int)*8)-slots);
	out_data.clear();
	for(i=0 ; i < this->slots ; i++){
		if(out_bits & (1<<i)){
			out_data.push_back(1);
		}
		else{
			out_data.push_back(0);
		}
	}
	int isNegative;
	int carry=0;
	int in_bit=1;
	int out_bit;
	if(out_data[this->slots - 1]){
		isNegative = 1;
		for(i=0 ; i < this->slots ; i++){
			out_data[i] ^= 1;
		}
		for(i=0 ; i < this->slots ; i++){
			out_bit = carry ^ out_data[i] ^ in_bit;
			carry = (out_data[i] & in_bit)|(carry & (out_data[i] ^ in_bit));
			out_data[i] = out_bit;
			in_bit = 0;
		}
	}
	else{
		isNegative = 0;
	}
	/*
	out_data now contains the absolute value of our result, so we can convert it back using powers
	of 2:
	*/
	double result = 0.0;
	for(i=0 ; i < this->slots ; i++){
		if(out_data[i]){
			result += pow(2.0, (double)(i-frac));
		}
	}
	if(isNegative){
		result *= -1.0;
	}
	return result;
}

void HE_fix::operator=(const HE_fix &in_value){
	int i;
	for(i=0 ; i < this->slots ; i++){
		this->e_data[i] = in_value.e_data[i];
		this->p_data[i] = in_value.e_data[i];
	}
}

HE_fix HE_fix::operator+(const HE_fix &in_value){
	vector<E_val> result;
	int i;
	for(i=0 ; i < this->slots ; i++){
		result.push_back(this->e_data[i] + in_value.e_data[i]);
		result.push_back((this->p_data[i] + in_value.p_data[i])%pow(2, this->bits));
	}
	return result;
}

HE_fix HE_fix::operator-(const HE_fix &in_value){
	HE_fix temp_he = in_value;
	HE_fix negate(-1.0);
	return (*this + (negate * temp_he));
}

HE_fix HE_fix::left_shift_const(int in_value){
	int i;
	HE_fix result = *this;
	for(i=0 ; i < in_value ; i++){
		result.left_shift_self();
	}
	return result;
}

HE_fix HE_fix::right_shift_const(int in_value){
	int i;
	HE_fix result = *this;
	for(i=0 ; i < in_value ; i++){
		result.right_shift_self();
	}
	return result;
}

void HE_fix::left_shift_self(){
	this->e_data.pop_back();
	this->p_data.pop_back();
//XXX
}

HE_fix HE_fix::operator*(const HE_fix &in_value){
	
}

int main(int argc, char **argv){
	double value = atof(argv[1]);
	HE_fix test(value);
	printf("%f\n", test.decode());
}
