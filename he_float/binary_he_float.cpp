#include "binary_he_float.h"


HE_float::HE_float(){
	this->mant_bits = HE_MANT;
	this->expo_bits = HE_EXPO;
	this->orig_value=0.0;
	this->final_value=0.0;
	this->encode();
}

HE_float::HE_float(float in){
	this->mant_bits = HE_MANT;
	this->expo_bits = HE_EXPO;
	this->orig_value=in;
	this->final_value=in;
	this->encode();
}

void HE_float::encode(){
	int i;
	unsigned int bits;
	//Mantissa first
	memcpy(&bits, &(this->orig_value), sizeof(float));
	bits = bits << (this->expo_bits + 1);
	bits = bits >> (this->expo_bits + 1);
	for(i=0 ; i < this->mant_bits ; i++){
		this->mant.push_back((bits & (1<<i))>>i);
	}
	//Now Exponent
	memcpy(&bits, &(this->orig_value), sizeof(float));
	bits = bits >> this->mant_bits;
	bits = (bits << this->mant_bits) << 1;
	bits = (bits >> 1) >> this->mant_bits;
	for(i=0 ; i < (int)pow(2.0, (float)this->expo_bits) ; i++){
		if(i == bits){
			this->expo.push_back(1);
		}
		else{
			this->expo.push_back(0);
		}
	}
	//Now the sign, the easy part;
	if(orig_value < 0.0){
		this->sign = 1;
	}
	else{
		this->sign = 0;
	}
	
	for(i=0 ; i < this->expo.size() ; i++){
		if(this->expo[i]){
			break;
		}
	}
	int temp=i;
	for(i=7 ; i >= 0 ; i--){
	}
	for(i=(this->mant.size()-1) ; i>=0 ; i--){
	}
}

void HE_float::decode(){
	int i=0;
	int a=0;
	int bits=0;
	for(i=0 ; i < this->mant_bits; i++){
		if(this->mant[a]){
			bits = bits ^ (1 << a);
		}
		a++;
	}
	for(i=0 ; i < this->expo.size() ; i++){
		if(this->expo[i]){
			break;
		}
	}
	bits = bits ^ (i << a);
	a += this->expo_bits;
	if(this->sign){
		bits = bits ^ (1 << a);
	}
	memcpy(&(this->final_value), &(bits), sizeof(float));
}

float HE_float::extract(){
	this->decode();
	return this->final_value;
}

void HE_float::operator=(const HE_float &in){
	//TODO
	return;
}

HE_float HE_float::operator+(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
HE_float HE_float::operator-(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
HE_float HE_float::operator*(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
HE_float HE_float::operator/(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
HE_float HE_float::operator>(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
HE_float HE_float::operator<(const HE_float &in){
	//TODO
	HE_float ret((float)0.0);
	return ret;
}
