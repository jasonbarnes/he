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
	this->mant_bits = in.mant_bits;
	this->expo_bits = in.expo_bits;
	this->orig_value = in.orig_value;
	this->final_value = in.final_value;
	this->sign = in.sign;
	int i;
	this->mant.clear();
	this->expo.clear();
	for(i=0 ;i < in.mant.size() ; i++){
		this->push_back(in.mant[i]);
	}
	for(i=0 ;i < in.expo.size() ; i++){
		this->push_back(in.expo[i]);
	}
	return;
}

deque<int> bitwiseAnd(deque<int> a, deque<int>b){
	deque<int> ret;
	int i;
	for(i=0 ; i < a.size() ; i++){
		ret.push_back(a[i] & b[i]);
	}
	return ret;
}

deque<int> leftShift(deque<int> a, int shift){
	deque<int> ret;
	if(shift > a.size()){
		shift = a.size();
	}
	int i;
	for(i=0 ; i < shift ; i++){
		ret.push_back(0);
	}
	for(i=0 ; i < a.size()-shift ; i++){
		ret.push_back(a[i]);
	}
	return ret;
}

deque<int> rightShift(deque<int> a, int shift){
	deque<int> ret;
	if(shift > a.size()){
		shift = a.size();
	}
	int i;
	for(i=shift ; i < a.size() ; i++){
		ret.push_back(a[i]);
	}
	for(i=0 ; i < shift ; i++){
		ret.push_back(0);
	}
	return ret;
}

deque<int> selectArray(deque<int> select, deque<deque<int> > data){
	assert(select.size() == data.size());
	int i,j;
	deque<int> ret;
	for(i=0 ; i < select.size() ; i++){
		for(j=0 ; j < data[0].size() ; j++){
			data[i][j] = data[i][j] & select[i];
		}
	}
	for(i=0 ; i < data[0].size() ; i++){
		ret.push_back(1);
	}
	for(i=0 ; i < data.size() ; i++){
		ret = bitwiseAnd(ret, data[i]);
	}
	return ret;
}

HE_float HE_float::operator+(const HE_float &in){
	HE_float a = (*this);
	HE_float b = (in);

	//Generating all possible renormilization options;
	deque<deque<int> >a_mant_choices;
	deque<deque<int> >a_expo_choices;
	deque<deque<int> >b_mant_choices;
	deque<deque<int> >b_expo_choices;
	//We need these later in case a and b's expo is more than 22 apart
	deque<int> max_a_expo;
	deque<int> max_b_expo;
	int i;
	for(i=0 ; i < this.mant.size() ; i++){
		a_mant_choices.push_back(rightShift(a.mant[i], i));
		a_expo_choices.push_back(leftShift(a.expo[i], i));
		b_mant_choices.push_back(b.mant);
		b_expo_choices.push_back(b.expo);
	}
	//TODO XXX
	for(i=1 ; i < this.mant.size() ; i++){
		b_mant_choices.push_back(rightShift(b.mant[i], i));
		b_expo_choices.push_back(leftShift(b.expo[i], i));
		a_mant_choices.push_back(a.mant);
		a_expo_choices.push_back(a.expo);
	}
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
