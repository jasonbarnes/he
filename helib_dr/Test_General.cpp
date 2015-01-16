/* Copyright (C) 2012,2013 IBM Corp.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Test_General.cpp - A general test program that uses a mix of operations over four ciphertexts.
 */
#include <NTL/ZZ.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>

#include <cstdlib>
#include <cstdio>
#include <deque>
#include <cmath>

#include <string>
#include <iostream>
#include <sstream>

#include <vector>

#ifdef DEBUG
#define debugCompare(ea,sk,p,c) {\
  PlaintextArray pp(ea);\
  ea.decrypt(c, sk, pp);\
  if (!pp.equals(p)) { cerr << "oops\n"; exit(0); }\
  }
#else
#define debugCompare(ea,sk,p,c)
#endif

//HE_Fix

#define HE_BASE 2147483647
#define HE_FRAC 8
#define HE_MAX_SCALE 65536
//Define the next line if you want to recrypt
#define HE_RECRYPT_ON
#define HE_RECRYPT_NOFITY_ONCE
//#define HE_RECYRPT_NOTIFY_ALL

//#define HE_VECTOR_DESTRUCT_ON
//#define HE_DR_DESTRUCT_ON
typedef int P_int;
typedef P_int E_val;

using namespace std;

int total_recrypts;


class HE_dr{
	public:
	Ctxt *data;
	int p_data;
	int decrypted_data;
	int scale;
	int base;
	int frac;
	double orig_value;
	double final_value;
	double track_value;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	~HE_dr();
	HE_dr();
	HE_dr(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, double in_value);
	void encode();
	void decode();
	void encrypt();
	void decrypt();
	double extract();
	void operator=(const HE_dr &in);
	void operator+=(const HE_dr &in);
	void operator-=(const HE_dr &in);
	void operator*=(const HE_dr &in);
	HE_dr operator+(const HE_dr &in);
	HE_dr operator-(const HE_dr &in);
	HE_dr operator*(const HE_dr &in);
	void recrypt();
};

HE_dr::~HE_dr(){
	#ifdef HE_DR_DESTRUCT_ON
	if(data != NULL){
		delete this->data;
		this->data = NULL;
	}
	#endif
}

HE_dr::HE_dr(){
	this->data=NULL;
	this->p_data=0;
	this->scale=0;
	this->base=HE_BASE;
	this->frac=HE_FRAC;
	this->orig_value=0.0;
	this->track_value=0.0;
	this->final_value=0.0;
	this->HE_seckey=NULL;
	this->HE_pubkey=NULL;
	this->HE_ea=NULL;
}

HE_dr::HE_dr(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, double in_value){
	this->data=NULL;
	this->p_data=0;
	this->scale=0;
	this->base=HE_BASE;
	this->frac=HE_FRAC;
	this->orig_value=in_value;
	this->track_value=in_value;
	this->final_value=0.0;
	this->HE_seckey=in_seckey;
	this->HE_pubkey=in_pubkey;
	this->HE_ea=in_ea;
	this->encode();
}

void HE_dr::encode(){
	double value=this->orig_value;
	int whole_part;
	int isNegative;
	if(value < -1.0){
		isNegative=1;
		value*=-1.0;
	}
	else{
		isNegative=0;
	}
	this->scale=(int)pow(2.0, (double)this->frac);
	value = value * this->scale;
	whole_part = (int)value;
	if(this->base != 0){
		whole_part = whole_part % this->base;
	}
	if(isNegative){
		whole_part = this->base - whole_part;
	}
	this->p_data=whole_part;
	this->encrypt();
}

void HE_dr::encrypt(){
	if(this->HE_seckey == NULL){
		return;
	}
	PlaintextArray temp_pt(*(this->HE_ea));
	temp_pt.encode(this->p_data);
	this->data = new Ctxt(*(this->HE_pubkey));
	(*this->HE_ea).encrypt((*(this->data)), (*this->HE_pubkey), temp_pt);
}

void HE_dr::decrypt(){
	//this->decrypted_data=this->p_data;
	if(this->HE_seckey == NULL){
		return;
	}
	PlaintextArray temp_pt(*(this->HE_ea));
	(*(this->HE_ea)).decrypt((*(this->data)), (*(this->HE_seckey)), temp_pt);
	stringstream ss;
	temp_pt.print(ss);
	string str = ss.str();
	this->decrypted_data = atoi(str.c_str()+2);
	return;
}

void HE_dr::decode(){
	this->decrypt();
	int isNegative=0;
	if(this->decrypted_data > (this->base/2)){
		isNegative=1;
		this->decrypted_data = (this->base)-(this->decrypted_data);
	}
	else{
		isNegative=0;
	}
	double value=this->decrypted_data;
	value = value/((double)(this->scale));
	if(isNegative){
		value*=-1.0;
	}
	this->final_value=value;
}

double HE_dr::extract(){
	this->decode();
	return this->final_value;
}

void HE_dr::operator=(const HE_dr &in){
	if(this->data != NULL){
		delete this->data;
		this->data = NULL;
	}
	this->p_data = in.p_data;
	this->decrypted_data = in.decrypted_data;
	this->scale = in.scale;
	this->base = in.base;
	this->frac = in.frac;
	this->orig_value = in.orig_value;
	this->track_value = in.track_value;
	this->final_value = in.final_value;
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	this->orig_value=0.0;
	this->encode();
	(*(this->data))+=(*(in.data));
	this->p_data = in.p_data;
}

void HE_dr::operator+=(const HE_dr &in){
	Ctxt *operand=in.data;
	int deleteOperand=0;
	PlaintextArray temp_pt(*(this->HE_ea));
	PlaintextArray const_scale(*(this->HE_ea));
	ZZX const_poly;
	if(this->scale != in.scale){
		if(this->scale < in.scale){
			const_scale.encode((in.scale)/(this->scale));
			(*this->HE_ea).encode(const_poly, const_scale);
			(*(this->data)).multByConstant(const_poly);
			this->scale = in.scale;
			operand = in.data;
			deleteOperand=0;
		}
		else if(in.scale < this->scale){
			if(in.scale == 0){
				const_scale.encode(pow(2, (double)this->frac));
			}
			else{
				const_scale.encode((this->scale)/(in.scale));
			}
			(*this->HE_ea).encode(const_poly, const_scale);
			operand = new Ctxt(*(this->HE_pubkey));
			temp_pt.encode(0);
			(*this->HE_ea).encrypt((*(operand)), (*this->HE_pubkey), temp_pt);
			(*(operand))+=(*(in.data));
			(*(operand)).multByConstant(const_poly);
			deleteOperand=1;
		}
	}
	else{
		deleteOperand=0;
	}
	(*(this->data))+=(*(operand));
	if(deleteOperand){
		delete operand;
		operand=NULL;
	}
	this->p_data+=in.p_data;
	this->track_value+=in.track_value;
	return;
}

void HE_dr::operator-=(const HE_dr &in){
	Ctxt *operand=in.data;
	int deleteOperand=0;
	PlaintextArray temp_pt(*(this->HE_ea));
	PlaintextArray const_scale(*(this->HE_ea));
	ZZX const_poly;
	if(this->scale != in.scale){
		if(this->scale < in.scale){
			const_scale.encode((in.scale)/(this->scale));
			(*this->HE_ea).encode(const_poly, const_scale);
			(*(this->data)).multByConstant(const_poly);
			this->scale = in.scale;
			operand = in.data;
			deleteOperand=0;
		}
		else if(in.scale < this->scale){
			if(in.scale == 0){
				const_scale.encode(pow(2, (double)this->frac));
			}
			else{
				const_scale.encode((this->scale)/(in.scale));
			}
			(*this->HE_ea).encode(const_poly, const_scale);
			operand = new Ctxt(*(this->HE_pubkey));
			temp_pt.encode(0);
			(*this->HE_ea).encrypt((*(operand)), (*this->HE_pubkey), temp_pt);
			(*(operand))+=(*(in.data));
			(*(operand)).multByConstant(const_poly);
			deleteOperand=1;
		}
	}
	else{
		deleteOperand=0;
	}
	(*(this->data))-=(*(operand));
	if(deleteOperand){
		delete operand;
		operand = NULL;
	}
	this->p_data-=in.p_data;
	this->track_value-=in.track_value;
	return;
}

void HE_dr::operator*=(const HE_dr &in){
	(*(this->data))*=(*(in.data));
	this->scale*=in.scale;
	if(scale > HE_MAX_SCALE){
		this->recrypt();
	}
	//Fail if overflow has occurred.
	assert(scale <= HE_MAX_SCALE);
	this->p_data*=in.p_data;
	this->track_value*=in.track_value;
}

HE_dr HE_dr::operator+(const HE_dr &in){
	HE_dr ret(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0);
	ret+=(*(this));
	ret+=in;	
	return ret;
}

HE_dr HE_dr::operator-(const HE_dr &in){
	HE_dr ret(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0);
	ret+=(*(this));
	ret-=in;	
	return ret;
}
HE_dr HE_dr::operator*(const HE_dr &in){
	HE_dr ret(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0);
	ret+=(*(this));
	ret*=in;	
	return ret;
}

void HE_dr::recrypt(){
	#ifdef HE_RECRYPT_ON
	if(this->data == NULL){
		return;
	}	
	#ifdef HE_RECRYPT_NOTIFY_ALL
	cerr << "WARNING: " << total_recrypts << " recrypt() have occurred." << endl;
	#endif
	#ifdef HE_RECRYPT_NOTIFY_ONCE
	#ifdef HE_RECRYPT_NOTIFY_ALL
	cerr << "WARNING: " << total_recrypts << " recrypt() have occurred." << endl;
	#else
	if(!notify_once_error){
		if(total_recrypts == 0){
			cerr << "WARNING: recrypt() has occurred." << endl;
		}
	}
	#endif
	#endif
	total_recrypts++;
	double value = this->extract();
	this->orig_value = value;
	this->p_data=0;
	this->scale=0;
	this->final_value=0.0;
	delete this->data;
	this->data = NULL;
	this->encode();
	#endif
}

class HE_vector{
	public:
	vector<HE_dr *> list;
	int n;
	//int noDestruct;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	~HE_vector();
	HE_vector();
	HE_vector(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, vector<double> *in_data);
	void encode(vector<double> in);
	vector<double> decode();
	void operator=(const HE_vector &in);
	void operator+=(const HE_vector &in);
	void operator-=(const HE_vector &in);
	void operator*=(const HE_vector &in);
	HE_vector operator+(const HE_vector &in);
	HE_vector operator-(const HE_vector &in);
	HE_vector operator*(const HE_vector &in);
	int check(int other_n);
	HE_dr sum();
	void scalarMult(HE_dr in);
	void setEqual(HE_vector in, FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea);
};

void HE_vector::setEqual(HE_vector in, FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea){
	int i;
	for(i=0 ; i < this->n ; i++){
		if(this->list[i] != NULL){
			delete (this->list[i]);
			(this->list[i]) = NULL;
		}
	}
	this->list.clear();
	this->n = in.n;
	/*
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	*/
	this->HE_seckey = in_seckey;
	this->HE_pubkey = in_pubkey;
	this->HE_ea = in_ea;
	in.HE_seckey = in_seckey;
	in.HE_pubkey = in_pubkey;
	in.HE_ea = in_ea;
	for(i=0 ; i < this->n ; i++){
		(this->list).push_back(new HE_dr(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0));
	}
	for(i=0 ; (unsigned int)i < this->list.size() ; i++){
		(*(this->list[i]))+=(*((in).list[i]));
		//(*(this->list[i]))+=(*(this->list[i]));
	}
	//in.noDestruct=1; //TODO: Review if necessary
	return;
}

HE_dr HE_vector::sum(){
	unsigned int i;
	HE_dr ret(HE_seckey, HE_pubkey, HE_ea, 0.0);
	for(i=0 ; i < list.size() ; i++){
		ret+=(*(list[i]));
	}
	return ret;
}

void HE_vector::scalarMult(HE_dr in){
	unsigned int i;
	for(i=0 ; i < this->list.size() ; i++){
		(*(list[i]))*=in;
	}
}

HE_vector::~HE_vector(){
	#ifdef HE_VECTOR_DESTRUCT_ON
	int i;
	for(i=0 ; i < this->n ; i++){
		if(this->list[i] != NULL){
			delete (this->list[i]);
			(this->list[i]) = NULL;
		}
	}
	(this->list).clear();
	#endif
}

HE_vector::HE_vector(){
	//this->noDestruct=0;
	this->n=0;
	this->list.clear();
	this->HE_seckey=NULL;
	this->HE_pubkey=NULL;
	this->HE_ea=NULL;
}

HE_vector::HE_vector(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, vector<double> *in_data){
	//this->noDestruct=0;
	this->n=0;
	this->list.clear();
	this->HE_seckey=in_seckey;
	this->HE_pubkey=in_pubkey;
	this->HE_ea=in_ea;
	this->encode(*in_data);
}

void HE_vector::encode(vector<double> in_data){
	int i;
	if(this->n>0){
		for(i=0 ; i < this->n ; i++){
			if(this->list[i] != NULL){
				delete (this->list[i]);
				(this->list[i])=NULL;
			}
		}
	}
	this->list.clear();
	this->n=0;
	for(i=0 ; (unsigned int)i < in_data.size() ; i++){	
		(this->list).push_back(new HE_dr(this->HE_seckey, this->HE_pubkey, this->HE_ea, in_data[i]));
	}
	this->n=in_data.size();
}

vector<double> HE_vector::decode(){
	int i;
	vector<double> ret;
	ret.clear();
	for(i=0 ; i < this->n ; i++){
		ret.push_back((*((this->list)[i])).extract());
	}
	return ret;
}

int HE_vector::check(int other_n){
	if(this->n != other_n){
		cerr << "Vector sizes do not match: " << this->n << " " << other_n << endl;
		return 1;
	}
	return 0;
}

/*void HE_vector::operator=(const HE_vector &in){
	int i;
	//Two cases, either this HE_vector hasn't been allocated yet, (HE_vector()) , or
	//it has and we need to do a deep copy.
	if(this->n==0){
		if(in.n == 0){
			return;
		}
		this->n=in.n;
		this->HE_seckey=in.HE_seckey;
		this->HE_pubkey=in.HE_pubkey;
		this->HE_ea=in.HE_ea;
		this->list.clear();
		for(i=0 ; i < this->n ; i++){
			(this->list).push_back(new HE_dr(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0));
		}
	}
	if(this->check(in.n)){
		return;
	}
	for(i=0 ; i < this->n ; i++){
		(*(this->list[i]))=(*(in.list[i]));
	}
	return;
}
*/

void HE_vector::operator=(const HE_vector&in){
	int i;
	for(i=0 ; i < this->n ; i++){
		if(this->list[i] != NULL){
			delete (this->list[i]);
			(this->list[i])=NULL;
		}
	}
	this->list.clear();
	this->n = in.n;
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	for(i=0 ; i < this->n ; i++){
		(this->list).push_back(new HE_dr(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0));
	}
	for(i=0 ; i < this->n ; i++){
		(*(this->list[i]))+=(*(in.list[i]));
	}
	return;
}

void HE_vector::operator+=(const HE_vector &in){
	if(this->check(in.n)){
		return;
	}
	int i;
	for(i=0 ; i < n ; i++){
		(*(this->list[i]))+=(*(in.list[i]));
	}
	return;
}

void HE_vector::operator-=(const HE_vector &in){
	if(this->check(in.n)){
		return;
	}
	int i;
	for(i=0 ; i < n ; i++){
		(*(this->list[i]))-=(*(in.list[i]));
	}
	return;
}

void HE_vector::operator*=(const HE_vector &in){
	if(this->check(in.n)){
		return;
	}
	int i;
	for(i=0 ; i < n ; i++){
		(*(this->list[i]))*=(*(in.list[i]));
	}
	return;
}

HE_vector HE_vector::operator+(const HE_vector &in){
	HE_vector ret;
	if(this->check(in.n)){
		return ret;
	}
	ret = (*this);
	ret+=in;
	return ret;
}

HE_vector HE_vector::operator-(const HE_vector &in){
	HE_vector ret;
	if(this->check(in.n)){
		return ret;
	}
	ret = (*this);
	ret-=in;
	return ret;
}

HE_vector HE_vector::operator*(const HE_vector &in){
	HE_vector ret;
	if(this->check(in.n)){
		return ret;
	}
	ret = (*this);
	(ret)*=(in);
	return ret;
}

class HE_data{
	public:
	vector<double> labels;
	vector<HE_vector *> data;
	int n;
	int m;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	HE_data(char * filename, FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea);
	vector<HE_vector *> extract_data_rows(int start, int end);
	vector<double> extract_label_rows(int start, int end);
	vector<HE_vector *> extract_data_all();
	vector<double> extract_label_all();
};

HE_data::HE_data(char *filename, FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea){
	FILE *fp;
	char *buffer = (char *)malloc(10000 * sizeof(char));
	char *ptr = buffer;
	vector<double> temp_data;
	temp_data.clear();
	this->HE_seckey = in_seckey;
	this->HE_pubkey = in_pubkey;
	this->HE_ea = in_ea;
	this->labels.clear();
	this->data.clear();
	this->n=0;
	this->m=0;
	int temp_n=0;
	int temp_n_set=0;
	fp = fopen(filename, "r");
	int line_count=1;
	while(fgets(buffer, 10000, fp)){
		(this->labels).push_back(atof(ptr));
		while(1==1){
			while((*ptr != ',') && (*ptr != '\n') && (*ptr != '\0')){
				ptr++;
			}
			if((*ptr == '\n') || (*ptr == '\0')){
				if(temp_n_set){
					if(this->n != temp_n){
						cerr << "WARNING: Input file matrix rows are not same length." << endl;
						return;
					}
				}
				else{
					temp_n_set=1;
				}
				this->n = temp_n;
				this->data.push_back(new HE_vector(this->HE_seckey, this->HE_pubkey, this->HE_ea, &temp_data));
				temp_data.clear();
				temp_n=0;
				ptr=buffer;
				break;
			}
			ptr++;
			temp_n++;
			temp_data.push_back(atof(ptr));
		}
	}
	fclose(fp);
}

vector<HE_vector *> HE_data::extract_data_rows(int start, int end){
	int i;
	vector<HE_vector *> ret;
	for(i=0 ; i < (end-start)+1 ; i++){
		ret.push_back(this->data[start+i]);
	}
	return ret;
}

vector<double> HE_data::extract_label_rows(int start, int end){
	int i;
	vector<double> ret;
	for(i=0 ; i < (end-start)+1 ; i++){
		ret.push_back(this->labels[i]);
	}
	return ret;
}

vector<HE_vector *> HE_data::extract_data_all(){
	return this->data;
}

vector<double> HE_data::extract_label_all(){
	return this->labels;
}

HE_dr iprod(HE_vector a, HE_vector b){
	HE_dr w(a.HE_seckey, a.HE_pubkey, a.HE_ea, 0.0);
	HE_vector c = a*b;
	w+=c.sum();
	return w;
}

//CSGD code
//The last 3 variables starting with HE should be passed into
//any method, since they are used for HElib.
void linreg_grad_i(HE_vector *g, HE_vector *w, HE_vector *x, int y, HE_dr *alpha, HE_dr *lambda, int d, FHESecKey *HE_seckey, const FHEPubKey *HE_pubkey, EncryptedArray *HE_ea){
	HE_dr y_dr(HE_seckey, HE_pubkey, HE_ea, double(y));
	HE_dr c = (*alpha) * (iprod(*w, *x) - y_dr);
	//XXX
	(*g).setEqual(*w, HE_seckey, HE_pubkey, HE_ea);
	fflush(stdout);
	(*g).scalarMult(c);

	vector<double> temp_zeros;
	int i;
	for(i=0 ; i < d ; i++){
		temp_zeros.push_back(0.0);
	}
	HE_vector gw(HE_seckey, HE_pubkey, HE_ea, &temp_zeros);
	gw+=(*w);
	gw.scalarMult(((*alpha)*(*lambda)));
	(*g)+=gw;
	return;
}

HE_vector ridge_regression(vector<HE_vector *> *X, vector<int> y, HE_dr *alpha, HE_dr *lambda, int N, int d, int niter, FHESecKey *HE_seckey, const FHEPubKey *HE_pubkey, EncryptedArray *HE_ea ){
	vector<double> w_start;
	int i;
	int j;
	for(i=0 ; i < d ; i++){
		w_start.push_back(0.0);
	}
	HE_vector w(HE_seckey, HE_pubkey, HE_ea, &w_start);
	vector<HE_vector *> G;
	//We can reuse w_start here:
	for(i=0 ; i < N ; i++){
		G.push_back(new HE_vector(HE_seckey, HE_pubkey, HE_ea, &w_start));
	}
	for(i=0 ; i < niter ; i++){	
		for(j=0 ; j < N ; j++){
			linreg_grad_i(G[j], &w, (*X)[j], y[j], alpha, lambda, d, HE_seckey, HE_pubkey, HE_ea);
		}
		for(j=0 ; j < N ;j++){
			w-=(*G[j]);
		}
		if(i % 20 == 0){
			//Debug Statements?
		}
	}
	for(i=0 ; i < N ; i++){
		delete G[i];
		G[i]=NULL;
	}
	return w;
}

vector<HE_dr> get_predictions(vector<HE_vector *> *X, HE_vector *w, int N, int d, FHESecKey *HE_seckey, const FHEPubKey *HE_pubkey, EncryptedArray *HE_ea){
	vector<double> temp_zeros;
	int i;
	for(i=0 ; i < N ; i++){
		temp_zeros.push_back(0.0);
	}
	vector<HE_dr> pr;
	HE_vector *xi;
	for(i=0 ; i < N ; i++){
		xi = (*X)[i];
		pr.push_back(iprod(*w, *xi));
	}
	return pr;
}

double get_accuracy(vector<HE_dr>pr, vector<int> y, int N, FHESecKey *HE_seckey, const FHEPubKey *HE_pubkey, EncryptedArray *HE_ea){
	int right = 0;
	int i;
	long pri;
	for(i=0 ; i < N ; i++){
		if(pr[i].extract() >= 0){
			pri = 1;
		}
		else{
			pri = -1;
		}
		if(pri == y[i]){
			right++;
		}
	}
	return (double)right/(double)N;
}

void ml_code(vector<HE_vector *> train_data, vector<HE_vector *> test_data, vector<double> train_labels, vector<double> test_labels, FHESecKey *HE_seckey, const FHEPubKey *HE_pubkey, EncryptedArray *HE_ea){
	unsigned int i;
	vector<int> y;
	vector<int> yte;
	for(i=0 ; i < train_labels.size() ; i++){
		y.push_back((int)train_labels[i]);
	}
	for(i=0 ; i < test_labels.size() ; i++){
		yte.push_back((int)test_labels[i]);
	}
	vector<HE_vector *> *x = &train_data;
	vector<HE_vector *> *xte = &test_data;
	int N = (*x).size();
	int Nte = (*xte).size();
	int d = (*(*x)[0]).n;
	int dte = (*(*xte)[0]).n;
	assert(d == dte);
	HE_dr alpha(HE_seckey, HE_pubkey, HE_ea, 0.03125);
	HE_dr lambda(HE_seckey, HE_pubkey, HE_ea, 0.1);
	HE_vector w = ridge_regression(x, y, &alpha, &lambda, N, d, 2, HE_seckey, HE_pubkey, HE_ea);
	vector<HE_dr> pr = get_predictions(xte, &w, Nte, dte, HE_seckey, HE_pubkey, HE_ea);
	double acc = get_accuracy(pr, yte, Nte, HE_seckey, HE_pubkey, HE_ea);
	printf("Accuracy: %f\n", acc);
	return;
}

/*
HE_vector HE_vector::operator*(const HE_vector &in){
	HE_vector ret;
	if(this->check(in.n)){
		return ret;
	}
	ret = in;
	ret *= (*this);
	return ret;
}
*/
/**************

1. c1.multiplyBy(c0)
2. c0 += random constant
3. c2 *= random constant
4. tmp = c1
5. ea.shift(tmp, random amount in [-nSlots/2, nSlots/2])
6. c2 += tmp
7. ea.rotate(c2, random amount in [1-nSlots, nSlots-1])
8. c1.negate()
9. c3.multiplyBy(c2) 
10. c0 -= c3

**************/


void  TestIt(long R, long p, long r, long d, long c, long k, long w, 
               long L, long m, const Vec<long>& gens, const Vec<long>& ords)
{
  //char buffer[32];
  /*cerr << "\n\n******** TestIt: R=" << R 
       << ", p=" << p
       << ", r=" << r
       << ", d=" << d
       << ", c=" << c
       << ", k=" << k
       << ", w=" << w
       << ", L=" << L
       << ", m=" << m
       << ", gens=" << gens
       << ", ords=" << ords
       << endl;
*/
  vector<long> gens1, ords1;
  convert(gens1, gens);
  convert(ords1, ords);

  FHEcontext context(m, p, r, gens1, ords1);
  buildModChain(context, L, c);

#ifdef DEBUG_PRINTOUT
  if (context.lazy)
    cerr << "LAZY REDUCTIONS\n";
  else
    cerr << "NON-LAZY REDUCTIONS\n";
#endif
  //context.zMStar.printout();
  //cerr << endl;

  FHESecKey secretKey(context);
  const FHEPubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key


  ZZX G;

  if (d == 0)
    G = context.alMod.getFactorsOverZZ()[0];
  else
    G = makeIrredPoly(p, d); 

  //cerr << "G = " << G << "\n";
  //cerr << "generating key-switching matrices... ";
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need
  //cerr << "done\n";


  //cerr << "computing masks and tables for rotation...";
  EncryptedArray ea(context, G);
  //cerr << "done\n";



  //long nslots = ea.size();

  PlaintextArray p0(ea);
  PlaintextArray p1(ea);
  PlaintextArray p2(ea);
  PlaintextArray p3(ea);

  p0.random();
  p1.random();
  p2.random();
  p3.random();

  Ctxt c0(publicKey), c1(publicKey), c2(publicKey), c3(publicKey);
  ea.encrypt(c0, publicKey, p0);
  ea.encrypt(c1, publicKey, p1);
  ea.encrypt(c2, publicKey, p2);
  ea.encrypt(c3, publicKey, p3);

//CSGD Start

FHESecKey *HE_seckey;
const FHEPubKey *HE_pubkey;
EncryptedArray *HE_ea;
HE_seckey=&secretKey;
HE_pubkey=&publicKey;
HE_ea=&ea;
HE_data reader("heart_train.csv", HE_seckey, HE_pubkey, HE_ea);
HE_data reader1("heart_test.csv", HE_seckey, HE_pubkey, HE_ea);
vector<HE_vector *> train_data=reader.extract_data_all();
vector<HE_vector *> test_data=reader1.extract_data_all();
vector<double> train_labels=reader.extract_label_all();
vector<double> test_labels=reader1.extract_label_all();

printf("File reading/allocation done\n");
ml_code(train_data, test_data, train_labels, test_labels, HE_seckey, HE_pubkey, HE_ea);

//CSGD End


//Original Test_General
/*
resetAllTimers();

  FHE_NTIMER_START(Circuit);
  for (long i = 0; i < R; i++) {

    cerr << "*** round " << i << "..."<<endl;
     long shamt = RandomBnd(2*(nslots/2) + 1) - (nslots/2);
                  // random number in [-nslots/2..nslots/2]
     long rotamt = RandomBnd(2*nslots - 1) - (nslots - 1);
                  // random number in [-(nslots-1)..nslots-1]
     // two random constants
     PlaintextArray const1(ea);
     PlaintextArray const2(ea);
     const1.random();
     const2.random();

     ZZX const1_poly, const2_poly;
     ea.encode(const1_poly, const1);
     ea.encode(const2_poly, const2);

     p1.mul(p0);     // c1.multiplyBy(c0)
     c1.multiplyBy(c0);              CheckCtxt(c1, "c1*=c0");
     debugCompare(ea,secretKey,p1,c1);

     p0.add(const1); // c0 += random constant
     c0.addConstant(const1_poly);    CheckCtxt(c0, "c0+=k1");
     debugCompare(ea,secretKey,p0,c0);

     p2.mul(const2); // c2 *= random constant
     c2.multByConstant(const2_poly); CheckCtxt(c2, "c2*=k2");
     debugCompare(ea,secretKey,p2,c2);

     PlaintextArray tmp_p(p1); // tmp = c1
     Ctxt tmp(c1);
     sprintf(buffer, "c2>>=%d", (int)shamt);
     tmp_p.shift(shamt); // ea.shift(tmp, random amount in [-nSlots/2,nSlots/2])
     ea.shift(tmp, shamt);           CheckCtxt(tmp, buffer);
     debugCompare(ea,secretKey,tmp_p,tmp);

     p2.add(tmp_p);  // c2 += tmp
     c2 += tmp;                      CheckCtxt(c2, "c2+=tmp");
     debugCompare(ea,secretKey,p2,c2);

     sprintf(buffer, "c2>>>=%d", (int)rotamt);
     p2.rotate(rotamt); // ea.rotate(c2, random amount in [1-nSlots, nSlots-1])
     ea.rotate(c2, rotamt);          CheckCtxt(c2, buffer);
     debugCompare(ea,secretKey,p2,c2);

     p1.negate(); // c1.negate()
     c1.negate();                    CheckCtxt(c1, "c1=-c1");
     debugCompare(ea,secretKey,p1,c1);

     p3.mul(p2); // c3.multiplyBy(c2) 
     c3.multiplyBy(c2);              CheckCtxt(c3, "c3*=c2");
     debugCompare(ea,secretKey,p1,c3);

     p0.sub(p3); // c0 -= c3
     c0 -= c3;                       CheckCtxt(c0, "c0=-c3");
     debugCompare(ea,secretKey,p0,c0);
  }

  FHE_NTIMER_STOP(Circuit);
   
  cerr << endl;
  printAllTimers();
  cerr << endl;
   
  resetAllTimers();
  FHE_NTIMER_START(Check);
   
  PlaintextArray pp0(ea);
  PlaintextArray pp1(ea);
  PlaintextArray pp2(ea);
  PlaintextArray pp3(ea);
   
  ea.decrypt(c0, secretKey, pp0);
  ea.decrypt(c1, secretKey, pp1);
  ea.decrypt(c2, secretKey, pp2);
  ea.decrypt(c3, secretKey, pp3);
   
  if (!pp0.equals(p0)) cerr << "oops 0\n";
  if (!pp1.equals(p1)) cerr << "oops 1\n";
  if (!pp2.equals(p2)) cerr << "oops 2\n";
  if (!pp3.equals(p3)) cerr << "oops 3\n";
   
  FHE_NTIMER_STOP(Check);
   
  cerr << endl;
  printAllTimers();
  cerr << endl;
   

#if 0

  vector<Ctxt> vc(L,c0);            // A vector of L ciphertexts
  vector<PlaintextArray> vp(L, p0); // A vector of L plaintexts
  for (long i=0; i<L; i++) {
    vp[i].random();                     // choose a random plaintext 
    ea.encrypt(vc[i], publicKey, vp[i]); // encrypt it
    if (i>0) vp[i].mul(vp[i-1]); // keep a running product of plaintexts
  }
  incrementalProduct(vc); // Compute the same running product homomorphically

  // Check that the products match
  bool fail = false;
  for (long i=0; i<L; i++) {
    ea.decrypt(vc[i], secretKey, p0); // decrypt it
    if (!p0.equals(vp[i])) {
      fail = true;
      cerr << "incrementalProduct oops "<<i<< endl;
    }
  }
  if (!fail) cerr << "incrementalProduct works\n";
#endif
*/

}


/* A general test program that uses a mix of operations over four ciphertexts.
 * Usage: Test_General_x [ name=value ]...
 *   R       number of rounds  [ default=1 ]
 *   p       plaintext base  [ default=2 ]
 *   r       lifting  [ default=1 ]
 *   d       degree of the field extension  [ default=1 ]
 *              d == 0 => factors[0] defines extension
 *   c       number of columns in the key-switching matrices  [ default=2 ]
 *   k       security parameter  [ default=80 ]
 *   L       # of levels in the modulus chain  [ default=heuristic ]
 *   s       minimum number of slots  [ default=0 ]
 *   repeat  number of times to repeat the test  [ default=1 ]
 *   m       use specified value as modulus
 *   mvec    use product of the integers as  modulus
 *              e.g., mvec='[5 3 187]' (this overwrite the m argument)
 *   gens    use specified vector of generators
 *              e.g., gens='[562 1871 751]'
 *   ords    use specified vector of orders
 *              e.g., ords='[4 2 -4]', negative means 'bad'
 */
int main(int argc, char **argv) 
{
  setTimersOn();

  ArgMapping amap;


  long R=1;
  amap.arg("R", R, "number of rounds");

  long p=2;
  amap.arg("p", p, "plaintext base");

  long r=1;
  amap.arg("r", r,  "lifting");

  long d=1;
  amap.arg("d", d, "degree of the field extension");
  amap.note("d == 0 => factors[0] defines extension");

  long c=2;
  amap.arg("c", c, "number of columns in the key-switching matrices");

  
  long k=80;
  amap.arg("k", k, "security parameter");

  long L=0;
  amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

  long s=0;
  amap.arg("s", s, "minimum number of slots");

  long repeat=1;
  amap.arg("repeat", repeat,  "number of times to repeat the test");

  long chosen_m=0;
  amap.arg("m", chosen_m, "use specified value as modulus", NULL);

  Vec<long> mvec;
  amap.arg("mvec", mvec, "use product of the integers as  modulus", NULL);
  amap.note("e.g., mvec='[5 3 187]' (this overwrite the m argument)");

  Vec<long> gens;
  amap.arg("gens", gens, "use specified vector of generators", NULL);
  amap.note("e.g., gens='[562 1871 751]'");

  Vec<long> ords;
  amap.arg("ords", ords, "use specified vector of orders", NULL);
  amap.note("e.g., ords='[4 2 -4]', negative means 'bad'");

  amap.parse(argc, argv);

  p=HE_BASE;
  total_recrypts=0;
  if (L==0) { // determine L based on R,r
    L = 3*R+3;
    if (p>2 || r>1) { // add some more primes for each round
      long addPerRound = 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
      L += R * addPerRound;
    }
  }

  long w = 64; // Hamming weight of secret key
  //  long L = z*R; // number of levels

  if (mvec.length()>0)
    chosen_m = computeProd(mvec);
  long m = FindM(k, L, c, p, d, s, chosen_m, true);

  for (long repeat_cnt = 0; repeat_cnt < repeat; repeat_cnt++) {
    TestIt(R, p, r, d, c, k, w, L, m, gens, ords);
  }
}

// call to get our running test case:
// Test_General_x p=23 m=20485 L=10 R=5
//
// another call to get an example where phi(m) is very
// close to m:
// Test_General_x m=18631 L=10 R=5
