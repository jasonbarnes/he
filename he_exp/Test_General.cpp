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
#include <cstring>

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
#define HE_MANT_BITS 23
#define HE_EXPO_BITS 8
//Define the next line if you want to recrypt
#define HE_RECRYPT_ON
//#define HE_RECRYPT_NOTIFY_ONCE
//#define HE_RECYRPT_NOTIFY_ALL

//#define HE_VECTOR_DESTRUCT_ON
//#define HE_DR_DESTRUCT_ON

//Define the next line to turn HElib on.
//#define HE_ON
//Define this line to ignore HElib and Plaintext, and output the value as if doubles were used.
//#define HE_USE_TRACK_VAL
typedef int P_int;
typedef P_int E_val;

using namespace std;

int total_recrypts;
int max_recrypts;
int notify_once_error;

class HE_float{
	public:
	#ifdef HE_ON
	deque<Ctxt *> mant;
	deque<Ctxt *> expo;
	#endif
	deque<unsigned long> p_mant;
	deque<unsigned long> p_expo;
	deque<unsigned long> final_mant;
	deque<unsigned long> final_expo;
	double orig_value;
	double final_value;
	double track_value;
	unsigned long base;
	int bias;
	int mant_bits;
	int expo_bits;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	int num_recrypts;

	~HE_float();
	HE_float();
	HE_float(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, double in_value);
	void encode();
	void decode();
	void encrypt();
	void decrypt();
	double extract();
	void negate();
	void operator=(const HE_float &in);
	void operator+=(const HE_float &in);
	void operator-=(const HE_float &in);
	void operator*=(const HE_float &in);
	void operator/=(const HE_float &in);
	HE_float operator+(const HE_float &in);
	HE_float operator-(const HE_float &in);
	HE_float operator*(const HE_float &in);
	HE_float operator/(const HE_float &in);
	void recrypt();
};

HE_float::~HE_float(){
}

HE_float::HE_float(){
	this->orig_value=0.0;
	this->final_value=0.0;
	this->track_value=0.0;
	this->base = HE_BASE;
	this->mant_bits = HE_MANT_BITS;
	this->expo_bits = HE_EXPO_BITS;
	this->bias = (int)pow(2.0, this->expo_bits);
	this->bias = (this->bias >> 1) - 1;
	this->HE_seckey = NULL;
	this->HE_pubkey = NULL;
	this->HE_ea = NULL;
	this->num_recrypts=0;
}

HE_float::HE_float(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, double in_value){
	this->orig_value=in_value;
	this->final_value=0.0;
	this->track_value=in_value;
	this->base = HE_BASE;
	this->mant_bits = HE_MANT_BITS;
	this->expo_bits = HE_EXPO_BITS;
	this->bias = (int)pow(2.0, this->expo_bits);
	this->bias = (this->bias >> 1) - 1;
	this->HE_seckey = in_seckey;
	this->HE_pubkey = in_pubkey;
	this->HE_ea = in_ea;
	this->num_recrypts=0;
	this->encode();
}

//This function takes the value in orig_value and transforms it into a bitwise representation
//Stored in p_mant and p_expo
void HE_float::encode(){
	this->orig_value = abs(this->orig_value); //This scheme is only proved for positive
						  //values.  This may change later.

	float fl_value = (float)this->orig_value; //We lose some precision here, but it's
						  //easier than working with doubles during
						  //bit conversions...
	unsigned int bits;
	deque<unsigned long> temp_mant;
	assert(sizeof(float)==sizeof(int));//Just to make sure this isnt an odd OS/compiler.
	memcpy(&bits, &fl_value, sizeof(float));
	//The variable "bits" containts the bits of fl_value.  Now, we'll mask them to extract
	//the exponent and mantissa
	int i,j;
	this->p_mant.clear();
	this->p_expo.clear();
	temp_mant.clear();
	for(i=0 ; i < this->mant_bits; i++){
		temp_mant.push_back(((1<<i)&bits)>>i);
		this->p_mant.push_back(0);
	}
	j=0;
	this->p_mant = temp_mant;
	//We also have to push back some additional bits.  We have HE_MANT_BITS functional
	//bits that carry info, along with a top carry bit (the understood '1' in most
	//floating point reps) and enough extra bits on top to account for excess mult.
	//room.
	this->p_mant.push_back(1);
	for(i=0 ; i < (this->mant_bits+1) ; i++){
		this->p_mant.push_back(0);
	}
	bits = bits >> this->mant_bits;
	for(i=0 ; i < (int)pow(2.0, (double)this->expo_bits); i++){
		if((unsigned int)i==bits){
			this->p_expo.push_back(1);
		}
		else{
			this->p_expo.push_back(0);
		}
	}
	//Now we've encoded the mantissa and exponent into p_mant and p_expo.  We just
	//have to encrypt, and the number is ready.
	this->encrypt();
	return;
}

void HE_float::decode(){
	this->decrypt();
	//The decrypted bits are now in final_mant and final_expo.
	//We can't cast directly back to floats or doubles, we have to do this the hard way.
	this->final_value=0.0;
	int i, j;
	j=0;
	//We have to get rid of the extra multiply space first:
	for(i=0 ; i < (this->mant_bits)+1 ; i++){
		this->final_mant.pop_back();
	}
	for(i=this->final_mant.size()-1; i>=0; i--){
		this->final_value+=final_mant[i]*pow(2.0, (double)j);
		j--;
	}
	for(i=0 ; i < final_expo.size() ; i++){
		if(p_expo[i] == 1){
			break;
		}
	}
	int temp_expo = i-this->bias;
	this->final_value*=pow(2.0, (double)temp_expo);
	return;
}

void HE_float::encrypt(){
	#ifdef HE_ON
	//do encryption stuff
	#endif
	return;
}

void HE_float::decrypt(){
	#ifdef HE_ON
	//do decryption stuff
	#else
	//Decryption is off, so we'll just transfer p_mant and p_expo to the final variables:
	int i;
	this->final_mant = this->p_mant;
	this->final_expo = this->p_expo;
	#endif
	return;
}

double HE_float::extract(){
	this->decode();
	return this->final_value;
}

void HE_float::operator=(const HE_float &in){
	#ifdef HE_ON
	//Ciphertext equivalence code
	#endif
	//Now, we do the same for the plaintext and other variables;
	this->p_mant = in.p_mant;
	this->p_expo = in.p_expo;
	this->final_mant = in.final_mant;
	this->final_expo = in.final_expo;
	this->orig_value = in.orig_value;
	this->final_value = in.final_value;
	this->track_value = in.track_value;
	this->base = in.base;
	this->bias = in.bias;
	this->mant_bits = in.mant_bits;
	this->expo_bits = in.expo_bits;
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	return;
}

deque<unsigned long> rightShiftP(deque<unsigned long> a, int n){
	int i;
	deque<unsigned long> ret = a;
	for(i=0 ; i < n ; i++){
		ret.pop_front();
		ret.push_back(0);
	}
	return ret;
}
deque<unsigned long> leftShiftP(deque<unsigned long> a, int n){
	int i;
	deque<unsigned long> ret = a;
	for(i=0 ; i < n ; i++){
		ret.pop_back();
		ret.push_front(0);
	}
	return ret;
}

#ifdef HE_ON
deque<deque<Ctxt *> > generateMantOptionsA(deque<Ctxt *> a){
	//Takes a Ctxt array and returns all possible shift options
	//Does right shift first, then nothing.
	deque<deque<Ctxt *> > ret;
	return ret;
}
deque<deque<Ctxt *> > generateMantOptionsB(deque<Ctxt *> a){
	//Takes a Ctxt array and returns all possible shift options
	//Does nothing first, then right shift.
	deque<deque<Ctxt *> > ret;
	return ret;
}
#endif

deque<deque<unsigned long> > generatePMantOptionsA(deque<unsigned long> a){
	//Like generateMantOptions, but for plaintext
	deque<deque<unsigned long> > ret;
	unsigned long i;
	deque<unsigned long> temp;
	for(i=0 ; i < a.size() ; i++){
		temp = rightShiftP(a, i);
		ret.push_back(temp);
	}
	for(i=1 ; i < a.size() ; i++){
		temp = a;
		ret.push_back(a);
	}
	return ret;
}

deque<deque<unsigned long> > generatePMantOptionsB(deque<unsigned long> a){
	//Like generateMantOptions, but for plaintext
	deque<deque<unsigned long> > ret;
	unsigned long i;
	deque<unsigned long> temp;
	for(i=0 ; i < a.size() ; i++){
		temp = a;
		ret.push_back(temp);
	}
	for(i=1 ; i < a.size() ; i++){
		temp = rightShiftP(a, i);
		ret.push_back(a);
	}
	return ret;
}

#ifdef HE_ON
deque<deque<Ctxt*> > generateExpoOptionsA(deque<Ctxt *> a){
	//Stuff
}
deque<deque<Ctxt*> > generateExpoOptionsB(deque<Ctxt *> a){
	//Stuff
}
#endif

deque<deque<unsigned long> > generatePExpoOptionsA(deque<unsigned long> a, int mant_size){
	deque<deque<unsigned long> > ret;
	int i;
	deque<unsigned long> temp;
	for(i=0 ; i < mant_size ; i++){
		temp = a;
		ret.push_back(leftShiftP(a, i));
	}
	for(i=1 ; i < mant_size ; i++){
		temp = a;
		ret.push_back(temp);
	}
	return ret;
}

deque<deque<unsigned long> > generatePExpoOptionsB(deque<unsigned long> a, int mant_size){
	deque<deque<unsigned long> > ret;
	int i;
	deque<unsigned long> temp;
	for(i=0 ; i < mant_size ; i++){
		temp = a;
		ret.push_back(temp);
	}
	for(i=1 ; i < mant_size ; i++){
		temp = a;
		ret.push_back(leftShiftP(a, i));
	}
	return ret;
}

deque<unsigned long> generatePSelectArray(deque<deque<unsigned long> > a, deque<deque<unsigned long> >b){
	deque<deque<unsigned long> > c;
	deque<unsigned long> temp;
	int i,j;

	for(i=0 ;i < a.size() ; i++){
		c.push_back(a[i]);
		for(j=0 ; j < a[0].size() ; i++){
			c[i][j] &= b[i][j];
		}
	}
	temp.clear();
	unsigned long value;
	for(i=0 ; i < c.size() ; i++){
		value = 0;
		for(j=0 ; j < c[0].size() ; j++){
			value += c[i][j];
		}
		temp.push_back(value);
	}
	return temp;
}

deque<unsigned long> p_select(deque<unsigned long> select, deque<deque<unsigned long> > options){
	int i,j;
	deque<deque<unsigned long> > select_result;
	deque<unsigned long> final_result;
	for(i=0 ; i < select.size() ; i++){
		select_result.push_back(options[i]);
		for(j=0 ; j < select_result[i].size() ; j++){
			select_result[i][j] *= select[i];
		}
	}
	final_result = select_result[i];
	for(i=1 ; i < select_result.size(); i++){
		for(j=0 ; j < select_result[i].size(); j++){
			final_result[j] += select_result[i][j];
		}
	}
	return final_result;
}

void additiveRescale(HE_float *a, HE_float *b){
	//Takes 2 HE_floats, and adjusts them so that their exponents are equivalent
	//If exponents are more than 23 apart, it won't work
	#ifdef HE_ON
	#endif
	deque<deque<unsigned long> > p_expo_options_a = generatePExpoOptionsA(a->p_expo, a->p_mant.size());
	deque<deque<unsigned long> > p_expo_options_b = generatePExpoOptionsB(b->p_expo, a->p_mant.size());
	deque<deque<unsigned long> > p_mant_options_a = generatePMantOptionsA(a->p_mant);
	deque<deque<unsigned long> > p_mant_options_b = generatePMantOptionsB(b->p_mant);
	deque<unsigned long> p_select_array = generatePSelectArray(p_expo_options_a, p_expo_options_b);
//	unsigned long p_max_select = generatePMaxSelect(p_select_array);
	a->p_expo = p_select(p_select_array, p_expo_options_a);
	b->p_expo = p_select(p_select_array, p_expo_options_b);
	a->p_mant = p_select(p_select_array, p_mant_options_a);
	b->p_mant = p_select(p_select_array, p_mant_options_b);
	return;
}

void HE_float::operator+=(const HE_float &in){
	HE_float a = in;
	additiveRescale(this, &a);
	#ifdef HE_ON
	//Ciphertext code
	#else
	//This is the plaintext-only version.
	//Exponents are the same, so we just have to do an add:
	int i;
	for(i=0 ; i < this->p_mant.size() ; i++){
		this->p_mant[i] += a.p_mant[i];
		this->p_mant[i] = this->p_mant[i] % this->base;
	}
	#endif
	return;
}

void HE_float::negate(){
	//Here, we negate each digit.
	#ifdef HE_ON
	#endif
	int i;
	for(i=0 ; i < this->p_mant.size() ; i++){
		this->p_mant[i] = base - this->p_mant[i];
	}
	return;
}

void HE_float::operator-=(const HE_float &in){
	HE_float a = in;
	a.negate();
	(*this)+=a;
	return;
}

deque<unsigned long> multiplyExpoP(deque<unsigned long> a, deque<unsigned long>b){
	deque<deque<unsigned long> > expo_options;
	int i,j;
	deque<unsigned long> temp;
	for(i=1 ; i < a.size() ; i++){
		expo_options.push_back(leftShiftP(a, i));
		temp = rightShiftP(b, i-1);
		for(j=0 ; j < expo_options[i-1].size() ; j++){
			expo_options[i][j] *= temp[0];
		}
	}
	temp.clear();
	temp = expo_options[0];
	for(i=1 ; i < expo_options[0].size() ; i++){
		for(j=0 ; j < temp.size() ; j++){
			temp[j] += expo_options[i][j];
		}
	}
	return temp;
}


void HE_float::operator*=(const HE_float &in){
	HE_float a = in;
	#ifdef HE_ON
	#else
	deque<unsigned long> res_expo_p = multiplyExpoP(this->p_expo, a.p_expo);
	deque<unsigned long> res;
	int i,j;
	for(i=0 ; i < a.p_mant.size() ; i++){
		res.push_back(0);
	}
	deque<unsigned long> temp;
	for(i=0 ; i < a.p_mant.size() ; i++){
		temp = leftShiftP(a.p_mant, i);
		for(j=0 ; j< temp.size() ; j++){
			temp[j] *= this->p_mant[j];
			res[j] += temp[j];
		}
	}
	this->p_mant = res;
	this->p_expo = res_expo_p;
	#endif
	return;
}

void HE_float::operator/=(const HE_float &in){
	return;
}

HE_float HE_float::operator+(const HE_float &in){
	HE_float ret;
	return ret;
}

HE_float HE_float::operator-(const HE_float &in){
	HE_float ret;
	return ret;
}

HE_float HE_float::operator*(const HE_float &in){
	HE_float ret;
	return ret;
}

HE_float HE_float::operator/(const HE_float &in){
	HE_float ret;
	return ret;
}

void HE_float::recrypt(){
	return;
}

//CSGD code

#ifdef HE_ON
void  TestIt(long R, long p, long r, long d, long c, long k, long w, 
               long L, long m, const Vec<long>& gens, const Vec<long>& ords)
#else
void TestIt()
#endif
{
#ifdef HE_ON
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

#endif
//CSGD Start

#ifdef HE_ON
FHESecKey *HE_seckey;
const FHEPubKey *HE_pubkey;
EncryptedArray *HE_ea;
HE_seckey=&secretKey;
HE_pubkey=&publicKey;
HE_ea=&ea;

HE_float Xa;
HE_float Xb(HE_seckey, HE_pubkey, HE_ea, 1.7);
#endif
HE_float Xa;
HE_float Xb(NULL, NULL, NULL, 1.7);
printf("%f\n", Xb.extract());
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
  #ifdef HE_ON
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
  max_recrypts=0;
  notify_once_error=0;
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
#else
  total_recrypts=0;
  max_recrypts=0;
  notify_once_error=0;
TestIt();
}
#endif
// call to get our running test case:
// Test_General_x p=23 m=20485 L=10 R=5
//
// another call to get an example where phi(m) is very
// close to m:
// Test_General_x m=18631 L=10 R=5
