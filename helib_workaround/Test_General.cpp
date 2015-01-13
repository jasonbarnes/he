/* Copyright (C) 2012,2013 IBM Corp.
:q
:q
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

#define DEFAULT_BITS 16
#define DEFAULT_SLOTS 32
#define DEFAULT_WHOLE 8
#define DEFAULT_FRAC 8

typedef int P_int;
typedef P_int E_val;

using namespace std;

/*FHESecKey *HE_seckey;
const FHEPubKey *HE_pubkey;
EncryptedArray *HE_ea;
*/
class HE_fix{
	public:
	deque<int> p_data;
	deque<Ctxt *> e_data;
	int bits;
	int slots;
	int whole;
	int frac;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	
	Ctxt *encrypt(int value);
	int decrypt(Ctxt *value);
	void encode(double value);
	double decode();
	
	//Instantiation
	HE_fix(){
		HE_seckey = NULL;
		HE_pubkey = NULL;
		HE_ea = NULL;
		bits = DEFAULT_BITS;
		slots = DEFAULT_SLOTS;
		whole = DEFAULT_WHOLE;
		frac = DEFAULT_FRAC;
		int i;
		for(i=0 ; i < this->slots ; i++){
			p_data.push_back(0);
			e_data.push_back(NULL);
		}
	}
	HE_fix(FHESecKey *s, const FHEPubKey *p, EncryptedArray *e){
		HE_seckey = s;
		HE_pubkey = p;
		HE_ea = e;
		bits = DEFAULT_BITS;
		slots = DEFAULT_SLOTS;
		whole = DEFAULT_WHOLE;
		frac = DEFAULT_FRAC;
		this->encode(0.0);
	}
	HE_fix(FHESecKey *s, const FHEPubKey *p, EncryptedArray *e, int in_bits , int in_slots, int in_whole, int in_frac){
		HE_seckey = s;
		HE_pubkey = p;
		HE_ea = e;
		bits = in_bits;
		slots = in_slots;
		whole = in_whole;
		frac = in_frac;
		this->encode(0.0);
	}
	HE_fix(FHESecKey *s, const FHEPubKey *p, EncryptedArray *e,double in_value){
		HE_seckey = s;
		HE_pubkey = p;
		HE_ea = e;
		bits = DEFAULT_BITS;
		slots = DEFAULT_SLOTS;
		whole = DEFAULT_WHOLE;
		frac = DEFAULT_FRAC;
		this->encode(in_value);
	}
	HE_fix(FHESecKey *s, const FHEPubKey *p, EncryptedArray *e,double in_value, int in_bits, int in_slots, int in_whole, int in_frac){
		HE_seckey = s;
		HE_pubkey = p;
		HE_ea = e;
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
	void multiply_by_element(Ctxt *in_e, int in_p);
};

Ctxt *HE_fix::encrypt(int value){
	PlaintextArray temp_pt(*(this->HE_ea));
	temp_pt.encode(value);
	Ctxt *temp_ct = new Ctxt(*(this->HE_pubkey));
	(*(this->HE_ea)).encrypt((*temp_ct), (*(this->HE_pubkey)), temp_pt);
	return temp_ct;
}

int HE_fix::decrypt(Ctxt *value){
	PlaintextArray temp_pt(*(this->HE_ea));
	(*(this->HE_ea)).decrypt((*value), (*(this->HE_seckey)), temp_pt);
	stringstream ss;
	temp_pt.print(ss);
	string str = ss.str();
	return atoi(str.c_str()+2);
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
	deque<int> frac_array;
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
	deque<int> out_data;
	int i;
	for(i=0 ; i < this->slots ; i++){
		out_data.push_back(this->decrypt(e_data[i]));
	}
	/*
	We've recovered the plaintext, now we need to reinterpret it.
	*/
	for(i=(this->slots - 1) ; i >= 0 ; i--){
		printf("%d ", out_data[i]);
	}
	printf("\n");
	for(i=(this->slots - 1) ; i >= 0 ; i--){
		printf("%d ", this->p_data[i]);
	}
	printf("\n");
	long long int out_bits=(long long int)0;
	for(i=0 ; i < (this->whole + this->frac) ; i++){
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
	if(out_data[(this->whole + this->frac) - 1]){
		isNegative = 1;
		for(i=0 ; i < (this->whole + this->frac) ; i++){
			out_data[i] ^= 1;
		}
		for(i=0 ; i < (this->slots + this->frac) ; i++){
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
	for(i=0 ; i < (this->whole + this->frac) ; i++){
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
		if(this->e_data[i] != NULL){
			delete this->e_data[i];
		}
	}
	this->e_data.clear();
	this->bits = in_value.bits;
	this->slots = in_value.slots;
	this->whole = in_value.whole;
	this->frac = in_value.frac;
	this->HE_seckey = in_value.HE_seckey;
	this->HE_pubkey = in_value.HE_pubkey;
	this->HE_ea = in_value.HE_ea;
	this->encode(0.0);
	for(i=0 ; i < this->slots ; i++){
		//this->e_data.push_back(this->encrypt(0));
		(*this->e_data[i]) += (*(in_value.e_data[i]));
		this->p_data[i] = in_value.p_data[i];
	}
}

HE_fix HE_fix::operator+(const HE_fix &in_value){
	deque<Ctxt *> result;
	deque<int> p_result;
	int i;
	for(i=0 ; i < this->slots ; i++){
		result.push_back(this->encrypt(0));
		(*(result[i]))+=(*(this->e_data[i]));
		(*(result[i]))+=(*(in_value.e_data[i]));
		//result.push_back(this->e_data[i] + in_value.e_data[i]);
		p_result.push_back((this->p_data[i] + in_value.p_data[i])%(int)pow((double)2.0, (double)this->bits));
	}
	HE_fix ret;
	ret.e_data = result;
	ret.p_data = p_result;
	ret.bits = this->bits;
	ret.slots = this->slots;
	ret.whole = this->frac;
	ret.frac = this->frac;
	ret.HE_seckey = this->HE_seckey;
	ret.HE_pubkey = this->HE_pubkey;
	ret.HE_ea = this->HE_ea;
	return ret;
}

HE_fix HE_fix::operator-(const HE_fix &in_value){
	HE_fix temp_he = in_value;
	HE_fix negate(this->HE_seckey, this->HE_pubkey, this->HE_ea, -1.0);
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
	e_data.push_front(this->encrypt(0));
	p_data.push_front(0);
}

void HE_fix::right_shift_self(){
	this->e_data.pop_front();
	this->p_data.pop_front();
	e_data.push_back(this->encrypt(0));
	p_data.push_back(0);
}

HE_fix HE_fix::operator*(const HE_fix &in_value){
	deque<Ctxt *> result;
	deque<Ctxt *> temp;
	deque<int> p_result;
	deque<int> p_temp;
	int i,j,k;
	for(i=0 ; i < this->slots ; i++){
		result.push_back(this->encrypt(0));
		p_result.push_back(0);
	}
	for(i=0 ; i < this->slots ; i++){
		for(j=0 ; j < this->slots ; j++){
			temp.push_back(this->encrypt(0));
			(*(temp[j]))+=(*(this->e_data[j]));
			p_temp.push_back(0);
			p_temp[j]+=this->p_data[j];
		}
		for(j=0 ; j < i ; j++){
			temp.pop_back();
			p_temp.pop_back();
			temp.push_front(this->encrypt(0));
			p_temp.push_front(0);
		}
		for(j=0 ; j < this->slots ; j++){
			(*(temp[j])) *= (*(in_value.e_data[i]));
			(*(result[j])) += (*(temp[j]));
			p_temp[j] *= in_value.p_data[i];
			p_result[j] += p_temp[j];
		}
		for(j=0 ; j < this->slots ; j++){
			delete temp[j];
		}
		temp.clear();
		p_temp.clear();
	}
	for(i=0 ; i < this->frac ; i++){
		result.pop_front();
		p_result.pop_front();
		result.push_back(this->encrypt(0));
		p_result.push_back(0);
	}
	HE_fix ret;
	ret.e_data = result;
	ret.p_data = p_result;
	ret.bits = this->bits;
	ret.slots = this->slots;
	ret.whole = this->frac;
	ret.frac = this->frac;
	ret.HE_seckey = this->HE_seckey;
	ret.HE_pubkey = this->HE_pubkey;
	ret.HE_ea = this->HE_ea;
	return ret;
}
/*HE_fix HE_fix::operator*(const HE_fix &in_value){
	HE_fix temp(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0, this->bits, this->slots, this->whole, this->frac);
	HE_fix result(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0.0, this->bits, this->slots, this->whole, this->frac);
	int i;
	int j;
	int k;
	printf("AAA\n");
	for(i=0 ; i < this->slots ; i++){
		printf("A\n");
		fflush(stdout);
		//temp = in_value;
		for(k=0 ; k < temp.slots ; k++){
			if(
		}
		printf("B\n");
		temp.multiply_by_element(this->e_data[i], this->p_data[i]);
		printf("C\n");
		for(j=0 ; j < i ; j++){
			temp.left_shift_self();
		}
		printf("D\n");
		result = result + temp;
		printf("E\n");
	}
	printf("BBB\n");
	for(i=0 ; i < frac ; i++){
		result.right_shift_self();
	}
	printf("CCC\n");
	return result;
}*/

void HE_fix::multiply_by_element(Ctxt *in_e, int in_p){
	int i;
	for(i=0 ; i < this->slots ; i++){
		(*(this->e_data[i])) *= (*(in_e));
		this->p_data[i] = this->p_data[i] * in_p;
	}
}

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

//CSGD Start XXX
printf("CSGD Start\n");
FHESecKey *HE_seckey;
const FHEPubKey *HE_pubkey;
EncryptedArray *HE_ea;
HE_seckey=&secretKey;
HE_pubkey=&publicKey;
HE_ea=&ea;

int i;
HE_fix Xa(HE_seckey, HE_pubkey, HE_ea, 1.7);
HE_fix Xb(HE_seckey, HE_pubkey, HE_ea, 2.3);
HE_fix Xc;
system("date");
for(i=0 ; i < 10 ; i++){
	Xc = Xa+Xb;
}
system("date");
printf("%f\n", Xc.decode());

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
