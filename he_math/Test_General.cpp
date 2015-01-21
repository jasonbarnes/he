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


//Note to Jake, Matt, or Stephen:
//If you comment out the following line, it turns off all encryption,
//but the fixed-point representation is still used.
//It also removes all HElib code, allowing it to be built
//outside of HElib.

//#define HE_ON
#define HE_BASE 65537
#define HELIB_DEPTH 5
#define HE_INT_BITS 16

#ifdef HE_ON
#include <NTL/ZZ.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#endif

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
int total_recrypts;
int max_recrypts;
int notify_once_error;

#ifndef HE_ON
typedef int* FHESecKey;
typedef int* FHEPubKey;
typedef int* EncryptedArray;
#endif

using namespace std;

class HE_bit{
	public:
	#ifdef HE_ON
	#endif
	unsigned long p_data;
	unsigned long decrypted_data;
	long orig_value;
	long final_value;
	long track_value;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	int num_recrypts;	
	unsigned long base;
	int mult_depth;

	HE_bit();
	HE_bit(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value);
	void encode();
	void decode();
	void encrypt();
	void decrypt();
	long extract();

	void operator=(const HE_bit &in);
	void operator+=(const HE_bit &in);
	void operator-=(const HE_bit &in);
	void operator*=(const HE_bit &in);
	HE_bit operator+(const HE_bit &in);
	HE_bit operator-(const HE_bit &in);
	HE_bit operator*(const HE_bit &in);

	void recrypt();
};

class HE_int{
	public:
	#ifdef HE_ON
	#endif
	deque<HE_bit *> p_data;
	deque<HE_bit *> decrypted_data;
	long orig_value;
	long final_value;
	long track_value;
	FHESecKey *HE_seckey;
	const FHEPubKey *HE_pubkey;
	EncryptedArray *HE_ea;
	unsigned long base;

	int bits;

	HE_int();
	HE_int(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value);
	HE_int(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value, int in_bits);
	void encode();
	void decode();
	void encrypt();
	void decrypt();
	long extract();
	void recrypt();

	void operator=(const HE_int &in);
	void operator+=(const HE_int &in);
	void operator-=(const HE_int &in);
	void operator*=(const HE_int &in);
	HE_int operator+(const HE_int &in);
	HE_int operator-(const HE_int &in);
	HE_int operator*(const HE_int &in);

	HE_int operator>>(const int &in);
	HE_int operator<<(const int &in);
};

HE_bit::HE_bit(){
	#ifdef HE_ON
	this->data=NULL;
	#endif
	this->base = HE_BASE;
	this->p_data=0;
	this->orig_value=0;
	this->track_value=0;
	this->final_value=0;
	this->HE_seckey=NULL;
	this->HE_pubkey=NULL;
	this->HE_ea=NULL;
	this->num_recrypts=0;
	this->mult_depth=0;
}

HE_bit::HE_bit(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value){
	#ifdef HE_ON
	this->data=NULL;
	#endif
	this->base = HE_BASE;
	this->p_data=0;
	this->orig_value=in_value;
	this->track_value=in_value;
	this->final_value=0;
	#ifdef HE_ON
	#else
	this->HE_seckey=NULL;
	this->HE_pubkey=NULL;
	this->HE_ea=NULL;
	#endif
	this->num_recrypts=0;
	this->encode();
	this->mult_depth=0;
}

void HE_bit::encode(){
	int isNegative=0;
	if(this->orig_value < 0){
		this->orig_value *= -1;
		isNegative=1;
	}
	this->p_data = (this->orig_value)%(this->base);
	if(isNegative){
		this->p_data = this->base - this->p_data;
	}
	this->encrypt();
}

void HE_bit::encrypt(){
	#ifdef HE_ON
	#endif
	return;
}

void HE_bit::decrypt(){
	#ifdef HE_ON
	#else
	this->decrypted_data = this->p_data;
	#endif
	return;
}

void HE_bit::decode(){
	this->decrypt();
	int isNegative=0;
	if(this->decrypted_data > (this->base >> 1)){
		isNegative=1;
		this->decrypted_data = this->base - this->decrypted_data;
	}
	this->final_value = this->decrypted_data;
	if(isNegative){
		this->final_value *= -1;
	}
	return;
}

long HE_bit::extract(){
	this->decode();
	return this->final_value;
}

void HE_bit::operator=(const HE_bit &in){
	#ifdef HE_ON
	#endif
	this->p_data = in.p_data;
	this->decrypted_data = in.decrypted_data;
	this->orig_value = in.orig_value;
	this->final_value = in.final_value;
	this->track_value = in.track_value;
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	this->num_recrypts = in.num_recrypts;
	this->base = in.base;
	this->mult_depth= in.mult_depth;
	return;
}

void HE_bit::operator+=(const HE_bit &in){
	#ifdef HE_ON
	#endif
	this->p_data = (this->p_data + in.p_data) % this->base;
	return;
}

void HE_bit::operator-=(const HE_bit &in){
	#ifdef HE_ON
	#endif
	this->p_data = (this->p_data - in.p_data) % this->base;
	return;
}


void HE_bit::operator*=(const HE_bit &in){
	#ifdef HE_ON
	#endif
	this->p_data = (this->p_data * in.p_data) % this->base;
	this->mult_depth++;
	#ifdef HELIB_DEPTH
	if(this->mult_depth >= HELIB_DEPTH){
		this->recrypt();
	}
	#endif
	return;
}

HE_bit HE_bit::operator+(const HE_bit &in){
	HE_bit ret = in;
	#ifdef HE_ON
	#endif
	ret += (*this);
	return ret;
}
HE_bit HE_bit::operator-(const HE_bit &in){
	HE_bit ret = in;
	#ifdef HE_ON
	#endif
	ret -= (*this);
	return ret;
}
HE_bit HE_bit::operator*(const HE_bit &in){
	HE_bit ret = in;
	#ifdef HE_ON
	#endif
	ret *= (*this);
	return ret;
}

void HE_bit::recrypt(){
	int cur_value = this->extract();
	#ifdef HE_ON
	#endif
	this->track_value = cur_value;
	this->orig_value = cur_value;
	this->p_data = cur_value;
	this->encode();
	this->mult_depth = 0;
	total_recrypts++;
	this->num_recrypts++;
	if(this->num_recrypts > max_recrypts){
		max_recrypts = this->num_recrypts;
	}
	return;
}

HE_int::HE_int(){
	this->bits = HE_INT_BITS;
	this->orig_value = 0;
	this->final_value = 0;
	this->track_value = 0;
	this->HE_seckey = NULL;
	this->HE_pubkey = NULL;
	this->HE_ea = NULL;
	this->base = HE_BASE;
	this->encode();
}
HE_int::HE_int(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value){
	this->bits = HE_INT_BITS;
	this->orig_value = in_value;
	this->final_value = 0;
	this->track_value = in_value;
	this->HE_seckey = in_seckey;
	this->HE_pubkey = in_pubkey;
	this->HE_ea = in_ea;
	this->base = HE_BASE;
	this->encode();
}
HE_int::HE_int(FHESecKey *in_seckey, const FHEPubKey *in_pubkey, EncryptedArray *in_ea, long in_value, int in_bits){
	this->bits = in_bits;
	this->orig_value = in_value;
	this->final_value = 0;
	this->track_value = in_value;
	this->HE_seckey = in_seckey;
	this->HE_pubkey = in_pubkey;
	this->HE_ea = in_ea;
	this->base = HE_BASE;
	this->encode();
}
void HE_int::encode(){
	#ifdef HE_ON
	#endif
	this->p_data.clear();
	int negativeMult=1;
	if(this->orig_value < 0){
		this->orig_value *= -1;
		negativeMult=-1;
	}
	int i;
	HE_bit *temp;
	for(i=0 ; i < this->bits ; i++){	
		if(i >= 64){
			temp = new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0);
		}
		else{
			temp = new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, this->orig_value);
		}
		p_data.push_back(temp);
	}
	this->encrypt();
	return;
}

void HE_int::encrypt(){
	#ifdef HE_ON
	#endif
	return;
}

void HE_int::decrypt(){
	#ifdef HE_ON
	#else
	this->decrypted_data = this->p_data;
	#endif
	return;
}

void HE_int::decode(){
	#ifdef HE_ON
	#endif
	this->decrypt();
	int i;
	long temp;
	this->final_value=0;
	for(i=0 ; i < this->decrypted_data.size() ; i++){
		temp = this->decrypted_data[i]->extract();
		this->final_value+=temp*(long)pow(2.0, (double)i);
	}
	return;
}

long HE_int::extract(){
	this->decode();
	return this->final_value;
}

void HE_int::recrypt(){
	#ifdef HE_ON
	#endif
	int i;
	for(i=0 ; i < p_data.size() ; i++){
		p_data[i]->recrypt();
	}
	return;
}

void HE_int::operator=(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i;
	this->p_data.clear();
	this->orig_value = in.orig_value;
	this->final_value = in.final_value;
	this->track_value = in.track_value;
	this->HE_seckey = in.HE_seckey;
	this->HE_pubkey = in.HE_pubkey;
	this->HE_ea = in.HE_ea;
	this->base = in.base;
	this->bits = in.bits;
	for(i=0 ; i < in.p_data.size() ; i++){
		this->p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
		(*(this->p_data[i])) += (*(in.p_data[i]));
	}
	return;
}

void HE_int::operator+=(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i;
	HE_int a = in;
	this->track_value += in.track_value;
	while(a.p_data.size() < this->p_data.size()){
		a.p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	while(this->p_data.size() < a.p_data.size()){
		this->p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	for(i=0 ; i < a.p_data.size() ; i++){
		(*(this->p_data[i])) += (*(a.p_data[i]));
	}
	return;
}

void HE_int::operator-=(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i;
	HE_int a = in;
	this->track_value -= in.track_value;
	while(a.p_data.size() < this->p_data.size()){
		a.p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	while(this->p_data.size() < a.p_data.size()){
		this->p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	for(i=0 ; i < a.p_data.size() ; i++){
		(*(this->p_data[i])) -= (*(a.p_data[i]));
	}
	return;
}

void HE_int::operator*=(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i,j;
	HE_int a = in;
	HE_int b;
	HE_int c;
	this->track_value *= in.track_value;
	while(a.p_data.size() < this->p_data.size()){
		a.p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	while(this->p_data.size() < a.p_data.size()){
		this->p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	HE_int res(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0, a.p_data.size());
	for(i=0 ; i < a.p_data.size() ; i++){
		c = a;
		b = (*this);
		for(j=0 ; j< c.p_data.size() ; j++){
			(*(c.p_data[j])) *= (*(b.p_data[i]));
		}
		a << i;
		res+=a;
	}
	this->p_data = res.p_data;
	return;
}

HE_int HE_int::operator+(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i,j;
	HE_int res = in;
	res+=(*this);
	return res;
}
HE_int HE_int::operator-(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i,j;
	HE_int res = in;
	res-=(*this);
	return res;
}
HE_int HE_int::operator*(const HE_int &in){
	#ifdef HE_ON
	#endif
	int i,j;
	HE_int res = in;
	res*=(*this);
	return res;
}

HE_int HE_int::operator>>(const int &in){
	#ifdef HE_ON
	#endif
	int i;
	HE_int res = (*this);
	for(i=0 ; i < in ; i++){
		res.p_data.pop_front();
		res.p_data.push_back(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	return res;
}
HE_int HE_int::operator<<(const int &in){
	#ifdef HE_ON
	#endif
	int i;
	HE_int res = (*this);
	for(i=0 ; i < in ; i++){
		res.p_data.pop_back();
		res.p_data.push_front(new HE_bit(this->HE_seckey, this->HE_pubkey, this->HE_ea, 0));
	}
	return res;
}
//TODO


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
HE_bit Xa;
HE_bit Xb(NULL, NULL, NULL, 0);
HE_bit Xc(NULL, NULL, NULL, 1);
HE_bit Xd(NULL, NULL, NULL, 65536);
printf("%lu %lu %lu %lu\n", Xa.extract(), Xb.extract(), Xc.extract(), Xd.extract());
Xb += Xc;
printf("%lu ", Xb.extract());
Xb -= Xd;
printf("%lu ", Xb.extract());
Xb *= Xc;
printf("%lu ", Xb.extract());
Xb = Xc + Xd;
printf("%lu ", Xb.extract());
Xc = Xb - Xd;
printf("%lu ", Xc.extract());
Xd = Xd * Xd;
printf("%lu \n", Xd.extract());


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
