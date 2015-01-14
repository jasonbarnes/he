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
	if(data != NULL){
		delete this->data;
	}
}

HE_dr::HE_dr(){
	this->data=NULL;
	this->p_data=0;
	this->scale=0;
	this->base=HE_BASE;
	this->frac=HE_FRAC;
	this->orig_value=0.0;
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
	whole_part = whole_part % this->base;
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
	}
	this->p_data = in.p_data;
	this->decrypted_data = in.decrypted_data;
	this->scale = in.scale;
	this->base = in.base;
	this->frac = in.frac;
	this->orig_value = in.orig_value;
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
			const_scale.encode((this->scale)/(in.scale));
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
	}
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
			const_scale.encode((this->scale)/(in.scale));
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
	}
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
	int notify_once_error=0;
	#ifdef HE_RECRYPT_ON
	if(this->data == NULL){
		return;
	}	
	#ifdef HE_RECRYPT_NOTIFY_ALL
	notify_once_error=1;
	cerr << "WARNING: " << total_recrypts << " recrypt() have occurred." << endl;
	#endif
	#ifdef HE_RECRYPT_NOTIFY_ONCE
	if(!notify_once_error){
		if(total_recrypts == 0){
			cerr << "WARNING: recrypt() has occurred." << endl;
		}
	}
	#endif
	total_recrypts++;
	double value = this->extract();
	this->orig_value = value;
	this->p_data=0;
	this->scale=0;
	this->final_value=0.0;
	delete this->data;
	this->encode();
	#endif
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
FHESecKey *HE_seckey = &secretKey;
const FHEPubKey *HE_pubkey = &publicKey;
EncryptedArray *HE_ea = &ea;
HE_dr Xa;
HE_dr Xb(HE_seckey, HE_pubkey, HE_ea, -3.3);
HE_dr Xc(HE_seckey, HE_pubkey, HE_ea, 2.7);
HE_dr Xd = Xb + Xc;
HE_dr Xe = Xb - Xc;
HE_dr Xf = Xd * Xe;
printf("%f %f %f %f %f %f\n", Xa.extract(), Xb.extract(), Xc.extract(), Xd.extract(), Xe.extract(), Xf.extract());
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
