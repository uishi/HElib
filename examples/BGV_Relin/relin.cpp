/* Copyright (C) 2019 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
#include <iostream>

#include <helib/helib.h>

using namespace  helib;
#if 0
void Relin(Ctxt& ct, long keyID) {
  FHE_TIMER_START;
  // Special case: if *this is empty or already re-linearized then do nothing
  if (ct.isEmpty() || ct.inCanonicalForm(keyID)) return;

  ct.dropSmallAndSpecialPrimes();
  long g = ct.getPtxtSpace();
	auto context = ct.getContext();
	auto pubKey = ct.getPubKey();
  double logProd = context.logOfProduct(context.specialPrimes);

  Ctxt tmp(pubKey, g); // an empty ciphertext, same plaintext space
  tmp.intFactor = intFactor;   // same intFactor, too
  tmp.ptxtMag = ptxtMag;       // same CKKS plaintext size
  tmp.noiseBound = noiseBound * NTL::xexp(logProd);  // The noise after mod-up
  tmp.ratFactor = ratFactor * NTL::xexp(logProd);  // CKKS factor after mod-up

  for (CtxtPart& part : ct.parts) {
    // For a part relative to 1 or base,  only scale and add
    if (part.skHandle.isOne() || part.skHandle.isBase(keyID)) {
      part.addPrimesAndScale(context.specialPrimes);
      tmp.addPart(part, /*matchPrimeSet=*/true);
      continue;
    }
    // Look for a key-switching matrix to re-linearize this part
    const KeySwitch& W = (keyID>=0)?
      pubKey.getKeySWmatrix(part.skHandle,keyID) :
      pubKey.getAnyKeySWmatrix(part.skHandle);

    //OLD: assert(W.toKeyID>=0);      // verify that a switching matrix exists
    helib::assertTrue(W.toKeyID>=0, "No key-switching matrix exists");

    if (g>1) { // g==1 for CKKS, g>1 for BGV
      g = NTL::GCD(W.ptxtSpace, g); // verify that the plaintext spaces match
      //OLD: assert (g>1);
      helib::assertTrue (g>1, "Plaintext spaces do not match");
      tmp.ptxtSpace = g;
    }
    tmp.keySwitchPart(part, W); // switch this part & update noiseBound
  }
  *this = tmp;
}
#endif

int main(int argc, char *argv[]) {
  setTimersOn();
  /*  Example of BGV scheme  */
  
  // Plaintext prime modulus
  unsigned long p = 4999;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 32109;
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  //unsigned long bits = 300;
  unsigned long bits = 1000;
  // Number of columns of Key-Switching matix (default = 2 or 3)
  unsigned long c = 2;
  
  std::cout << "Initialising context object..." << std::endl;
  // Intialise context
  helib::FHEcontext context(m, p, r);
  // Modify the context, adding primes to the modulus chain
  std::cout  << "Building modulus chain..." << std::endl;
  buildModChain(context, bits, c);

// ctxt primes + special primes
  //auto primes = context.fullPrimes();
	long numprime = context.numPrimes();

	double prime_size_bits = 0;
	for (long i = 0; i < numprime; ++i) {
	  //prime_size_bits += std::log2(prime.getQ());
	  prime_size_bits += std::log2(context.ithModulus(i).getQ());
	}
	//TODO Does it represent special primes and ctxt primes??
	// Let us aggreate proper one! (see FHEContext.h)
	std::cout << "bits size = " << prime_size_bits << std::endl;


  auto index_set_for_ctxt_and_special_primes = context.fullPrimes();
	double bit_pq = context.logOfProduct(index_set_for_ctxt_and_special_primes) / log(2.0);
	std::cout << "bits size PQ = " << bit_pq << std::endl;

  // Print the context
  context.zMStar.printout();
  std::cout << std::endl;
  
  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;
  
  // Secret key management
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::FHESecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);
  
  // Public key management
  // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  const helib::FHEPubKey& public_key = secret_key;
  
  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = *(context.ea);
  
  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;
  
  // Create a vector of long with nslots elements
  std::vector<long> ptxt(nslots);
  // Set it with numbers 0..nslots - 1
  for (int i = 0; i < nslots; ++i) {
    ptxt[i] = i;
  }
  // Print the plaintext
  std::cout << "Initial Ptxt: " << helib::vecToStr(ptxt) << std::endl;
  
  // Create a ciphertext
  helib::Ctxt ctxt(public_key);
  // Encrypt the plaintext using the public_key
  ea.encrypt(ctxt, public_key, ptxt);
  
  // Square the ciphertext
  ctxt *= ctxt;
	std::cout << "# Ring Elements = " <<  ctxt.size() << std::endl;
  ctxt.reLinearize();

  // Double it (using additions)
  ctxt += ctxt;
  
  // Create a plaintext for decryption
  std::vector<long> decrypted(nslots);
  // Decrypt the modified ciphertext
  ea.decrypt(ctxt, secret_key, decrypted);
  
  // Print the decrypted plaintext
  std::cout << "Decrypted Ptxt: " << helib::vecToStr(decrypted) << std::endl;
  setTimersOff();
//	printAllTimers();
  return 0;
}
