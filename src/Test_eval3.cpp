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


namespace std {} using namespace std;
namespace NTL {} using namespace NTL;


#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include "powerful.h"
#include "permutations.h"

#include <cassert>



template<class type>
class Step1Matrix : public PlaintextBlockMatrixInterface<type> 
{
public:
  PA_INJECT(type)

private:
  const EncryptedArray& ea;

  shared_ptr<CubeSignature> sig;
  long dim;

  Mat< mat_R > A;

public:
  // constructor
  Step1Matrix(const EncryptedArray& _ea, 
              shared_ptr<CubeSignature> _sig,
              const Vec<long>& reps,
              long _dim,
              long cofactor,
              bool invert = false);

  virtual const EncryptedArray& getEA() const { return ea; }

  virtual bool get(mat_R& out, long i, long j) const;
              
};

template<class type>
bool Step1Matrix<type>::get(mat_R& out, long i, long j) const
{
  long i1 = sig->getCoord(i, dim);
  long j1 = sig->getCoord(j, dim);

  if (sig->addCoord(i, dim, -i1) != sig->addCoord(j, dim, -j1)) 
    return true;

  out = A[i1][j1];
  return false;
}

template<class type>
Step1Matrix<type>::Step1Matrix(const EncryptedArray& _ea, 
                               shared_ptr<CubeSignature> _sig,
                               const Vec<long>& reps,
                               long _dim,
                               long cofactor,
                               bool invert)
: ea(_ea), sig(_sig), dim(_dim)
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  const RX& G = ea.getDerived(type()).getG();

  assert(dim == sig->getNumDims() - 1);
  assert(sig->getSize() == ea.size());

  long sz = sig->getDim(dim);
  assert(sz == reps.length());

  long d = deg(G);

  // so sz == phi(m_last)/d, where d = deg(G) = order of p mod m

  Vec<RX> points;
  points.SetLength(sz);
  for (long j = 0; j < sz; j++) 
    points[j] = RX(reps[j]*cofactor, 1) % G;

  Mat<RX> AA;

  AA.SetDims(sz*d, sz);
  for (long j = 0; j < sz; j++)
    AA[0][j] = 1;

  for (long i = 1; i < sz*d; i++)
    for (long j = 0; j < sz; j++)
      AA[i][j] = (AA[i-1][j] * points[j]) % G;

  A.SetDims(sz, sz);
  for (long i = 0; i < sz; i++)
    for (long j = 0; j < sz; j++) {
      A[i][j].SetDims(d, d);
      for (long k = 0; k < d; k++)
        VectorCopy(A[i][j][k], AA[i*d + k][j], d);
    }


  if (invert) {
    REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

    mat_R A1, A2;

    A1.SetDims(sz*d, sz*d);
    for (long i = 0; i < sz*d; i++)
      for (long j = 0; j < sz*d; j++)
        A1[i][j] = A[i/d][j/d][i%d][j%d];


    long p = ea.getAlMod().getZMStar().getP();
    long r = ea.getAlMod().getR();

    ppInvert(A2, A1, p, r);

    for (long i = 0; i < sz*d; i++)
      for (long j = 0; j < sz*d; j++)
        A[i/d][j/d][i%d][j%d] = A2[i][j];
 }
}


PlaintextBlockMatrixBaseInterface*
buildStep1Matrix(const EncryptedArray& ea, 
                 shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps,
                 long dim,
                 long cofactor,
                 bool invert = false)
{
  switch (ea.getAlMod().getTag()) {
  case PA_GF2_tag: 
    return new Step1Matrix<PA_GF2>(ea, sig, reps, dim, cofactor, invert);

  case PA_zz_p_tag: 
    return new Step1Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor, invert);

  default: return 0;
  }
}

/***** END Step1 stuff *****/



template<class type>
class Step2Matrix : public PlaintextMatrixInterface<type> 
{
public:
  PA_INJECT(type)

private:
  const EncryptedArray& ea;
  shared_ptr<CubeSignature> sig;
  long dim;

  Mat<RX> A;

public:
  // constructor
  Step2Matrix(const EncryptedArray& _ea, 
              shared_ptr<CubeSignature> _sig,
              const Vec<long>& reps,
              long _dim,
              long cofactor,
              bool invert = false);

  virtual const EncryptedArray& getEA() const { return ea; }

  virtual bool get(RX& out, long i, long j) const;
              
};

template<class type>
bool Step2Matrix<type>::get(RX& out, long i, long j) const
{
  long i1 = sig->getCoord(i, dim);
  long j1 = sig->getCoord(j, dim);

  if (sig->addCoord(i, dim, -i1) != sig->addCoord(j, dim, -j1)) 
    return true;

  out = A[i1][j1];
  return false;
}

template<class type>
Step2Matrix<type>::Step2Matrix(const EncryptedArray& _ea, 
                               shared_ptr<CubeSignature> _sig,
                               const Vec<long>& reps,
                               long _dim,
                               long cofactor,
                               bool invert)
: ea(_ea), sig(_sig), dim(_dim)
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  const RX& G = ea.getDerived(type()).getG();

  long sz = sig->getDim(dim);
  assert(sz == reps.length());


  Vec<RX> points;
  points.SetLength(sz);
  for (long j = 0; j < sz; j++) 
    points[j] = RX(reps[j]*cofactor, 1) % G;

  A.SetDims(sz, sz);
  for (long j = 0; j < sz; j++)
    A[0][j] = 1;

  for (long i = 1; i < sz; i++)
    for (long j = 0; j < sz; j++)
      A[i][j] = (A[i-1][j] * points[j]) % G;

  if (invert) {
    REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

    mat_RE A1, A2;
    conv(A1, A);

    long p = ea.getAlMod().getZMStar().getP();
    long r = ea.getAlMod().getR();

    ppInvert(A2, A1, p, r);
    conv(A, A2);
 }
}


PlaintextMatrixBaseInterface*
buildStep2Matrix(const EncryptedArray& ea, 
                 shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps,
                 long dim,
                 long cofactor,
                 bool invert = false)
{
  switch (ea.getAlMod().getTag()) {
  case PA_GF2_tag: 
    return new Step2Matrix<PA_GF2>(ea, sig, reps, dim, cofactor, invert);

  case PA_zz_p_tag: 
    return new Step2Matrix<PA_zz_p>(ea, sig, reps, dim, cofactor, invert);

  default: return 0;
  }
}



// two-step tower stuff...

class TowerBase { 
public:
  virtual ~TowerBase() { }
};

template<class type>
class Tower : public TowerBase {
public:
  PA_INJECT(type)

  long cofactor, d1, d2, p, r;

  long d;
  RE zeta; // = [X^cofactor mod G]

  RX H;  // = the min poly of zeta over R

  Mat<R> M2, M2i;
  // M2 is the matrix that takes us from the two-step tower
  // to the one-step tower, and M2i is its inverse.

  mutable shared_ptr< Mat<RE> > linPolyMatrix;


  Tower(long _cofactor, long _d1, long _d2, long _p, long _r)
    : cofactor(_cofactor), d1(_d1), d2(_d2), p(_p), r(_r) 
  {
    d = RE::degree();
    assert(d == d1*d2);

    const RXModulus& G = RE::modulus();

    zeta = conv<RE>(RX(cofactor, 1));  // zeta = [X^cofactor mod G]

    // compute H = min poly of zeta over R

    Mat<R> M1;
    M1.SetDims(d1, d);

    for (long i = 0; i < d1; i++) {
      VectorCopy(M1[i], rep(power(zeta, i)), d);
    }

    Vec<R> V1;
    VectorCopy(V1, rep(power(zeta, d1)), d);

    Mat<R> M1sq;

    Mat<R> R1;
    R1.SetDims(d, d1);

    for (;;) {
      for (long i = 0; i < d; i++)
        for (long j = 0; j < d1; j++)
          random(R1[i][j]);

      M1sq = M1*R1;
    
      Mat<long> M1sqInt = conv< Mat<long> >(M1sq);
      {
         RBak bak; bak.save();
         GenericModulus<R>::init(p);
         Mat<R> M1sq_modp = conv< Mat<R> >(M1sqInt);
         if (determinant(M1sq_modp) != 0) break;
      }
   
    }

    Vec<R> V1sq = V1*R1;

    Mat<R> M1sqi;
    ppInvert(M1sqi, M1sq, p, r);

    Vec<R> W1 = V1sq * M1sqi;

    assert(W1*M1 == V1);

    H = RX(d1, 1) - conv<RX>(W1);
    // H is the min poly of zeta

    assert(eval(H, zeta) == 0);

    // compute matrices M2 and M2i

    M2.SetDims(d, d);

    for (long i = 0; i < d2; i++) {
      // construct rows [i..i+d1)
      for (long j = 0; j < d1; j++) {
         VectorCopy(M2[i*d1+j], (rep(power(zeta, j)) << i) % G, d);
      }
    }

    ppInvert(M2i, M2, p, r);
  }


  // converts an object represented in the two-step
  // tower representation to the one-step representation

  RE convert2to1(const Vec<RX>& v) const
  {
    assert(v.length() <= d2);

    Vec<R> w;
    w.SetLength(d);

    for (long i = 0; i < v.length(); i++) {
      assert(deg(v[i]) < d1);
      for (long j = 0; j <= deg(v[i]); j++) 
        w[i*d1 + j] = v[i][j];
    }

    Vec<R> z = w*M2;
    return conv<RE>( conv<RX>( z ) );
  }

  // performs the reverse conversion

  Vec<RX> convert1to2(const RE& beta) const
  {
    Vec<R> z = VectorCopy(rep(beta), d);
    Vec<R> w = z*M2i;

    Vec<RX> res;
    res.SetLength(d2);

    for (long i = 0; i < d2; i++) {
      Vec<R> tmp;
      tmp.SetLength(d1);
      for (long j = 0; j < d1; j++)
        tmp[j] = w[i*d1+j];

      res[i] = conv<RX>(tmp);
    }

    return res;
  }

  void buildLinPolyMatrix(Mat<RE>& M) const
  {
     ZZ q = power_ZZ(p, d1);

     M.SetDims(d2, d2);

     for (long j = 0; j < d2; j++) 
        conv(M[0][j], RX(j, 1));

     for (long i = 1; i < d2; i++)
        for (long j = 0; j < d2; j++)
           M[i][j] = power(M[i-1][j], q);
  }



  void buildLinPolyCoeffs(Vec<RE>& C_out, const Vec<RE>& L) const
  {
     FHE_TIMER_START;

     if (!linPolyMatrix) {
       FHE_NTIMER_START(buildLinPolyCoeffs_buildMatrix);

       Mat<RE> M;
       buildLinPolyMatrix(M);
       Mat<RE> Minv;
       ppInvert(Minv, M, p, r);
       linPolyMatrix = shared_ptr< Mat<RE> >(new Mat<RE>(Minv) );
     }

     Vec<RE> C;
     mul(C, L, *linPolyMatrix);

     C_out = C;
  }

  void applyLinPoly(RE& beta, const Vec<RE>& C, const RE& alpha) const
  {
     assert(d2 == C.length());
     ZZ q = power_ZZ(p, d1);

     RE gamma, res;

     gamma = conv<RE>(RX(1, 1));
     res = C[0]*alpha;
     for (long i = 1; i < d2; i++) {
        gamma = power(gamma, q);
        res += C[i]*conv<RE>(CompMod(rep(alpha), rep(gamma), RE::modulus()));
     }

     beta = res;
  }


  void print(ostream& s, const PlaintextArray& v, long nrows) const
  {
    vector<ZZX> v1;
    v.decode(v1); 
    Vec<RX> v2;
    convert(v2, v1);
    for (long i = 0; i < v2.length(); i++) {
      if (i % nrows == 0) s << "\n";
      s << convert1to2(conv<RE>(v2[i])) << "\n";
    }
  }

};

template class Tower<PA_GF2>;
template class Tower<PA_zz_p>;

TowerBase* buildTowerBase(const EncryptedArray& ea, 
                      long cofactor, long d1, long d2)
{
  long p = ea.getAlMod().getZMStar().getP();
  long r = ea.getAlMod().getR();

  switch (ea.getAlMod().getTag()) {
    case PA_GF2_tag: {
      GF2EBak ebak; ebak.save(); 
      ea.restoreContextForG();
      return new Tower<PA_GF2>(cofactor, d1, d2, p, r);
    }
    case PA_zz_p_tag: {
      zz_pBak bak; bak.save(); zz_pEBak ebak; ebak.save();
      ea.restoreContext(); ea.restoreContextForG();
      return new Tower<PA_zz_p>(cofactor, d1, d2, p, r);
    }
    default: return 0;
  }
}


template<class type>
class Step1aMatrix : public PlaintextBlockMatrixInterface<type> 
{
public:
  PA_INJECT(type)

private:
  const EncryptedArray& ea;
  long cofactor, d1, d2, phim1;
  shared_ptr<TowerBase> towerBase;
  bool invert;



  Mat< mat_R > A;

public:
  // constructor
  Step1aMatrix(const EncryptedArray& _ea, 
              const Vec<long>& reps,
              long _cofactor, long _d1, long _d2, long _phim1,
              shared_ptr<TowerBase> _towerBase,
              bool _invert = false);

  virtual const EncryptedArray& getEA() const { return ea; }

  virtual bool get(mat_R& out, long i, long j) const;
              
};

template<class type>
bool Step1aMatrix<type>::get(mat_R& out, long i, long j) const
{
  long sz = phim1/d1;

  long i_lo = i*d2;
  long i_hi = i_lo + d2 - 1;
  long j_lo = j*d2;
  long j_hi = j_lo + d2 - 1;

  if (i_hi/sz < j_lo/sz || j_hi/sz < i_lo/sz) return true;

  long d = d1*d2;

  Mat<R> tmp;

  tmp.SetDims(d, d);
  clear(tmp);

  for (long i1 = i_lo; i1 <= i_hi; i1++)
    for (long j1 = j_lo; j1 <= j_hi; j1++) 
      if (i1/sz == j1/sz) {
        long i2 = i1 % sz;
        long j2 = j1 % sz;
        for (long i3 = 0; i3 < d1; i3++)
          for (long j3 = 0; j3 < d1; j3++)
            tmp[(i1-i_lo)*d1 + i3][(j1-j_lo)*d1 + j3] = A[i2][j2][i3][j3];
      }

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());

  if (invert)
    mul(out, tower->M2i, tmp);
  else
    mul(out, tmp, tower->M2);

  return false;
}

template<class type>
Step1aMatrix<type>::Step1aMatrix(const EncryptedArray& _ea, 
                               const Vec<long>& reps,
                               long _cofactor, long _d1, long _d2, long _phim1,
                               shared_ptr<TowerBase> _towerBase,
                               bool _invert)
: ea(_ea), cofactor(_cofactor), d1(_d1), d2(_d2), phim1(_phim1), 
  towerBase(_towerBase), invert(_invert)
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  long p = ea.getAlMod().getZMStar().getP();
  long r = ea.getAlMod().getR();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());

  const RX& H = tower->H;

  assert(phim1 % d1 == 0);

  long sz = phim1/d1;

  Vec<RX> points;
  points.SetLength(sz);
  for (long j = 0; j < sz; j++)
    points[j] = RX(reps[j], 1) % H;

  Mat<RX> AA;
  AA.SetDims(sz*d1, sz);
  for (long j = 0; j < sz; j++)
    AA[0][j] = 1;

  for (long i = 1; i < sz*d1; i++)
    for (long j = 0; j < sz; j++)
      AA[i][j] = (AA[i-1][j] * points[j]) % H;

  A.SetDims(sz, sz);
  for (long i = 0; i < sz; i++)
    for (long j = 0; j < sz; j++) {
      A[i][j].SetDims(d1, d1);
      for (long k = 0; k < d1; k++)
        VectorCopy(A[i][j][k], AA[i*d1 + k][j], d1);
    }

  if (invert) {
    Mat<R> A1, A2;
    A1.SetDims(sz*d1, sz*d1);
    for (long i = 0; i < sz*d1; i++)
      for (long j = 0; j < sz*d1; j++)
        A1[i][j] = A[i/d1][j/d1][i%d1][j%d1];


    ppInvert(A2, A1, p, r);

    for (long i = 0; i < sz*d1; i++)
      for (long j = 0; j < sz*d1; j++)
        A[i/d1][j/d1][i%d1][j%d1] = A2[i][j];
  }
}


PlaintextBlockMatrixBaseInterface*
buildStep1aMatrix(const EncryptedArray& ea, 
                 const Vec<long>& reps,
                 long cofactor, long d1, long d2, long phim1,
                 shared_ptr<TowerBase> towerBase,
                 bool invert = false)
{
  switch (ea.getAlMod().getTag()) {
  case PA_GF2_tag: 
    return new Step1aMatrix<PA_GF2>(ea, reps, cofactor, d1, d2, phim1, towerBase, invert);

  case PA_zz_p_tag: 
    return new Step1aMatrix<PA_zz_p>(ea, reps, cofactor, d1, d2, phim1, towerBase, invert);

  default: return 0;
  }
}

/***** END Step1a stuff *****/


class Step2aShuffleBase {
public:

Vec<long> new_order;

virtual void apply(PlaintextArray& v) const = 0;
virtual void apply(Ctxt& v) const = 0;

};

template<class type>
class Step2aShuffle : public Step2aShuffleBase
{
public:
  PA_INJECT(type)

  virtual void apply(PlaintextArray& v) const
  {
    if (invert) 
      applyBack(v);
    else
      applyFwd(v);
  }

  virtual void apply(Ctxt& v) const
  {
    if (invert) 
      applyBack(v);
    else
      applyFwd(v);
  }



private:
  const EncryptedArray& ea;
  shared_ptr<CubeSignature> sig;
  Vec<long> reps;
  long dim;
  long cofactor;
  shared_ptr<TowerBase> towerBase;
  bool invert;
  

  long p, r, d, d1, d2, phim1, phim2, nrows;

  long hfactor;
  Vec<long> cshift;
  Mat<long> intraSlotPerm;
  Mat<long> eval_reordering;
  Mat<RE> eval_mat;
  Mat<RX> inv_mat;

  bool get(Vec<RE>& entry, long i, long j) const;
  bool iget(Vec<RE>& entry, long i, long j) const;

  typedef bool (Step2aShuffle<type>::*get_type)(Vec<RE>&, long, long) const; 

  void mat_mul(PlaintextArray& ctxt, get_type) const;
  void mat_mul(Ctxt& ctxt, get_type) const;

  void applyBack(PlaintextArray& v) const;
  void applyBack(Ctxt& v) const;

  void applyFwd(PlaintextArray& v) const;
  void applyFwd(Ctxt& v) const;

public:
  // constructor
  Step2aShuffle(const EncryptedArray& _ea, 
              shared_ptr<CubeSignature> _sig,
              const Vec<long>& _reps,
              long _dim,
              long _cofactor,
              shared_ptr<TowerBase> _towerBase,
              bool _invert = false);

};


template<class type>
Step2aShuffle<type>::Step2aShuffle(const EncryptedArray& _ea, 
                                   shared_ptr<CubeSignature> _sig,
                                   const Vec<long>& _reps,
                                   long _dim,
                                   long _cofactor,
                                   shared_ptr<TowerBase> _towerBase,
                                   bool _invert)

: ea(_ea), sig(_sig), reps(_reps), dim(_dim), cofactor(_cofactor),
  towerBase(_towerBase), invert(_invert)
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());

  p = tower->p;
  r = tower->r;
  d = tower->d;
  d1 = tower->d1;
  d2 = tower->d2;

  phim1 = sig->getDim(dim+1); // actually, phim1/d1
  phim2 = sig->getDim(dim) * d2;

  // cout << "phim1=" << phim1 << ", phim2=" << phim2 << ", d2=" << d2 << "\n";

  nrows = phim1*phim2/d2;

  hfactor = GCD(d2, phim1);

  cshift.SetLength(d2);

  Mat< Pair<long, long> > mapping;
  mapping.SetDims(nrows, d2);

  for (long i = 0; i < phim1*phim2; i++)
    mapping[i/d2][i%d2] = Pair<long,long>(i%phim1, i/phim1);

  // cout << "mapping:\n";
  // cout << mapping << "\n";

  Mat<long> hshift;
  
  hshift.SetDims(nrows, d2/hfactor); 

  for (long j = 0 ; j < d2/hfactor; j++) {
    hshift[0][j] = 0;

    for (long i = 1; i < nrows; i++) 
      if (mapping[i][j*hfactor].a != 0)
        hshift[i][j] = hshift[i-1][j];
      else
        hshift[i][j] = (hshift[i-1][j] + 1) % hfactor;
  }

  // cout << "hshift:\n";
  // cout << hshift << "\n";

  // apply the hshift's to mapping

  for (long i = 0; i < nrows; i++) { 
    for (long j = 0; j < d2/hfactor; j++) {
      // rotate subarray mapping[i][j*hfactor..j*hfactor+hfactor-1]
      // by hshift[i][j]

      long amt = hshift[i][j];

      Vec< Pair<long, long> > tmp1, tmp2;
      tmp1.SetLength(hfactor);
      tmp2.SetLength(hfactor);
 
      for (long k = 0; k < hfactor; k++) tmp1[k] = mapping[i][j*hfactor+k];
      for (long k = 0; k < hfactor; k++) tmp2[(k+amt)%hfactor] = tmp1[k];
      for (long k = 0; k < hfactor; k++) mapping[i][j*hfactor+k] = tmp2[k];
    }
  }

  
  // cout << "mapping:\n";
  // cout << mapping << "\n";

  for (long j = 0; j < d2; j++) {
    long amt = 0;

    while (mapping[0][j].a != 0) {
      amt++;

      // rotate column j of mapping mapping by 1
      Vec< Pair<long, long> > tmp1, tmp2;
      tmp1.SetLength(nrows);
      tmp2.SetLength(nrows);

      for (long i = 0; i < nrows; i++) tmp1[i] = mapping[i][j];
      for (long i = 0; i < nrows; i++) tmp2[(i+1)%nrows] = tmp1[i];
      for (long i = 0; i < nrows; i++) mapping[i][j] = tmp2[i];
    } 

    cshift[j] = amt;
  }

  // cout << "mapping:\n";
  // cout << mapping << "\n";

  new_order.SetLength(phim1);
  for (long i = 0; i < phim1; i++)
    new_order[i] = mapping[i][0].a;

  // cout << new_order << "\n";


  intraSlotPerm.SetDims(nrows, d2);

  for (long i = 0; i < nrows; i++)
    for (long j = 0; j < d2; j++)
      intraSlotPerm[i][j] = (j/hfactor)*hfactor + mcMod(j - hshift[i][j/hfactor], hfactor);

  eval_reordering.SetDims(phim1, phim2);

  for (long i = 0; i < nrows; i++)
    for (long j = 0; j < d2; j++) {
      eval_reordering[i % phim1][(i / phim1)*d2 + j] = mapping[i][j].b;
      assert(mapping[i][j].a == new_order[i % phim1]);
    }

  // cout << "eval_reordering: \n";
  // cout << eval_reordering << "\n";

  eval_mat.SetDims(phim2, phim2/d2);

  Vec<RE> points;
  points.SetLength(phim2/d2);
  for (long j = 0; j < phim2/d2; j++)
    points[j] = conv<RE>(RX(reps[j]*cofactor, 1));

  for (long j = 0; j < phim2/d2; j++)
    eval_mat[0][j] = 1;

  for (long i = 1; i < phim2; i++)
    for (long j = 0; j < phim2/d2; j++)
      eval_mat[i][j] = eval_mat[i-1][j] * points[j];

  if (invert) {
    Mat<RX> inv_mat1;
    inv_mat1.SetDims(phim2, phim2);
    for (long i = 0; i < phim2; i++) {
      for (long j = 0; j < phim2/d2; j++) {
        Vec<RX> tmp1 = tower->convert1to2(eval_mat[i][j]);
        for (long k = 0; k < d2; k++)
          inv_mat1[i][j*d2+k] = tmp1[k];
      }
    }

    eval_mat.kill(); // we no longer need it

    { // temporarily switch RE::modulus to the minpoly of the subring
      REBak ebak1; ebak1.save();
      RE::init(tower->H);
      Mat<RE> inv_mat2, inv_mat3;
      conv(inv_mat2, inv_mat1);
      ppInvert(inv_mat3, inv_mat2, p, r);
      conv(inv_mat, inv_mat3);
    }
  }

}

template<class type>
bool Step2aShuffle<type>::get(Vec<RE>& entry, long i, long j) const 
{
  long i1 = sig->getCoord(i, dim);
  long j1 = sig->getCoord(j, dim);

  if (sig->addCoord(i, dim, -i1) != sig->addCoord(j, dim, -j1)) 
    return true;

  long i2 = sig->getCoord(i, dim+1);

  for (long i3 = 0; i3 < d2; i3++) {
    entry[i3] = eval_mat[eval_reordering[i2][i1*d2+i3]][j1];
  }

  return false;
}


template<class type>
bool Step2aShuffle<type>::iget(Vec<RE>& entry, long i, long j) const 
{
  long i1 = sig->getCoord(i, dim);
  long j1 = sig->getCoord(j, dim);

  if (sig->addCoord(i, dim, -i1) != sig->addCoord(j, dim, -j1)) 
    return true;

  long j2 = sig->getCoord(j, dim+1);

  Mat<RX> tmp;
  tmp.SetDims(d2, d2);
  for (long i3 = 0; i3 < d2; i3++)
    for (long j3 = 0; j3 < d2; j3++)
      tmp[i3][j3] = inv_mat[i1*d2+i3][eval_reordering[j2][j1*d2+j3]];

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());

  for (long i3 = 0; i3 < d2; i3++) {
    entry[i3] = tower->convert2to1(tmp[i3]);
  }

  return false;
}


template<class type>
void Step2aShuffle<type>::mat_mul(PlaintextArray& ctxt, get_type get_fn) const
{
  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();

  // ctxt.reLinearize(); 

  PlaintextArray res(ea);

  Vec<RE> entry;
  entry.SetLength(d2);

  Vec<RE> C;
  C.SetLength(d2);

  
  Vec< Vec<RX> > diag;
  diag.SetLength(nslots);
  for (long j = 0; j < nslots; j++) diag[j].SetLength(d2);

  for (long i = 0; i < nslots; i++) {
    // process diagonal i


    bool zDiag = true;
    long nzLast = -1;

    for (long j = 0; j < nslots; j++) {
      bool zEntry = (this->*get_fn)(entry, mcMod(j-i, nslots), j);

      if (!zEntry) {    // non-empty entry

        zDiag = false;  // mark diagonal as non-empty

        // clear entries between last nonzero entry and this one

        for (long jj = nzLast+1; jj < j; jj++) {
          for (long k = 0; k < d2; k++)
            clear(diag[jj][k]);
        }

        nzLast = j;

        // compute the lin poly coeffs
        tower->buildLinPolyCoeffs(C, entry);
        conv(diag[j], C);
      }
    }

    if (zDiag) continue; // zero diagonal, continue

    // clear trailing zero entries    
    for (long jj = nzLast+1; jj < nslots; jj++) {
      for (long k = 0; k < d2; k++)
        clear(diag[jj][k]);
    }

    // now diag[j] contains the lin poly coeffs

    PlaintextArray shCtxt = ctxt;
    shCtxt.rotate(i); 

    // apply the linearlized polynomial
    for (long k = 0; k < d2; k++) {

      // compute the constant
      bool zConst = true;
      vector<ZZX> cvec;
      cvec.resize(nslots);
      for (long j = 0; j < nslots; j++) {
        convert(cvec[j], diag[j][k]);
        if (!IsZero(cvec[j])) zConst = false;
      }

      if (zConst) continue;

      PlaintextArray cpoly(ea);
      cpoly.encode(cvec);
      // FIXME: record the encoded polynomial for future use

      PlaintextArray shCtxt1 = shCtxt;
      shCtxt1.frobeniusAutomorph(k*d1);
      shCtxt1.mul(cpoly);
      res.add(shCtxt1);
    }
  }
  ctxt = res;
}

template<class type>
void Step2aShuffle<type>::mat_mul(Ctxt& ctxt, get_type get_fn) const
{
  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();

  ctxt.reLinearize(); 

  Ctxt res(ZeroCtxtLike, ctxt);

  Vec<RE> entry;
  entry.SetLength(d2);

  Vec<RE> C;
  C.SetLength(d2);

  
  Vec< Vec<RX> > diag;
  diag.SetLength(nslots);
  for (long j = 0; j < nslots; j++) diag[j].SetLength(d2);

  for (long i = 0; i < nslots; i++) {
    // process diagonal i

    bool zDiag = true;
    long nzLast = -1;

    for (long j = 0; j < nslots; j++) {
      bool zEntry = (this->*get_fn)(entry, mcMod(j-i, nslots), j);

      if (!zEntry) {    // non-empty entry

        zDiag = false;  // mark diagonal as non-empty

        // clear entries between last nonzero entry and this one

        for (long jj = nzLast+1; jj < j; jj++) {
          for (long k = 0; k < d2; k++)
            clear(diag[jj][k]);
        }

        nzLast = j;

        // compute the lin poly coeffs
        tower->buildLinPolyCoeffs(C, entry);
        conv(diag[j], C);
      }
    }

    if (zDiag) continue; // zero diagonal, continue

    // clear trailing zero entries    
    for (long jj = nzLast+1; jj < nslots; jj++) {
      for (long k = 0; k < d2; k++)
        clear(diag[jj][k]);
    }

    // now diag[j] contains the lin poly coeffs

    Ctxt shCtxt = ctxt;
    ea.rotate(shCtxt, i); 

    // apply the linearlized polynomial
    for (long k = 0; k < d2; k++) {

      // compute the constant
      bool zConst = true;
      vector<ZZX> cvec;
      cvec.resize(nslots);
      for (long j = 0; j < nslots; j++) {
        convert(cvec[j], diag[j][k]);
        if (!IsZero(cvec[j])) zConst = false;
      }

      if (zConst) continue;

      ZZX cpoly;
      ea.encode(cpoly, cvec);
      // FIXME: record the encoded polynomial for future use

      Ctxt shCtxt1 = shCtxt;
      shCtxt1.frobeniusAutomorph(k*d1);
      shCtxt1.multByConstant(cpoly);
      res += shCtxt1;
    }
  }
  ctxt = res;
}






template<class type>
void Step2aShuffle<type>::applyFwd(PlaintextArray& v) const
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();

  // cout << "starting shuffle...\n";

  // tower->print(cout, v, nrows);

  // build linPolyCoeffs

  Mat< Vec<ZZX> > C;

  C.SetDims(d2, d2);
  for (long i = 0; i < d2; i++)
    for (long j = 0; j < d2; j++)
      C[i][j].SetLength(nrows);

  // C[i][j][k] is the j-th lin-poly coefficient
  // of the map that projects subslot intraSlotPerm[k][i]
  // onto subslot i

  for (long k = 0; k < nrows; k++) {
    for (long i = 0; i < d2; i++) {
      long idx_in = intraSlotPerm[k][i];
      long idx_out = i;

      Vec< Vec<RX> > map2;
      map2.SetLength(d2);
      map2[idx_in].SetLength(idx_out+1);
      map2[idx_in][idx_out] = 1;
      // map2 projects idx_in ontot idx_out

      Vec<RE> map1;
      map1.SetLength(d2);
      for (long j = 0; j < d2; j++)
        map1[j] = tower->convert2to1(map2[j]);

      Vec<RE> C1;
      tower->buildLinPolyCoeffs(C1, map1);

      for (long j = 0; j < d2; j++)
        C[i][j][k] = conv<ZZX>(rep(C1[j]));
    }
  }

  // mask each sub-slot

  Vec< shared_ptr<PlaintextArray> > frobvec; 
  frobvec.SetLength(d2);
  for (long j = 0; j < d2; j++) {
    shared_ptr<PlaintextArray> ptr(new PlaintextArray(v));
    ptr->frobeniusAutomorph(j*d1);
    frobvec[j] = ptr;
  }

  Vec< shared_ptr<PlaintextArray> > colvec;
  colvec.SetLength(d2);
  for (long i = 0; i < d2; i++) {
    shared_ptr<PlaintextArray> acc(new PlaintextArray(ea));

    for (long j = 0; j < d2; j++) {
      PlaintextArray const1(ea);

      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = C[i][j][k % nrows];
      const1.encode(vec1);

      PlaintextArray ctxt1(*frobvec[j]);

      ctxt1.mul(const1);
      acc->add(ctxt1);
    }

    colvec[i] = acc;
  }

  // for (long i = 0; i < d2; i++) {
    // cout << "column " << i << "\n";
    // tower->print(cout, *colvec[i], nrows);
  // }

  // rotate each subslot 

  for (long i = 0; i < d2; i++) {
    if (cshift[i] == 0) continue;

    if (nrows == nslots) {
      // simple rotation

      colvec[i]->rotate(cshift[i]);

    }
    else {
      // synthetic rotation 

      vector<long> mask;
      mask.resize(nslots);

      for (long j = 0; j < nslots; j++) 
        mask[j] = ((j % nrows) < (nrows - cshift[i]));

      PlaintextArray emask(ea);
      emask.encode(mask);

      PlaintextArray tmp1(*colvec[i]), tmp2(*colvec[i]);

      tmp1.mul(emask);
      tmp2.sub(tmp1);

      tmp1.rotate(cshift[i]);
      tmp2.rotate(-(nrows-cshift[i]));
      
      tmp1.add(tmp2);
      *colvec[i] = tmp1;
    }
  }

  // for (long i = 0; i < d2; i++) {
    // cout << "column " << i << "\n";
    // tower->print(cout, *colvec[i], nrows);
  // }

  // combine columns

  PlaintextArray v1(ea);
  for (long i = 0; i < d2; i++) 
    v1.add(*colvec[i]);


  // apply the matrix

  mat_mul(v1, &Step2aShuffle<type>::get);

  v = v1;
}


template<class type>
void Step2aShuffle<type>::applyBack(PlaintextArray& v) const
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();


  mat_mul(v, &Step2aShuffle<type>::iget);

  Mat< Vec<ZZX> > C;

  C.SetDims(d2, d2);
  for (long i = 0; i < d2; i++)
    for (long j = 0; j < d2; j++)
      C[i][j].SetLength(nrows);

  // C[i][j][k] is the j-th lin-poly coefficient
  // of the map that projects subslot i
  // onto subslot i if hfactor == 1, or
  // onto subslot 0 if hfactor != 1

  for (long k = 0; k < nrows; k++) {
    for (long i = 0; i < d2; i++) {
      long idx_in = i;
      long idx_out = (hfactor == 1) ? i : 0;

      Vec< Vec<RX> > map2;
      map2.SetLength(d2);
      map2[idx_in].SetLength(idx_out+1);
      map2[idx_in][idx_out] = 1;
      // map2 projects idx_in ontot idx_out

      Vec<RE> map1;
      map1.SetLength(d2);
      for (long j = 0; j < d2; j++)
        map1[j] = tower->convert2to1(map2[j]);

      Vec<RE> C1;
      tower->buildLinPolyCoeffs(C1, map1);

      for (long j = 0; j < d2; j++)
        C[i][j][k] = conv<ZZX>(rep(C1[j]));
    }
  }

  // mask each sub-slot

  Vec< shared_ptr<PlaintextArray> > frobvec; 
  frobvec.SetLength(d2);
  for (long j = 0; j < d2; j++) {
    shared_ptr<PlaintextArray> ptr(new PlaintextArray(v));
    ptr->frobeniusAutomorph(j*d1);
    frobvec[j] = ptr;
  }

  Vec< shared_ptr<PlaintextArray> > colvec;
  colvec.SetLength(d2);
  for (long i = 0; i < d2; i++) {
    shared_ptr<PlaintextArray> acc(new PlaintextArray(ea));

    for (long j = 0; j < d2; j++) {
      PlaintextArray const1(ea);

      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = C[i][j][k % nrows];
      const1.encode(vec1);

      PlaintextArray ctxt1(*frobvec[j]);

      ctxt1.mul(const1);
      acc->add(ctxt1);
    }

    colvec[i] = acc;
  }
  

  // rotate each subslot 

  for (long i = 0; i < d2; i++) {
    long shamt = mcMod(-cshift[i], nrows);

    if (shamt == 0) continue;

    if (nrows == nslots) {
      // simple rotation

      colvec[i]->rotate(shamt);

    }
    else {
      // synthetic rotation 

      vector<long> mask;
      mask.resize(nslots);

      for (long j = 0; j < nslots; j++) 
        mask[j] = ((j % nrows) < (nrows - shamt));

      PlaintextArray emask(ea);
      emask.encode(mask);

      PlaintextArray tmp1(*colvec[i]), tmp2(*colvec[i]);

      tmp1.mul(emask);
      tmp2.sub(tmp1);

      tmp1.rotate(shamt);
      tmp2.rotate(-(nrows-shamt));
      
      tmp1.add(tmp2);
      *colvec[i] = tmp1;
    }
  }

  // combine columns...
  // optimized to avoid unnecessary constant muls
  // when hfactor == 1

  PlaintextArray v1(ea);

  if (hfactor == 1) {
    for (long i = 0; i < d2; i++) { 
      v1.add(*colvec[i]);
    }
  }
  else {
    for (long i = 0; i < d2; i++) { 
      PlaintextArray const1(ea);
      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = conv<ZZX>(RX(intraSlotPerm[k%nrows][i], 1) % RE::modulus());
      const1.encode(vec1);

      PlaintextArray ctxt1(*colvec[i]);
      ctxt1.mul(const1);
      
      v1.add(ctxt1);
    }
  }

  v = v1;
}




template<class type>
void Step2aShuffle<type>::applyBack(Ctxt& v) const
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();


  mat_mul(v, &Step2aShuffle<type>::iget);
  v.reLinearize();

  Mat< Vec<ZZX> > C;

  C.SetDims(d2, d2);
  for (long i = 0; i < d2; i++)
    for (long j = 0; j < d2; j++)
      C[i][j].SetLength(nrows);

  // C[i][j][k] is the j-th lin-poly coefficient
  // of the map that projects subslot i
  // onto subslot i if hfactor == 1, or
  // onto subslot 0 if hfactor != 1

  for (long k = 0; k < nrows; k++) {
    for (long i = 0; i < d2; i++) {
      long idx_in = i;
      long idx_out = (hfactor == 1) ? i : 0;

      Vec< Vec<RX> > map2;
      map2.SetLength(d2);
      map2[idx_in].SetLength(idx_out+1);
      map2[idx_in][idx_out] = 1;
      // map2 projects idx_in ontot idx_out

      Vec<RE> map1;
      map1.SetLength(d2);
      for (long j = 0; j < d2; j++)
        map1[j] = tower->convert2to1(map2[j]);

      Vec<RE> C1;
      tower->buildLinPolyCoeffs(C1, map1);

      for (long j = 0; j < d2; j++)
        C[i][j][k] = conv<ZZX>(rep(C1[j]));
    }
  }

  // mask each sub-slot

  Vec< shared_ptr<Ctxt> > frobvec; 
  frobvec.SetLength(d2);
  for (long j = 0; j < d2; j++) {
    shared_ptr<Ctxt> ptr(new Ctxt(v));
    ptr->frobeniusAutomorph(j*d1);
    frobvec[j] = ptr;
  }

  Vec< shared_ptr<Ctxt> > colvec;
  colvec.SetLength(d2);
  for (long i = 0; i < d2; i++) {
    shared_ptr<Ctxt> acc(new Ctxt(ZeroCtxtLike, v));

    for (long j = 0; j < d2; j++) {
      ZZX const1;

      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = C[i][j][k % nrows];
      ea.encode(const1, vec1);

      Ctxt ctxt1(*frobvec[j]);

      ctxt1.multByConstant(const1);
      (*acc) += ctxt1;
    }

    colvec[i] = acc;
  }
  

  // rotate each subslot 

  for (long i = 0; i < d2; i++) {
    long shamt = mcMod(-cshift[i], nrows);

    if (shamt == 0) continue;

    if (nrows == nslots) {
      // simple rotation

      ea.rotate(*colvec[i], shamt);
    }
    else {
      // synthetic rotation 

      vector<long> mask;
      mask.resize(nslots);

      for (long j = 0; j < nslots; j++) 
        mask[j] = ((j % nrows) < (nrows - shamt));

      ZZX emask;
      ea.encode(emask, mask);

      Ctxt tmp1(*colvec[i]), tmp2(*colvec[i]);

      tmp1.multByConstant(emask);
      tmp2 -= tmp1;

      ea.rotate(tmp1, shamt);
      ea.rotate(tmp2, -(nrows-shamt));
      
      tmp1 += tmp2;
      *colvec[i] = tmp1;
    }
  }

  // combine columns...
  // optimized to avoid unnecessary constant muls
  // when hfactor == 1

  Ctxt v1(ZeroCtxtLike, v);

  if (hfactor == 1) {
    for (long i = 0; i < d2; i++) { 
      v1 += *colvec[i];
    }
  }
  else {
    for (long i = 0; i < d2; i++) { 
      ZZX const1;
      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = conv<ZZX>(RX(intraSlotPerm[k%nrows][i], 1) % RE::modulus());
      ea.encode(const1, vec1);

      Ctxt ctxt1(*colvec[i]);
      ctxt1.multByConstant(const1);
      
      v1 += ctxt1;
    }
  }

  v = v1;
}




template<class type>
void Step2aShuffle<type>::applyFwd(Ctxt& v) const
{
  RBak bak; bak.save(); ea.getAlMod().restoreContext();
  REBak ebak; ebak.save(); ea.getDerived(type()).restoreContextForG();

  Tower<type> *tower = dynamic_cast<Tower<type> *>(towerBase.get());
  long nslots = ea.size();

  // cout << "starting shuffle...\n";

  // tower->print(cout, v, nrows);

  // build linPolyCoeffs

  v.reLinearize();

  Mat< Vec<ZZX> > C;

  C.SetDims(d2, d2);
  for (long i = 0; i < d2; i++)
    for (long j = 0; j < d2; j++)
      C[i][j].SetLength(nrows);

  // C[i][j][k] is the j-th lin-poly coefficient
  // of the map that projects subslot intraSlotPerm[k][i]
  // onto subslot i

  for (long k = 0; k < nrows; k++) {
    for (long i = 0; i < d2; i++) {
      long idx_in = intraSlotPerm[k][i];
      long idx_out = i;

      Vec< Vec<RX> > map2;
      map2.SetLength(d2);
      map2[idx_in].SetLength(idx_out+1);
      map2[idx_in][idx_out] = 1;
      // map2 projects idx_in ontot idx_out

      Vec<RE> map1;
      map1.SetLength(d2);
      for (long j = 0; j < d2; j++)
        map1[j] = tower->convert2to1(map2[j]);

      Vec<RE> C1;
      tower->buildLinPolyCoeffs(C1, map1);

      for (long j = 0; j < d2; j++)
        C[i][j][k] = conv<ZZX>(rep(C1[j]));
    }
  }

  // FIXME: in the case where nrows != nslots, which
  // is the same as saying we are at dimension 0, we can
  // avoid the extra masking depth incurred for the 
  // synthetic rotations, by folding them into 
  // the masking/frobenius step. A similar optimization
  // applies to the applyBack routine.


  // mask each sub-slot

  Vec< shared_ptr<Ctxt> > frobvec; 
  frobvec.SetLength(d2);
  for (long j = 0; j < d2; j++) {
    shared_ptr<Ctxt> ptr(new Ctxt(v));
    ptr->frobeniusAutomorph(j*d1);
    frobvec[j] = ptr;
  }

  Vec< shared_ptr<Ctxt> > colvec;
  colvec.SetLength(d2);
  for (long i = 0; i < d2; i++) {
    shared_ptr<Ctxt> acc(new Ctxt(ZeroCtxtLike, v));

    for (long j = 0; j < d2; j++) {
      ZZX const1;

      vector<ZZX> vec1;
      vec1.resize(nslots);
      for (long k = 0; k < nslots; k++)
        vec1[k] = C[i][j][k % nrows];
      ea.encode(const1, vec1);

      Ctxt ctxt1(*frobvec[j]);

      ctxt1.multByConstant(const1);
      (*acc) += ctxt1;
    }

    colvec[i] = acc;
  }

  // for (long i = 0; i < d2; i++) {
    // cout << "column " << i << "\n";
    // tower->print(cout, *colvec[i], nrows);
  // }

  // rotate each subslot 

  for (long i = 0; i < d2; i++) {
    if (cshift[i] == 0) continue;

    if (nrows == nslots) {
      // simple rotation

      ea.rotate(*colvec[i], cshift[i]);

    }
    else {
      // synthetic rotation 

      vector<long> mask;
      mask.resize(nslots);

      for (long j = 0; j < nslots; j++) 
        mask[j] = ((j % nrows) < (nrows - cshift[i]));

      ZZX emask;
      ea.encode(emask, mask);

      Ctxt tmp1(*colvec[i]), tmp2(*colvec[i]);

      tmp1.multByConstant(emask);
      tmp2 -= tmp1;

      ea.rotate(tmp1, cshift[i]);
      ea.rotate(tmp2, -(nrows-cshift[i]));
      
      tmp1 += tmp2;
      *colvec[i] = tmp1;
    }
  }

  // for (long i = 0; i < d2; i++) {
    // cout << "column " << i << "\n";
    // tower->print(cout, *colvec[i], nrows);
  // }

  // conbine columns

  Ctxt v1(ZeroCtxtLike, v);
  for (long i = 0; i < d2; i++) 
    v1 += *colvec[i];


  // apply the matrix

  mat_mul(v1, &Step2aShuffle<type>::get);

  v = v1;
}




Step2aShuffleBase*
buildStep2aShuffle(const EncryptedArray& ea, 
                 shared_ptr<CubeSignature> sig,
                 const Vec<long>& reps,
                 long dim,
                 long cofactor,
                 shared_ptr<TowerBase> towerBase,
                 bool invert = false)
{
  switch (ea.getAlMod().getTag()) {
  case PA_GF2_tag: 
    return new Step2aShuffle<PA_GF2>(ea, sig, reps, dim, cofactor, towerBase, invert);

  case PA_zz_p_tag: 
    return new Step2aShuffle<PA_zz_p>(ea, sig, reps, dim, cofactor, towerBase, invert);

  default: return 0;
  }
}

/***** END Step2a stuff *****/





void init_representatives(Vec<long>& representatives, long m, long p)
{
  Vec<bool> available;
  available.SetLength(m);

  long num_available = 0;

  for (long i = 0; i < m; i++) {
    if (GCD(i, m) == 1) {
      available[i] = true;
      num_available++;
    }
    else
      available[i] = false;
  }

  representatives.SetLength(0);

  while (num_available > 0) {

    // choose next available at random
    long i;
    do {
      i = RandomBnd(m);
    } while (!available[i]);

    append(representatives, i);

    // mark all conjugates as unavailable
    long j = i;
    do {
      available[j] = false;
      num_available--;
      j = MulMod(j, p, m);
    } while (j != i);
  }
}


void alt_init_representatives(Vec<long>& rep, long m, long gen, long phim)
{
  rep.SetLength(phim);
  rep[0] = 1;
  for (long i = 1; i < phim; i++)
    rep[i] = MulMod(rep[i-1], gen, m);
}


void init_slot_mappings(Vec<long>& slot_index, 
                        Vec<long>& slot_rotate, 
                        const Vec<long>& representatives, 
                        long m,
                        long p,
                        const FHEcontext& context)
{
   long nslots = representatives.length();

   assert(nslots == long(context.zMStar.getNSlots()));

   slot_index.SetLength(nslots);
   slot_rotate.SetLength(nslots);

   Vec<bool> used; // for debugging
   used.SetLength(nslots);
   for (long i = 0; i < nslots; i++) used[i] = false;
   
   for (long i = 0; i < nslots; i++) {
     long t = representatives[i];
     long h = 0;
     long idx;
     while ((idx = context.zMStar.indexOfRep(InvMod(t, m))) == -1) {
       t = MulMod(t, p, m);
       h++;
     }

     assert(!used[idx]);
     used[idx] = true;
     slot_index[idx] = i;
     slot_rotate[idx] = h;
   }
}


void convertToPowerful(Vec<zz_p>& v, const zz_pX& F, const Vec<long>& mvec)
{ 
  long nfactors = mvec.length();

  long m = computeProd(mvec);
  
  Vec<long> phivec;
  phivec.SetLength(nfactors);
  for (long i = 0; i < nfactors; i++) phivec[i] = phi_N(mvec[i]);

  long phim = computeProd(phivec);

  Vec<long> divvec;
  computeDivVec(divvec, m, mvec);

  Vec<long> invvec;
  computeInvVec(invvec, divvec, mvec);

  CubeSignature shortsig(phivec);
  CubeSignature longsig(mvec);

  Vec<long> polyToCubeMap;
  Vec<long> cubeToPolyMap;
  computePowerToCubeMap(polyToCubeMap, cubeToPolyMap, m, mvec, invvec, longsig);

  Vec<long> shortToLongMap;
  computeShortToLongMap(shortToLongMap, shortsig, longsig);


  Vec<zz_pX> cycvec;
  computeCycVec(cycvec, mvec);


  ZZX PhimX = Cyclotomic(m);
  zz_pX phimX = conv<zz_pX>(PhimX);

  HyperCube<zz_p> cube(shortsig);
  HyperCube<zz_p> tmpCube(longsig);

  convertPolyToPowerful(cube, tmpCube, F, cycvec, 
                        polyToCubeMap, shortToLongMap);

  zz_pX poly1;

  convertPowerfulToPoly(poly1, cube, m, shortToLongMap, cubeToPolyMap, phimX);

  if (F == poly1)
    cout << "*********** :-)\n";
  else {
    cout << "*********** :-(\n";
    cout << F << "\n";
    cout << poly1 << "\n";
  }

  v.SetLength(phim);
  for (long i = 0; i < phim; i++) v[i] = cube[i];
}

// apply p^{vec[i]} to slot i
void frobeniusAutomorph(Ctxt& ctxt, const EncryptedArray& ea, const Vec<long>& vec)
{
  long d = ea.getDegree();
  long nslots = ea.size();

  // construct masks
  Vec<ZZX> masks;
  masks.SetLength(d);

  for (long i = 0; i < d; i++) {
    vector<long> mask1_vec;
    mask1_vec.resize(nslots);
    for (long j = 0; j < nslots; j++) 
      mask1_vec[j] = (mcMod(vec[j], d) == i);

    ZZX mask1_poly;
    ea.encode(mask1_poly, mask1_vec);
    masks[i] = mask1_poly;
  }

  ctxt.reLinearize();
  Ctxt acc(ZeroCtxtLike, ctxt);
  for (long i = 0; i < d; i++) {
    if (masks[i] != 0) {
      Ctxt tmp = ctxt;
      tmp.frobeniusAutomorph(i);
      tmp.multByConstant(masks[i]);
      acc += tmp;
    }
  }

  ctxt = acc;
}


class EvalMap {
private:
  const EncryptedArray& ea;
  bool invert; 

  bool easy;  // easy => d1 == d, 
              // !ease => d1 != d (but we d1 * d2 == d)

  long nfactors;

  shared_ptr<PlaintextBlockMatrixBaseInterface> mat1;
    // use for both easy and !easy

  shared_ptr<Step2aShuffleBase> shuffle;
  shared_ptr<TowerBase> tower;
    // use only in the !easy case

  Vec< shared_ptr<PlaintextMatrixBaseInterface> > matvec;

  shared_ptr<PermNetwork> net;
  Vec<long> slot_rotate;
    // used for the initial/final inter- and intra-slot rotations

  
public:

  EvalMap(const EncryptedArray& _ea, const Vec<long>& mvec, long width, 
          bool _invert);

  void apply(Ctxt& ctxt) const;
};


EvalMap::EvalMap(const EncryptedArray& _ea, const Vec<long>& mvec, 
                 long width, bool _invert)
  : ea(_ea), invert(_invert)
{
  const FHEcontext& context = ea.getContext();
  const PAlgebra& zMStar = context.zMStar;
  
  long p = zMStar.getP();
  long d = zMStar.getOrdP();

  // FIXME: we should check that ea was initilized with 
  // G == factors[0], but this is a slight pain to check
  // currently

  nfactors = mvec.length();

  assert(nfactors > 0);

  for (long i = 0; i < nfactors; i++)
    for (long j = i+1; j < nfactors; j++)
      assert(GCD(mvec[i], mvec[j]) == 1);

  long m = computeProd(mvec);
  assert(m == zMStar.getM());

  Vec<long> phivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)  phivec[i] = phi_N(mvec[i]);
  long phim = computeProd(phivec);

  Vec<long> dprodvec(INIT_SIZE, nfactors+1);
  dprodvec[nfactors] = 1;
  
  for (long i = nfactors-1; i >= 0; i--)
    dprodvec[i] = dprodvec[i+1] *
      multOrd(PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]), mvec[i]);

  Vec<long> dvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    dvec[i] = dprodvec[i] / dprodvec[i+1];

  long nslots = phim/d;
  assert(d == dprodvec[0]);
  assert(nslots == zMStar.getNSlots());

  long inertPrefix = 0;
  for (long i = 0; i < nfactors && dvec[i] == 1; i++) {
    inertPrefix++;
  }

  if (inertPrefix == nfactors-1)
    easy = true;
  else if (inertPrefix == nfactors-2)
    easy = false;
  else
    Error("EvalMap: case not handled: bad inertPrefix");

  Vec< Vec<long> > local_reps(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    init_representatives(local_reps[i], mvec[i], 
                         PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]));




  Vec<long> crtvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++) 
    crtvec[i] = (m/mvec[i]) * InvMod((m/mvec[i]) % mvec[i], mvec[i]);

  Vec<long> redphivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    redphivec[i] = phivec[i]/dvec[i];

  CubeSignature redphisig(redphivec);


  Vec<long> global_reps(INIT_SIZE, phim/d);
  for (long i = 0; i < phim/d; i++) {
    global_reps[i] = 0;
    for (long j = 0; j < nfactors; j++) {
      long i1 = redphisig.getCoord(i, j);
      global_reps[i] = (global_reps[i] + crtvec[j]*local_reps[j][i1]) % m;
    }
  }

  Vec<long> slot_index;
  init_slot_mappings(slot_index, slot_rotate, global_reps, m, p, context);

  Vec< shared_ptr<CubeSignature> > sig_sequence;
  sig_sequence.SetLength(nfactors+1);
  sig_sequence[nfactors] = shared_ptr<CubeSignature>(new CubeSignature(phivec));

  Vec<long> reduced_phivec = phivec;

  for (long dim = nfactors-1; dim >= 0; dim--) {
    reduced_phivec[dim] /= dvec[dim];
    sig_sequence[dim] = 
      shared_ptr<CubeSignature>(new CubeSignature(reduced_phivec));
  }

  if (easy) {
    long dim = nfactors - 1;

    mat1 = shared_ptr<PlaintextBlockMatrixBaseInterface>(
      buildStep1Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], invert));

    matvec.SetLength(nfactors-1);

    while (dim > 0) {
      dim--;
      matvec[dim] = shared_ptr<PlaintextMatrixBaseInterface>(
        buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], invert));
    }
  }
  else {
    long m1 = mvec[nfactors-1];
    long cofactor = m/m1;

    long d1 = dvec[nfactors-1];
    long d2 = d/d1;

    tower = shared_ptr<TowerBase>(buildTowerBase(ea, cofactor, d1, d2));
    long dim = nfactors-1;

    mat1 = shared_ptr<PlaintextBlockMatrixBaseInterface>(
      buildStep1aMatrix(ea, local_reps[dim], cofactor, d1, d2, phivec[dim], tower, invert));


    dim--;
    shuffle = shared_ptr<Step2aShuffleBase>(
      buildStep2aShuffle(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], tower, invert));

    
    long phim1 = shuffle->new_order.length();

    Vec<long> no_i; // inverse function
    no_i.SetLength(phim1);
    for (long i = 0; i < phim1; i++) 
      no_i[shuffle->new_order[i]] = i;

    Vec<long> slot_index1;
    slot_index1.SetLength(nslots);
    for (long i = 0; i < nslots; i++) 
      slot_index1[i] = (slot_index[i]/phim1)*phim1 + no_i[slot_index[i] % phim1];

    slot_index = slot_index1;

    matvec.SetLength(nfactors-2);

    while (dim > 0) {
      dim--;
      matvec[dim] = shared_ptr<PlaintextMatrixBaseInterface>(
        buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], invert));
    }
  }

  if (invert) {
    Vec<long> slot_index_i; // inverse function
    slot_index_i.SetLength(nslots);
    for (long i = 0; i < nslots; i++) 
      slot_index_i[slot_index[i]] = i;

    slot_index = slot_index_i; 

    for (long i = 0; i < nslots; i++)
      slot_rotate[i] = mcMod(-slot_rotate[i], d);
  }

  Vec<GenDescriptor> gvec(INIT_SIZE, ea.dimension());
  for (long i=0; i<ea.dimension(); i++)
    gvec[i] = GenDescriptor(/*order=*/ea.sizeOfDimension(i),
                            /*good=*/ ea.nativeDimension(i), /*genIdx=*/i); 

  GeneratorTrees trees;
  long cost = trees.buildOptimalTrees(gvec, width);

  if (cost == NTL_MAX_LONG)
    Error("EvalMap: can't build network for given width");

  net = shared_ptr<PermNetwork>(new PermNetwork(slot_index, trees));
}

void EvalMap::apply(Ctxt& ctxt) const
{
  if (!invert) {
    // forward direction

    ea.mat_mul(ctxt, *mat1);
    if (!easy) shuffle->apply(ctxt);

    for (long i = matvec.length()-1; i >= 0; i--) 
      ea.mat_mul(ctxt, *matvec[i]);

    net->applyToCtxt(ctxt, ea);
    frobeniusAutomorph(ctxt, ea, slot_rotate);

  }
  else {
    frobeniusAutomorph(ctxt, ea, slot_rotate);
    net->applyToCtxt(ctxt, ea);

    for (long i = 0; i < matvec.length(); i++)
      ea.mat_mul(ctxt, *matvec[i]);

    if (!easy) shuffle->apply(ctxt);
    ea.mat_mul(ctxt, *mat1);
  }
}











void  TestIt(long R, long p, long r, long c, long _k, long w, 
               long L, const Vec<long>& mvec)
{
  cerr << "*** TestIt: R=" << R 
       << ", p=" << p
       << ", r=" << r
       << ", c=" << c
       << ", k=" << _k
       << ", w=" << w
       << ", L=" << L
       << ", mvec=" << mvec
       << endl;

  setTimersOn();

  long nfactors = mvec.length();
  for (long i = 0; i < nfactors; i++)
    for (long j = i+1; j < nfactors; j++)
      assert(GCD(mvec[i], mvec[j]) == 1);


  long m = computeProd(mvec);
  assert(GCD(p, m) == 1); 

  Vec<long> phivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)  phivec[i] = phi_N(mvec[i]);
  long phim = computeProd(phivec);

  Vec<long> dprodvec(INIT_SIZE, nfactors+1);
  dprodvec[nfactors] = 1;
  
  for (long i = nfactors-1; i >= 0; i--)
    dprodvec[i] = dprodvec[i+1] *
      multOrd(PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]), mvec[i]);

  Vec<long> dvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    dvec[i] = dprodvec[i] / dprodvec[i+1];

  cout << "dvec=" << dvec << "\n";

  long d = dprodvec[0];
  long nslots = phim/d;

  long inertPrefix = 0;
  for (long i = 0; i < nfactors && dvec[i] == 1; i++) {
    inertPrefix++;
  }

  cout << "inertPrefix=" << inertPrefix << "\n";

  Vec< Vec<long> > local_reps(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    init_representatives(local_reps[i], mvec[i], 
                         PowerMod(p % mvec[i], dprodvec[i+1], mvec[i]));

  Vec<long> crtvec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++) 
    crtvec[i] = (m/mvec[i]) * InvMod((m/mvec[i]) % mvec[i], mvec[i]);

  Vec<long> redphivec(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++)
    redphivec[i] = phivec[i]/dvec[i];

  CubeSignature redphisig(redphivec);

  Vec<long> global_reps(INIT_SIZE, phim/d);
  for (long i = 0; i < phim/d; i++) {
    global_reps[i] = 0;
    for (long j = 0; j < nfactors; j++) {
      long i1 = redphisig.getCoord(i, j);
      global_reps[i] = (global_reps[i] + crtvec[j]*local_reps[j][i1]) % m;
    }
  }


  FHEcontext context(m, p, r);
  buildModChain(context, L, c);
  context.zMStar.printout();
  cerr << endl;


  FHESecKey secretKey(context);
  const FHEPubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key

  cerr << "generating key-switching matrices... ";
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need
  addFrbMatrices(secretKey); // compute key-switching matrices that we need
  cerr << "done\n";



  ZZX GG;
  GG = context.alMod.getFactorsOverZZ()[0];

  EncryptedArray ea(context, GG);

  zz_p::init(context.alMod.getPPowR());


  zz_pX F;
  random(F, phim);

  Vec<zz_p> cube;
  convertToPowerful(cube, F, mvec);

  {
    vector<ZZX> val1;
    val1.resize(nslots);
    for (long i = 0; i < phim; i++) {
      val1[i/d] += conv<ZZX>(conv<ZZ>(cube[i])) << (i % d);
    }
    PlaintextArray pa1(ea);
    pa1.encode(val1);

    PlaintextArray check_val(ea);
    Ctxt ctxt(publicKey);
    ea.encrypt(ctxt, publicKey, pa1);

    CheckCtxt(ctxt, "init");

    cout << "build EvalMap\n";
    EvalMap map(ea, mvec, 5, false);
    cout << "apply EvalMap\n";
    map.apply(ctxt);
    CheckCtxt(ctxt, "EvalMap");
    cout << "check results\n";

    ZZX FF1;
    secretKey.Decrypt(FF1, ctxt);
    zz_pX F1 = conv<zz_pX>(FF1);

    if (F1 == F) 
      cout << "EvalMap: good\n";
    else
      cout << "EvalMap: bad\n";

    publicKey.Encrypt(ctxt, FF1);
    CheckCtxt(ctxt, "init");

    cout << "build EvalMap\n";
    EvalMap imap(ea, mvec, 5, true);
    cout << "apply EvalMap\n";
    imap.apply(ctxt);
    CheckCtxt(ctxt, "EvalMap");
    cout << "check results\n";

    PlaintextArray pa2(ea);
    ea.decrypt(ctxt, secretKey, pa2);

    if (pa1.equals(pa2))
      cout << "EvalMap: good\n";
    else
      cout << "EvalMap: bad\n";


    exit(0);
  }



  zz_pX G = conv<zz_pX>(GG);
  zz_pE::init(G);




  Vec<zz_pE> global_points(INIT_SIZE, phim/d);
  for (long i = 0; i < phim/d; i++) 
    global_points[i] = conv<zz_pE>(zz_pX(global_reps[i], 1)); 


  Vec<zz_pE> global_values(INIT_SIZE, phim/d);
  for (long i = 0; i < phim/d; i++)
    global_values[i] = eval(F, global_points[i]);

  Vec< Vec<zz_pE> > local_points(INIT_SIZE, nfactors);
  for (long i = 0; i < nfactors; i++) {
    local_points[i].SetLength(phivec[i]/dvec[i]);
    for (long j = 0; j < phivec[i]/dvec[i]; j++)
      local_points[i][j] = conv<zz_pE>(zz_pX(local_reps[i][j]*(m/mvec[i]), 1));
  }

  // cout << "*** " << cube << "\n";

  Vec< Vec<zz_pE> > eval_sequence;
  eval_sequence.SetLength(nfactors+1);
  conv(eval_sequence[nfactors], cube);

  Vec< shared_ptr<CubeSignature> > sig_sequence;
  sig_sequence.SetLength(nfactors+1);
  sig_sequence[nfactors] = shared_ptr<CubeSignature>(new CubeSignature(phivec));

  Vec<long> reduced_phivec = phivec;

  for (long dim = nfactors-1; dim >= 0; dim--) {
    reduced_phivec[dim] /= dvec[dim];
    sig_sequence[dim] = 
      shared_ptr<CubeSignature>(new CubeSignature(reduced_phivec));

    shared_ptr<CubeSignature> old_sig = sig_sequence[dim+1];
    shared_ptr<CubeSignature> new_sig = sig_sequence[dim];

    

    long nslices = old_sig->getProd(0, dim); // same for both old and new
    long ncols = old_sig->getProd(dim+1);  // same for both old and new
    long old_colsz  = old_sig->getDim(dim);
    long new_colsz  = new_sig->getDim(dim);

    Vec<zz_pE> old_col(INIT_SIZE, old_colsz);
    zz_pEX old_col_as_poly;
    Vec<zz_pE> new_col(INIT_SIZE, new_colsz);

    eval_sequence[dim].SetLength(new_sig->getSize());

    for (long i = 0; i < nslices; i++) {
      for (long j = 0; j < ncols; j++) {
        // extract old column
        for (long k = 0; k < old_colsz; k++) 
          old_col[k] = eval_sequence[dim+1][i*old_colsz*ncols + j + k*ncols];

        // convert old column to a polynomial
        conv(old_col_as_poly, old_col);

        // compute new column
        for (long k = 0; k < new_colsz; k++)
          new_col[k] = eval(old_col_as_poly, local_points[dim][k]);

        // insert new column
        for (long k = 0; k < new_colsz; k++)
          eval_sequence[dim][i*new_colsz*ncols + j + k*ncols] = new_col[k];
      }
    }
  }

  if (global_values == eval_sequence[0]) 
    cout << "I win!!\n";
  else {
    cout << "I lose\n";
    cout << global_values << "\n";
    cout << eval_sequence[0] << "\n";
  }

  Vec<long> slot_index, slot_rotate;
  init_slot_mappings(slot_index, slot_rotate, global_reps, m, p, context);

  zz_pE H = conv<zz_pE>(zz_pX(p, 1));

  vector<ZZX> adjusted_values;
  adjusted_values.resize(nslots);

  for (long i = 0; i < nslots; i++) {
    zz_pE V = global_values[slot_index[i]];
    long h = slot_rotate[i];
    for (long j = 0; j < h; j++) 
      V = conv<zz_pE>(CompMod(rep(V), rep(H), G));
    
    adjusted_values[i] = conv<ZZX>(rep(V));
  }


  ZZX FF1;
  ea.encode(FF1, adjusted_values);
  
  zz_pX F1 = conv<zz_pX>(FF1);

  if (F1 == F) 
    cout << "yes!!\n";
  else 
    cout << "NO!!!\n";



  for (long dim = 0; dim < inertPrefix; dim++) {
    PlaintextMatrixBaseInterface *mat = 
      buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim]);

    PlaintextMatrixBaseInterface *imat = 
      buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], true);

    
    vector<ZZX> val1;
    val1.resize(nslots);
    for (long i = 0; i < nslots; i++) 
      val1[i] = conv<ZZX>(rep(eval_sequence[dim+1][i]));

    PlaintextArray pa1(ea);
    pa1.encode(val1);
    PlaintextArray pa1_orig(pa1);

    pa1.mat_mul(*mat);

    vector<ZZX> val2;
    val2.resize(nslots);
    for (long i = 0; i < nslots; i++) 
      val2[i] = conv<ZZX>(rep(eval_sequence[dim][i]));

    PlaintextArray pa2(ea);
    pa2.encode(val2);

    if (pa1.equals(pa2))
      cout << "dim=" << dim << " GOOD\n";
    else
      cout << "dim=" << dim << " BAD\n";

    pa1.mat_mul(*imat);
    if (pa1.equals(pa1_orig))
      cout << "dim=" << dim << " INV GOOD\n";
    else
      cout << "dim=" << dim << " INV BAD\n";

  }

  if (inertPrefix == nfactors-1) {
    cout << "easy case\n";

    long dim = nfactors-1;
    PlaintextBlockMatrixBaseInterface *mat = 
      buildStep1Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim]);

    PlaintextBlockMatrixBaseInterface *imat = 
      buildStep1Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim], true);


    vector<ZZX> val1;
    val1.resize(nslots);
    for (long i = 0; i < phim; i++) {
      val1[i/d] += conv<ZZX>(rep(eval_sequence[dim+1][i])) << (i % d);
    }
    PlaintextArray pa1(ea);
    pa1.encode(val1);
    PlaintextArray pa1_orig(pa1);

    pa1.mat_mul(*mat);

    vector<ZZX> val2;
    val2.resize(nslots);
    for (long i = 0; i < nslots; i++) 
      val2[i] = conv<ZZX>(rep(eval_sequence[dim][i]));

    PlaintextArray pa2(ea);
    pa2.encode(val2);

    if (pa1.equals(pa2))
      cout << "dim=" << dim << " GOOD\n";
    else
      cout << "dim=" << dim << " BAD\n";


    pa1.mat_mul(*imat);
    if (pa1.equals(pa1_orig))
      cout << "dim=" << dim << " INV GOOD\n";
    else
      cout << "dim=" << dim << " INV BAD\n";

  }
  else if (inertPrefix == nfactors-2) {

#if 1
    cout << "harder case\n";

    long m1 = mvec[nfactors-1];
    long cofactor = m/m1;

    long d1 = dvec[nfactors-1];
    long d2 = d/d1;

    Tower<PA_zz_p> tower(cofactor, d1, d2, p, r);

    zz_pX g;
    random(g, d1);
    zz_pE beta = eval(g, tower.zeta) * conv<zz_pE>(zz_pX(1, 1));

    cout << g << "\n";
    cout << tower.convert1to2(beta) << "\n";

    long dim = nfactors-1;

    shared_ptr<TowerBase>  towerBase(buildTowerBase(ea, cofactor, d1, d2));

    vector<ZZX> val1;
    val1.resize(nslots);
    for (long i = 0; i < phim; i++) {
      val1[i/d] += conv<ZZX>(rep(eval_sequence[dim+1][i])) << (i % d);
    }
    PlaintextArray pa1(ea);
    pa1.encode(val1);

    PlaintextArray check_val(ea);
    Ctxt ctxt(publicKey);
    ea.encrypt(ctxt, publicKey, pa1);

    CheckCtxt(ctxt, "init");

    cout << "starting computation\n";

    resetAllTimers();

    FHE_NTIMER_START(ALL);

    PlaintextBlockMatrixBaseInterface *mat =
      buildStep1aMatrix(ea, local_reps[dim], cofactor, d1, d2, phivec[dim], towerBase);

    pa1.mat_mul(*mat);
    ea.mat_mul(ctxt, *mat);
    CheckCtxt(ctxt, "Step1a");
    ea.decrypt(ctxt, secretKey, check_val);
    assert(pa1.equals(check_val));

    vector<ZZX> val2;
    val2.resize(nslots);
    for (long i = 0; i < nslots; i++) {
      Vec<zz_pX> one_slot;
      one_slot.SetLength(d2);
      for (long j = 0; j < d2; j++) {
        Vec<zz_pX> v = tower.convert1to2(eval_sequence[dim][i*d2 + j]);
        for (long k = 1; k < d2; k++) assert(v[k] == 0);
        one_slot[j] = v[0];
      }
      val2[i] = conv<ZZX>(rep(tower.convert2to1(one_slot)));
    }

    PlaintextArray pa2(ea);
    pa2.encode(val2);

    if (pa1.equals(pa2))
      cout << "dim=" << dim << " GOOD\n";
    else
      cout << "dim=" << dim << " BAD\n";

    dim--;

    Step2aShuffleBase *shuffle = 
      buildStep2aShuffle(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim],
                        towerBase);

#if 0
    Step2aShuffleBase *ishuffle = 
      buildStep2aShuffle(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim],
                        towerBase, true);
#endif


    PlaintextArray pa_tmp(pa1);

    shuffle->apply(pa1);

    shuffle->apply(ctxt);
    CheckCtxt(ctxt, "Step2a");
    ea.decrypt(ctxt, secretKey, check_val);
    assert(pa1.equals(check_val));

#if 0
    ishuffle->apply(pa1);

    if (pa1.equals(pa_tmp)) 
      cout << "ishuffle YES\n";
    else
      cout << "ishuffle NO\n";

    ishuffle->apply(ctxt);
    ea.decrypt(ctxt, secretKey, check_val);
    assert(pa1.equals(check_val));
#endif

    
    long phim1 = shuffle->new_order.length();

    Vec<long> no_i; // inverse function
    no_i.SetLength(phim1);
    for (long i = 0; i < phim1; i++) 
      no_i[shuffle->new_order[i]] = i;

    Vec<long> slot_index1, slot_rotate1;
    slot_index1.SetLength(nslots);
    for (long i = 0; i < nslots; i++) 
      slot_index1[i] = (slot_index[i]/phim1)*phim1 + no_i[slot_index[i] % phim1];

    vector<ZZX> val3;
    val3.resize(nslots);
    for (long i = 0; i < nslots; i++) 
      val3[i] = conv<ZZX>(rep(eval_sequence[dim][i]));

    vector<ZZX> val3a;
    val3a.resize(nslots);
    for (long i = 0; i < nslots/phim1; i++)
      for (long j = 0; j < phim1; j++)
        val3a[i*phim1 + j] = val3[i*phim1 + shuffle->new_order[j]];

    PlaintextArray pa3(ea);
    pa3.encode(val3a);

    if (pa1.equals(pa3))
      cout << "dim=" << dim << " GOOD\n";
    else
      cout << "dim=" << dim << " BAD\n";

    while (dim > 0) {
      dim--;

      PlaintextMatrixBaseInterface *mat2 = 
        buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim]);

      pa1.mat_mul(*mat2);

      ea.mat_mul(ctxt, *mat2);
      CheckCtxt(ctxt, "Step2");
      ea.decrypt(ctxt, secretKey, check_val);
      assert(pa1.equals(check_val));

      vector<ZZX> val3;
      val3.resize(nslots);
      for (long i = 0; i < nslots; i++) 
        val3[i] = conv<ZZX>(rep(eval_sequence[dim][i]));

      vector<ZZX> val3a;
      val3a.resize(nslots);
      for (long i = 0; i < nslots/phim1; i++)
        for (long j = 0; j < phim1; j++)
          val3a[i*phim1 + j] = val3[i*phim1 + shuffle->new_order[j]];

      PlaintextArray pa3(ea);
      pa3.encode(val3a);

      if (pa1.equals(pa3))
        cout << "dim=" << dim << " GOOD\n";
      else
        cout << "dim=" << dim << " BAD\n";

    }

    {
      vector<ZZX> vals;
      pa1.decode(vals);
      
      zz_pE H = conv<zz_pE>(zz_pX(p, 1));

      vector<ZZX> adjusted_vals;
      adjusted_vals.resize(nslots);

      for (long i = 0; i < nslots; i++) {
        zz_pE V = conv<zz_pE>(conv<zz_pX>(vals[slot_index1[i]]));
        long h = slot_rotate[i];
        for (long j = 0; j < h; j++) 
          V = conv<zz_pE>(CompMod(rep(V), rep(H), G));
        
        adjusted_vals[i] = conv<ZZX>(rep(V));
      }

      ZZX FF2;
      ea.encode(FF2, adjusted_vals);
      
      zz_pX F2 = conv<zz_pX>(FF2);

      if (F2 == F) 
        cout << "yes!!\n";
      else 
        cout << "NO!!!\n";

      { // apply final permutation to ctxt

        // estimate cost of other computations
        long est_cost = 0;
        for (long i = 0; i < nfactors; i++)
          est_cost += phivec[i];

        // Setup generator-descriptors for the PAlgebra generators
        Vec<GenDescriptor> vec(INIT_SIZE, ea.dimension());
        for (long i=0; i<ea.dimension(); i++)
          vec[i] = GenDescriptor(/*order=*/ea.sizeOfDimension(i),
                                 /*good=*/ ea.nativeDimension(i), /*genIdx=*/i); 

        long widthBound = 0;
        long cost = NTL_MAX_LONG;
        shared_ptr<GeneratorTrees> trees;
   
        const long MAX_WIDTH = 5;

        // Get the generator-tree structures and the corresponding hypercube
        while (cost > est_cost && (cost == NTL_MAX_LONG || widthBound <= MAX_WIDTH) ) {
          widthBound++;
          trees = shared_ptr<GeneratorTrees>(new GeneratorTrees());
          cost = trees->buildOptimalTrees(vec, widthBound);
          cout << "trees=" << *trees << endl;
          cout << "cost =" << cost << endl;
        }

        // Build a permutation network for slot_index1
        PermNetwork net;
        net.buildNetwork(slot_index1, *trees);

        net.applyToCtxt(ctxt, ea);
        CheckCtxt(ctxt, "perm");

        pa1.applyPerm(slot_index1);

        ea.decrypt(ctxt, secretKey, check_val);
        assert(pa1.equals(check_val));

        frobeniusAutomorph(ctxt, ea, slot_rotate);
        CheckCtxt(ctxt, "frob");
        pa1.frobeniusAutomorph(slot_rotate);

        ea.decrypt(ctxt, secretKey, check_val);
        assert(pa1.equals(check_val));

        {
          ZZX FF1;
          secretKey.Decrypt(FF1, ctxt);
          zz_pX F1 = conv<zz_pX>(FF1);

          assert(F1 == F);
        }
      }
    }

#else

    cout << "harder case\n"; 
    cout.flush();

    resetAllTimers();


    long m1 = mvec[nfactors-1];
    long cofactor = m/m1;

    long d1 = dvec[nfactors-1];
    long d2 = d/d1;

    long dim = nfactors-1;

    shared_ptr<TowerBase>  towerBase(buildTowerBase(ea, cofactor, d1, d2));

    vector<ZZX> val1;
    val1.resize(nslots);
    for (long i = 0; i < phim; i++) {
      val1[i/d] += conv<ZZX>(rep(eval_sequence[dim+1][i])) << (i % d);
    }
    PlaintextArray pa1(ea);
    pa1.encode(val1);

    PlaintextArray check_val(ea);
    Ctxt ctxt(publicKey);
    ea.encrypt(ctxt, publicKey, pa1);

    PlaintextBlockMatrixBaseInterface *mat =
      buildStep1aMatrix(ea, local_reps[dim], cofactor, d1, d2, phivec[dim], towerBase);

    cout << "first mul\n";
    cout.flush();
    ea.mat_mul(ctxt, *mat);

    dim--;

    Step2aShuffleBase *shuffle = 
      buildStep2aShuffle(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim],
                        towerBase);


    cout << "shuffle\n";
    cout.flush();
    shuffle->apply(ctxt);


    while (dim > 0) {
      dim--;

      PlaintextMatrixBaseInterface *mat2 = 
        buildStep2Matrix(ea, sig_sequence[dim], local_reps[dim], dim, m/mvec[dim]);

      cout << "mul\n";
      cout.flush();
      ea.mat_mul(ctxt, *mat2);

    }


#endif
    

  }
  else {
    cout << "case not handled\n";

  }


  cerr << "*********\n";
  printAllTimers();
  cerr << endl;

   

}




void usage(char *prog) 
{
  cerr << "Usage: "<<prog<<" [ optional parameters ]...\n";
  cerr << "  optional parameters have the form 'attr1=val1 attr2=val2 ...'\n";
  cerr << "  e.g, 'R=1 p=2 k=80'\n\n";
  cerr << "  R is the number of rounds\n";
  cerr << "  p is the plaintext base [default=2]" << endl;
  cerr << "  r is the lifting [default=1]" << endl;
  cerr << "  d is the degree of the field extension [default==0]\n";
  cerr << "    (d == 0 => factors[0] defined the extension)\n";
  cerr << "  c is number of columns in the key-switching matrices [default=2]\n";
  cerr << "  k is the security parameter [default=80]\n";
  cerr << "  L is the # of primes in the modulus chai [default=4*R]\n";
  cerr << "  s is the minimum number of slots [default=4]\n";
  cerr << "  m defined the cyclotomic polynomial Phi_m(X)\n";
  cerr << "  seed is the PRG seed\n";
  exit(0);
}


int main(int argc, char *argv[]) 
{
  argmap_t argmap;
  argmap["R"] = "1";
  argmap["p"] = "2";
  argmap["r"] = "1";
  argmap["c"] = "2";
  argmap["k"] = "80";
  argmap["L"] = "0";
  argmap["s"] = "0";
  argmap["m1"] = "0";
  argmap["m2"] = "0";
  argmap["m3"] = "0";
  argmap["m4"] = "0";
  argmap["seed"] = "0";

  // get parameters from the command line
  if (!parseArgs(argc, argv, argmap)) usage(argv[0]);

  long R = atoi(argmap["R"]);
  long p = atoi(argmap["p"]);
  long r = atoi(argmap["r"]);
  long c = atoi(argmap["c"]);
  long k = atoi(argmap["k"]);
  //  long z = atoi(argmap["z"]);
  long L = atoi(argmap["L"]);
  if (L==0) { // determine L based on R,r
    if (r==1) L = 2*R+2;
    else      L = 4*R;
  }
  long s = atoi(argmap["s"]);

  long m1 = atoi(argmap["m1"]);
  long m2 = atoi(argmap["m2"]);
  long m3 = atoi(argmap["m3"]);
  long m4 = atoi(argmap["m4"]);
  long seed = atoi(argmap["seed"]);

  long w = 64; // Hamming weight of secret key
  //  long L = z*R; // number of levels

  Vec<long> mvec;
  if (m1 != 0) append(mvec, m1);
  if (m2 != 0) append(mvec, m2);
  if (m3 != 0) append(mvec, m3);
  if (m4 != 0) append(mvec, m4);
  

  if (seed) SetSeed(conv<ZZ>(seed));

  TestIt(R, p, r, c, k, w, L, mvec);


}

//   [1 1 3 8] Test_eval3_x p=2 m1=3 m2=5 m3=7 m4=17
//   Test_eval3_x p=2 m1=11 m2=41 m3=31 (phim1=6, phim2=40, d2=4)
//   [1 1 20]  Test_eval3_x p=2 m1=3 m2=11 m3=25
//   [1 1 20]  Test_eval3_x p=2 m1=3 m2=11 m3=41
//   Test_eval3_x p=2 m1=3 m2=11 m3=17
//   Test_eval3_x p=2 m1=3 m2=5 m3=43 (phim1 == 3)
//   Test_eval3_x p=2 m1=7 m2=13 m3=73 (phim1=8, phim2=12, d2=4)
//   Test_eval3_x p=2 m1=7 m2=33 m3=73 (phim1=8, phim2=20, d2=10)