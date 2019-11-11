pragma solidity >=0.4.21 <0.6.0;
import "./ED25519.sol";

contract SHA512 is ED25519 {

  uint[80]  K = 
            [ uint256(0x428a2f98d728ae22), 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];
    
  uint[8]  H = [ uint256(0x6a09e667f3bcc908), 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
           0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 ];

  function sha512modl(uint256 _r, uint256 _p, uint256 _hx ) public view returns(uint hashmodl){

    uint[80] memory W;
    initW(_r,_p,_hx ,W);
    uint[8] memory Ai = update(W);
    
    for(uint i=0;i<8;i++) Ai[i] = (Ai[i] + H[i]) & 0xFFFFFFFFFFFFFFFF;
    (uint high, uint low) = arrayToLE(Ai);

    hashmodl  =addmod(mulmod(mulmod(high,2**128,l),mulmod(2**128,1,l),l),mulmod(low,1,l),l);
  }

  function arrayToLE(uint[8] memory Ai)  pure public returns  (uint high, uint low){
    uint _high = (Ai[0] << 192) | (Ai[1] << 128) | (Ai[2] << 64) | Ai[3];
    uint _low  = (Ai[4] << 192) | (Ai[5] << 128)| (Ai[6] << 64) | Ai[7];
    assembly{
      let block := mload(0x40)
      mstore(add(block,0x20),_high)
      mstore(add(block,0x40),_low)
      mstore(0x40,add(block,0x60))
      let start_add := add(block,1)
      for { let i := start_add } lt(i, add(start_add,32)) { i := add(i, 1) } {
        low := add(low,shl(mul(sub(i,start_add),8),and(mload(i),0xFF)))
      }
      start_add := add(start_add,32)
      for { let i := start_add } lt(i, add(start_add,32)){ i := add(i, 1) } {
        high := add(high,shl(mul(sub(i,start_add),8),and(mload(i),0xFF)))
      }
    }
  }

  function initW(uint _r, uint _p, uint _hx , uint[80] memory w) public pure {
    assembly {
      let block := mload(0x40)
      let modulo :=exp(2,64)
      mstore(add(block,0x00),_r)
      mstore(add(block,0x20),_p)
      mstore(add(block,0x40),_hx)
      mstore(add(block,0x60),or(768,shl(128,exp(2,127))))
      mstore(0x40,add(block,0x80))
      
      for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
        mstore(
          add(w,mul(0x20,i)),
          and(
            mload(add(sub(block,24),mul(i,8))),
            0xFFFFFFFFFFFFFFFF
          )
        )
      }
      for { let i := 16 } lt(i, 80) { i := add(i, 1) } {
        let w_a := mload(add(w,mul(sub(i,15),0x20)))
        let w_b := mload(add(w,mul(sub(i,2),0x20)))
        let w_c := mload(add(w,mul(sub(i,16),0x20)))
        let w_d := mload(add(w,mul(sub(i,7),0x20)))

        let s0 := and(xor(xor(or(shr(1,w_a),shl(63,w_a)),or(shr(8,w_a),shl(56,w_a))),shr(7,w_a)),0xFFFFFFFFFFFFFFFF)
        let s1 := and(xor(xor(or(shr(19,w_b),shl(45,w_b)),or(shr(61,w_b),shl(3,w_b))),shr(6,w_b)),0xFFFFFFFFFFFFFFFF)
        
        mstore(add(w,mul(i,0x20)),and(
            add(add(w_c,s0),add(w_d,s1)),0xFFFFFFFFFFFFFFFF
          )
        )
      }
    }
  }

  function update(uint[80] memory W) public view returns(uint[8] memory){
    
    uint a = H[0];
    uint b = H[1];
    uint c = H[2];
    uint d = H[3];
    uint e = H[4];
    uint f = H[5];
    uint g = H[6];
    uint h = H[7];
    
    for(uint i=0;i<80;i++) {
    
      /*uint modulo = 2**64;*/
      
      uint S1 = ( rotr(e,14) ) ^ ( rotr(e,18) ) ^ ( rotr(e,41) );
      uint ch = ( e & f ) ^ ((~e) & g);
      uint temp1 = h+S1+ch+W[i]+K[i];
      uint S0 = (rotr(a,28)) ^ (rotr(a,34)) ^ (rotr(a,39));
      uint maj = ( a & b ) ^ ( a & c); 
      maj = maj ^ ( b & c );
      uint temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = addmod(d,temp1, 2**64);
      d = c;
      c = b;
      b = a;
      a = addmod(temp1,temp2, 2**64);
    }
    return [ a, b, c, d, e, f, g, h ];
  }

  /*  function finalize(uint[8] memory H,uint[8] memory A) public view {
    uint modulo = 2**64;
    for(uint i=0;i<8;i++) H[i] = addmod(H[i],A[i],modulo); 
  }*/

  function rotr(uint value, uint d) public pure returns (uint) {
    return (value >> d | value << (64-d)) & 0xFFFFFFFFFFFFFFFF;
  }
}
