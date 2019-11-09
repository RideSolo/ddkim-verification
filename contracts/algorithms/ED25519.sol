/*MIT License

Copyright (c) 2019, Jan Vornberger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// ------------------------------------------------------------------------------------ //
// modified by ridesolo@protonmail.com to include:
//      - call to ecAdd with projective coordinate handling
//      - multiplication of any point.
//      - signature verification for a given hash (please note that the hash should be precomputed) 
// ------------------------------------------------------------------------------------ //

pragma solidity ^0.5.0;

// Using formulas from https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
// and constants from https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03

contract ED25519 {
    uint constant q  = 2 ** 255 - 19;
    // = -(121665/121666)
    uint constant d  = 37095705934669439343138083508754565189542113879843219016388785533085940283555;
                      
    uint constant Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint constant By = 46316835694926478169428394003475163141307993866256225615783033603165251855960;

    // structure to be used for projective point coordinate
    struct Point {
        uint x;
        uint y;
        uint z;
    }

    struct Scratchpad {
        uint a;
        uint b;
        uint c;
        uint d;
        uint e;
        uint f;
        uint g;
        uint h;
    }

    function inv(uint a) internal view returns (uint invA) {
        uint e = q - 2;
        uint m = q;

        // use bigModExp precompile
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20)
            mstore(add(p, 0x20), 0x20)
            mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), a)
            mstore(add(p, 0x80), e)
            mstore(add(p, 0xa0), m)
            if iszero(staticcall(not(0), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            invA := mload(p)
        }
    }

    function ecAdd(Point memory p1,
                   Point memory p2) internal pure returns (Point memory p3) {
        Scratchpad memory tmp;

        tmp.a = mulmod(p1.z, p2.z, q);
        tmp.b = mulmod(tmp.a, tmp.a, q);
        tmp.c = mulmod(p1.x, p2.x, q);
        tmp.d = mulmod(p1.y, p2.y, q);

        tmp.e = mulmod(d, mulmod(tmp.c, tmp.d, q), q);
        tmp.f = addmod(tmp.b, q - tmp.e, q);
        tmp.g = addmod(tmp.b, tmp.e, q);
        p3.x = mulmod(mulmod(tmp.a, tmp.f, q),
                      addmod(addmod(mulmod(addmod(p1.x, p1.y, q),
                                           addmod(p2.x, p2.y, q), q),
                                    q - tmp.c, q), q - tmp.d, q), q);

        p3.y = mulmod( mulmod(tmp.a, tmp.g, q), addmod(tmp.d, tmp.c, q), q);

        p3.z = mulmod(tmp.f, tmp.g, q);
    }

    // --- added function to handdle point addition with projection ----------- //

    function ecAddVec(uint[2] memory _a,uint[2] memory _b) public view returns (uint[2] memory) {

        Point memory a;
        Point memory b;
        a.x = _a[0];
        a.y = _a[1];
        a.z = 1;        

        b.x = _b[0];
        b.y = _b[1];
        b.z = 1;

        Point memory c = ecAdd(a,b);

        uint invZ = inv(c.z);
        return [mulmod(c.x,invZ,q),mulmod(c.y,invZ,q)];
    }

    function ecDouble(Point memory p1) internal pure returns (Point memory p2) {
        Scratchpad memory tmp;

        tmp.a = addmod(p1.x, p1.y, q);
        tmp.b = mulmod(tmp.a, tmp.a, q);
        tmp.c = mulmod(p1.x, p1.x, q);
        tmp.d = mulmod(p1.y, p1.y, q);
        tmp.e = q - tmp.c;
        tmp.f = addmod(tmp.e, tmp.d, q);
        tmp.h = mulmod(p1.z, p1.z, q);
        tmp.g = addmod(tmp.f, q - mulmod(2, tmp.h, q), q);

        p2.x = mulmod(addmod(addmod(tmp.b, q - tmp.c, q), q - tmp.d, q), tmp.g, q);
        p2.y = mulmod(tmp.f, addmod(tmp.e, q - tmp.d, q), q);

        p2.z = mulmod(tmp.f, tmp.g, q);
    }

    // changed from scalarMultiBase to scalarMulti to handle multiplication of any given point

    function scalarMult(uint256[2] memory point ,uint s) public view returns (uint, uint) {
        Point memory b;
        Point memory result;
        b.x = point[0];
        b.y = point[1];
        b.z = 1;
        result.x = 0;
        result.y = 1;
        result.z = 1;

        while (s > 0) {
            if (s & 1 == 1) { result = ecAdd(result, b); }
            s = s >> 1;
            b = ecDouble(b);
        }

        uint invZ = inv(result.z);
        result.x = mulmod(result.x, invZ, q);
        result.y = mulmod(result.y, invZ, q);

        return (result.x, result.y);
    }
}