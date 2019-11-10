pragma solidity >=0.4.21 <0.6.0;

import "./algorithms/BytesUtils.sol";
import "./algorithms/RSA.sol";
import "./algorithms/ED25519.sol";
import "./algorithms/SHA1.sol";

import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

contract DkimChecker is Ownable, RSA, ED25519, SHA1 {
    using BytesUtils for *;

    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//

    struct KeyRsa {
        bytes exponent;
        bytes modulus;
    }

    struct KeyEd {
        uint x;
        uint y;
    }

    address public oracle; 	// to be set to the oracle contract address for access restrictions
    mapping(bytes32 => mapping(bytes32 => KeyRsa)) public dkimKeysRsa;     // domain name => selector => key
    mapping(bytes32 => mapping(bytes32 => KeyEd)) public dkimKeysEd;     // domain name => selector => bytes(key)
    
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//

    constructor(address _oracle) public {
        oracle =_oracle;
    }

    // Should be used with all function involving the oracle interaction, for access restrictions
    modifier onlyOracle() {
    	if(msg.sender != oracle) revert("The msg.sender is different than the oracle address");
    	_;
    }

    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//

    // Dkim key setter function to be used bu
    function setDkimKeyRsa(string memory _selector, string memory _domain, bytes memory _exponent, bytes memory _modulus) public onlyOracle returns(bool){
        // Extra requirements can be added here to avoid issue with domainkey dns record update
        KeyRsa storage key = dkimKeysRsa[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];
        key.exponent = _exponent;
        key.modulus = _modulus;
        return true;
    }

    function setDkimKeyEd(string memory _selector, string memory _domain, uint x, uint y) public onlyOracle returns(bool){
        // Extra requirements can be added here to avoid issue with domainkey dns record update
        KeyEd storage key = dkimKeysEd[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))] ;
        key.x = x;
        key.y = y;
        return true;
    }

    function getDkimKeyRsa(string memory _selector, string memory _domain) public view returns (bytes memory,bytes memory) {
        KeyRsa memory key = dkimKeysRsa[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];
        return (key.exponent,key.modulus);
    }

    function getDkimKeyEd(string memory _selector, string memory _domain) public view returns (uint x, uint y) {
        KeyEd memory key = dkimKeysEd[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];
        return (key.x,key.y);
    }
    
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//

    event ReturnVal(bool);

    function checkBodySHA1(bytes memory body, bytes20 bodyHash) public returns (bool){
      bytes20 computed = sha1(body);

        emit ReturnVal(bodyHash == computed); // just added to simulate a non-view function
        return true;
    }

    function checkBodySHA256(bytes memory body, bytes32 bodyHash) public returns (bool){
      bytes32 computed = sha256(body);

        emit ReturnVal(bodyHash == computed); // just added to simulate a non-view function
        return true;
    }

    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//
    // ----------------------------------------------------------------------------------------------------//

    function verifyRSASHA256(string memory _selector, string memory _domain, bytes memory _sig, bytes memory _canonicalizedHeader) public returns (bool) {
        // Recover the message from the signature
        KeyRsa memory key = dkimKeysRsa[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];

        bool ok;
        bytes memory result;
        (ok, result) = modexp(_sig, key.exponent, key.modulus);
        bool bl = ( ok &&  sha256(_canonicalizedHeader) == result.readBytes32(result.length - 32) );
        
        emit ReturnVal(bl); // just added to simulate a non-view function
        return bl;
    }

    function verifyRSASHA1(string memory _selector, string memory _domain,bytes memory _sig,  bytes memory _canonicalizedHeader) public returns (bool) {

        KeyRsa memory key = dkimKeysRsa[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];

        bool ok;
        bytes memory result;
        (ok, result) = modexp(_sig, key.exponent, key.modulus);
        bool bl = (ok &&  sha1(_canonicalizedHeader) == result.readBytes20(result.length - 20) );
        
        emit ReturnVal(bl); // just added to simulate a non-view function
        return bl;
    }

    // For more details abt ed25519 verification function check https://tools.ietf.org/html/rfc8032#section-5.1
    // "_R" and "_s" are the signature component.
    // _hash is the sha512 of abi.encodePacked(r,p,sha256(_canonicalizedHeader))
    
    function verifyED25519( string memory _selector, string memory _domain, uint[2] memory _R, uint[2] memory _lhs ,uint _hash)
    public returns (bool)
    {
        KeyEd memory key = dkimKeysEd[keccak256(abi.encodePacked(_selector))][keccak256(abi.encodePacked(_domain))];
        uint[2] memory rhs;

        (rhs[0], rhs[1])  = scalarMult([key.x , key.y], _hash);
        uint[2] memory Rs = ecAddVec(_R,rhs);

        bool bl = (_lhs[0] == Rs[0] && _lhs[1] == Rs[1]);

        emit ReturnVal(bl); // just added to simulate a non-view function
        return bl;
    }
}
