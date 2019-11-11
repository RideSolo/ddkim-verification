# ddkim-verification
on-chain verification of dkim signature 

# Description

The developed Dapp does the e-mail preprocessing offchain then passes the canonicalized header plus the signature to the ethereum contract for verification, since it is strictly unecessary to do the email processing inside the contract, resulting in extra gas consumption.

The canonicalized header can  be used later on inside the function to extract information such as email sender and receiver.

- RSA-SHA256 verification on-chain cost through the testing an average of 112k gas 
- RSA-SHA1 verification on-chain costed  310k gas mainly due to fact that sha1 algorithm is not precompiled in the EVM.
- ED25519-SHA256 verification costed 700k with full onchain verification (ED25519-SHA256 is the most gas consumptive schere since it requires sha256/sha512/and edDsa algorithms, the implemented sha512 is not widely optimized and the gas consumption results can be reduced further).

# Instalation

cd ~

git clone https://github.com/RideSolo/ddkim-verification.git

cd ddkim-verification

npm install

truffle test
