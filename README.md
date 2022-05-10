# Cryptanalysis of K-Cipher

----------
###Structure of the project
This project is a c++ implementation of differential cryptanalysis attack to [K-Cipher](https://eprint.iacr.org/2020/030.pdf).
The project contains the following files;    
* `KCipher.h`: Includes headers for the functions of K-Cipher.
* `KCipher.cpp`: Includes the implemenation of the functions of K-Cipher.
* `main.cpp`: Includes the attack.
* `CMakeLists.txt`: cmake file for running the code
_____________________
   
###Run the attack
To run the attack, run the following commands in the root directory of the project:
```bash
cmake .
make
./K_Cipher
```
### Round 3 attack
The first phase of the attack is to recover $r_1^2$ and $k_3$. This is done in the function `attack_round_3();`. 
For each block, the function recovers two candidates for $k_3$ and $r_1^2$. Having $k_3$ we can also recover $k_2$ because $k_2$ is a known permutation of $k_3$. 

### Round 2 attack
This round recovers $r_0^2$ and $r_1^1$. This is done in the function `attack_round_2();`. 
For this attack, we used the fact that we can change the order of xor and BitReordering and also distribute circular shift over modular addition (which works with probability 0.41 for 8-bit SBox).
The values return by the function are $r_1^1 >>_2 + k_2$ and $r_0^2$. Since $k_2$ is known, we can easily compute $r_1^1$. 

### Round 1 attack
This round recovers $r_0^1 >>2 + k_1$ and $r_0^1$. This is done in the function `attack_round_1();`.
For this attack, we used the fact that we can change the order of xor and BitReordering and also distribute circular shift over modular addition (which works with probability 0.41 for 8-bit SBox).
All the values recovered can are in the same equivalence classes and can be used to simulate the circuit.

### Recovering $k_0$ and $r_0^0$
This can be done using equation solving. There is no Sbox and with a pair of plaintext and partially decrypted ciphertext, one can recover these values.


_____________________________
Please note that the code is only tested on Ubuntu machine (`5.13.0-27-generic x86_64`). To run on other platforms please make sure that the 
randomness generation has sufficient entropy.    

