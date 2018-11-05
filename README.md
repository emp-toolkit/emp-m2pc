# EMP-m2pc[![Build Status](https://travis-ci.org/emp-toolkit/emp-m2pc.svg?branch=master)](https://travis-ci.org/emp-toolkit/emp-m2pc)
<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

## Faster Secure Two-Party Computation in the Single-Execution Setting

More details of the protocol can be found in the [paper](https://eprint.iacr.org/2016/762).

## Installation

1. Install prerequisites using instructions [here](https://github.com/emp-toolkit/emp-readme).
2. Install [emp-tool](https://github.com/emp-toolkit/emp-tool).
3. Install [emp-ot](https://github.com/emp-toolkit/emp-ot).
4. git clone https://github.com/emp-toolkit/emp-m2pc.git
5. cd emp-m2pc && cmake . && make 

## Test

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP address is hardcoded in the test files. Please replace
  SERVER_IP variable to the real ip.

### Question
Please send email to wangxiao@cs.umd.edu

## Acknowledgement
This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.
