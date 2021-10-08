# dydx-cpp-order-placing

The steps to run the program are as follows:

1) Change the input in the main() function according to your requirements.
2) export LD_LIBRARY_PATH=/Users/vanshajchadha/Desktop/dydx
3) g++ -std=c++17 -I /Users/vanshajchadha/Desktop/dydx/libraries/ -c dydxFunc.cpp
4) g++-11 -std=c++17 /Users/vanshajchadha/Desktop/dydx/libcrypto_c_exports.dylib -o dydx dydxFunc.o -lcurl
5) ./dydx
