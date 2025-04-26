# Testing

This folder contains various xtensa assembly files, used to test the functionalities of the instructions implemented.
They should be split based on Xtensa Options

Boolean option - test_bin.S

Command used for compilation
xt-clang --xtensa-core=XRC_FusionF1_All_cache test_bin.S -o test_bin.o