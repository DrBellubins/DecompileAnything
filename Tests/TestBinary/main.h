// Entry point of the test binary, only calls other classes that have the actual test code
#ifndef DA_MAIN_H
#define DA_MAIN_H

// Kept as a function so the binary can be linked into a test driver without a main clash.
int RunTestBinary(int argc, char **argv);

#endif // DA_MAIN_H
