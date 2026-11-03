// Implementation of the entry point. It parses the mode, hands the self-test harness to
// each test class, and reports the total. No test code lives here on purpose.
#include "main.h"

#include <cstdio>
#include <cstring>

#include "SelfTest.h"
#include "TestFunctions/math.h"
#include "TestFunctions/strings.h"
#include "TestFunctions/structs.h"

static void PrintUsage()
{
	std::printf("usage: da_tests [--selftest] [--golden] [module ...]\n");
	std::printf("  --selftest  check the hand-computed expectations (default)\n");
	std::printf("  --golden    print one JSON golden record per case on stdout\n");
	std::printf("  module      restrict to math, strings or structs\n");
}

int RunTestBinary(int argc, char **argv)
{
	CSelfTest::EMode mode = CSelfTest::MODE_REPORT;
	bool wantMath = false;
	bool wantStrings = false;
	bool wantStructs = false;
	bool anyModule = false;

	for (int index = 1; index < argc; ++index)
	{
		const char *argument = argv[index];
		if (std::strcmp(argument, "--golden") == 0)
			mode = CSelfTest::MODE_GOLDEN;
		else if (std::strcmp(argument, "--selftest") == 0)
			mode = CSelfTest::MODE_REPORT;
		else if (std::strcmp(argument, "--help") == 0 || std::strcmp(argument, "-h") == 0)
		{
			PrintUsage();
			return 0;
		}
		else if (std::strcmp(argument, "math") == 0)
			wantMath = anyModule = true;
		else if (std::strcmp(argument, "strings") == 0)
			wantStrings = anyModule = true;
		else if (std::strcmp(argument, "structs") == 0)
			wantStructs = anyModule = true;
		else
		{
			std::fprintf(stderr, "unknown argument: %s\n", argument);
			PrintUsage();
			return 2;
		}
	}
	if (!anyModule)
	{
		wantMath = true;
		wantStrings = true;
		wantStructs = true;
	}

	CSelfTest selfTest(mode);
	if (wantMath)
		CMathTests::RunSelfChecks(selfTest);
	if (wantStrings)
		CStringTests::RunSelfChecks(selfTest);
	if (wantStructs)
		CStructTests::RunSelfChecks(selfTest);
	return selfTest.Report();
}

int main(int argc, char **argv)
{
	return RunTestBinary(argc, argv);
}
