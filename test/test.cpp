#include <cpptest-lite/cpptest-main.h>
#include "addr_test.h"

int main(int argc, char* argv[]) {
    Test::setContinueAfterFail(true);
    Test::registerSuite(Test::newInstance<AddrTest>, "addr-tests");
    return Test::runSuites(argc, argv);
}