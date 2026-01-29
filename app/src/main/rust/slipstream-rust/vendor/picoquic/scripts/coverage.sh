make clean
rm CMakeCache.txt
mkdir -p covr
find . -name "*.gcda" -exec rm {} \;
find . -name "*.gcno" -exec rm {} \;
find . -name "*.gcov" -exec rm {} \;
COMPILER="-DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++" 
COVERAGE="-fprofile-arcs -ftest-coverage"
echo $COVERAGE
cmake "-DCMAKE_C_FLAGS=$COVERAGE" "-DCMAKE_CXX_FLAGS=$COVERAGE" $COMPILER .
make
./picoquic_ct -n
./picohttp_ct -n
EXCLUDED="-e picoquictest/ -e baton_app/ -e sample/ -e picoquic_t/"
EXCLUDED="$EXCLUDED -e thread_tester/ -e CMakeFiles/ -e picoquicfirst/ -e picohttp_t"
EXCLUDED="$EXCLUDED -e picolog/"
gcovr -r . $EXCLUDED --gcov-ignore-parse-errors --html --html-details -o covr/picoquic-cover.html
