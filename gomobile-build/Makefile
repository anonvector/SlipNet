.PHONY: build build-full build-lite clean

# Default: build both
build: build-full build-lite

build-full:
	gomobile bind -trimpath -target android/arm,android/arm64 -androidapi 21 \
		-ldflags '-s -w -checklinkname=0 -extldflags -Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
		-o ../app/libs/golibs-full.aar \
		noizdns/mobile \
		snowflake-mobile/snowflake

build-lite:
	gomobile bind -trimpath -target android/arm64 -androidapi 21 \
		-ldflags '-s -w -checklinkname=0 -extldflags -Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
		-o ../app/libs/golibs-lite.aar \
		noizdns/mobile

clean:
	rm -f ../app/libs/golibs-full.aar ../app/libs/golibs-full-sources.jar
	rm -f ../app/libs/golibs-lite.aar ../app/libs/golibs-lite-sources.jar
	rm -f ../app/libs/golibs.aar ../app/libs/golibs-sources.jar
