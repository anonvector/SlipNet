.PHONY: build build-full build-lite clean stage

# Reproducible builds: gomobile records the absolute directory of every local
# `replace` (../noizdns, ../vaydns, ...) in the libraries' module info, which
# -trimpath does not cover. Building through a fixed path makes the AARs
# independent of where the repository is checked out.
BUILD_ROOT := /tmp/slipnet-gomobile

# Default: build both
build: build-full build-lite

stage:
	ln -sfn "$(abspath ..)" $(BUILD_ROOT)

build-full: stage
	cd $(BUILD_ROOT)/gomobile-build && gomobile bind -trimpath -target android/arm,android/arm64,android/amd64 -androidapi 21 \
		-ldflags '-s -w -checklinkname=0 -extldflags -Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
		-o ../app/libs/golibs-full.aar \
		noizdns/mobile \
		vaydns-mobile/vaydns \
		soar-mobile/soar \
		snowflake-mobile/snowflake

build-lite: stage
	cd $(BUILD_ROOT)/gomobile-build && gomobile bind -trimpath -target android/arm,android/arm64,android/amd64 -androidapi 21 \
		-ldflags '-s -w -checklinkname=0 -extldflags -Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
		-o ../app/libs/golibs-lite.aar \
		noizdns/mobile \
		vaydns-mobile/vaydns \
		soar-mobile/soar

clean:
	rm -f ../app/libs/golibs-full.aar ../app/libs/golibs-full-sources.jar
	rm -f ../app/libs/golibs-lite.aar ../app/libs/golibs-lite-sources.jar
	rm -f ../app/libs/golibs.aar ../app/libs/golibs-sources.jar
