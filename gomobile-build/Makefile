.PHONY: build clean

build:
	gomobile bind -trimpath -target android/arm,android/arm64 -androidapi 21 \
		-ldflags '-s -w -checklinkname=0 -extldflags -Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
		-o ../app/libs/golibs.aar \
		dnstt-mobile/mobile \
		snowflake-mobile/snowflake

clean:
	rm -f ../app/libs/golibs.aar ../app/libs/golibs-sources.jar
