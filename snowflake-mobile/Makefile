.PHONY: build clean

build:
	gomobile bind -trimpath -target android/arm,android/arm64,android/amd64 -androidapi 21 \
		-ldflags '-s -w' \
		-o ../app/libs/snowflake.aar ./snowflake

clean:
	rm -f ../app/libs/snowflake.aar ../app/libs/snowflake-sources.jar
