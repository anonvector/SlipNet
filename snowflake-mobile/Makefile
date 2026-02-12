.PHONY: build clean

build:
	gomobile bind -target android/arm,android/arm64 -androidapi 21 \
		-o ../app/libs/snowflake.aar ./snowflake

clean:
	rm -f ../app/libs/snowflake.aar ../app/libs/snowflake-sources.jar
