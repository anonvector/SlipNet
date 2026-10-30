.PHONY: build test clean

build:
	gomobile bind -trimpath -target android/arm,android/arm64,android/amd64 -androidapi 21 \
		-ldflags '-s -w' \
		-o ../app/libs/soar.aar ./soar

test:
	go test ./soar

clean:
	rm -f ../app/libs/soar.aar ../app/libs/soar-sources.jar
