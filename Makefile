build:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ../bin/qrsecrets-windows-x64.exe
	GOOS=windows GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-windows.exe
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-windows-arm64.exe
	
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-darwin
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-darwin-arm64
	
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux-64
	GOOS=linux GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux-arm64

	GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd-64
	GOOS=freebsd GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd
	GOOS=freebsd GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd-arm64
	
	GOOS=openbsd GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd-64
	GOOS=openbsd GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd
	GOOS=openbsd GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd-arm64

clean:
	rm -rf ./bin/