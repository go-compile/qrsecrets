build:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-windows-x64.exe ./cmd/qrsecrets
	GOOS=windows GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-windows.exe ./cmd/qrsecrets
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-windows-arm64.exe ./cmd/qrsecrets
	
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-darwin ./cmd/qrsecrets
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-darwin-arm64 ./cmd/qrsecrets
	
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux-64 ./cmd/qrsecrets
	GOOS=linux GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux ./cmd/qrsecrets
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-linux-arm64 ./cmd/qrsecrets

	GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd-64 ./cmd/qrsecrets
	GOOS=freebsd GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd ./cmd/qrsecrets
	GOOS=freebsd GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-freebsd-arm64 ./cmd/qrsecrets
	
	GOOS=openbsd GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd-64 ./cmd/qrsecrets
	GOOS=openbsd GOARCH=386 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd ./cmd/qrsecrets
	GOOS=openbsd GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./bin/qrsecrets-openbsd-arm64 ./cmd/qrsecrets

clean:
	rm -rf ./bin/