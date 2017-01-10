# Go parameters
GOCMD=godep go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOINSTALL=$(GOCMD) install
GOTEST=$(GOCMD) test
GODEP=$(GOTEST) -i
GOFMT=gofmt -w

APPNAME=check_remote_plugin

TARGET=$(PWD)/target
FILES=main.go

req:
	go get github.com/tools/godep
	godep restore

build: req
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(TARGET)/$(APPNAME).linux.amd64 $(FILES)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(TARGET)/$(APPNAME).darwin.amd64 $(FILES)

clean:
	rm $(TARGET)/*

all: req test build
