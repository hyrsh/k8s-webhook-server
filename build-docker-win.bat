@ECHO OFF
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
SET VERSION=1.1
docker rmi k8s-webhook-server:%VERSION%
go build -o webhooksrv_x86_64 -ldflags="-extldflags=-static -s -w" main.go
timeout 2
move ./webhooksrv_x86_64 ./docker/webhooksrv_x86_64
chdir ./docker
docker build -t k8s-webhook-server:%VERSION% .
timeout 2
del "webhooksrv_x86_64"
:: docker run --rm --name=liquidenv -v C:/Users/<USERNAME>/go/src/liquidenv/testarea/docker-configs:/cfg -d liquidenv:1.0