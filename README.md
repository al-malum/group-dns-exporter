# group-dns-exporter

Exporter for checking the availability of groups of PowerdnsDNS servers

```golang
go build -o pdns-exporter -ldflags "-X main.desiredPathPid=/run/dns-exporter.pid" cmd/pdns/main.go
```
