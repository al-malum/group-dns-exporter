package pdns

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// структура, возвращающая rcode dns запроса, id апстрима и время ответа
type AvailabilityRecursor struct {
	RecursorID   string
	Rcode        int8
	ResponseTime time.Duration
}

func CheckAvailabilityRecursor(conf []RecursorServer, chAvailUpstr chan []AvailabilityRecursor) {
	var availList []AvailabilityRecursor
	var rcode int8
	// Для функций CheckAvailabilityAuth и CheckAvailabilityRecursor разные WaitGroup во избежание блокировок
	var wgAvailUpstrWg sync.WaitGroup
	dnsClient := CreateDnsClient()
	for _, server := range conf {
		wgAvailUpstrWg.Add(2) // 1 воркер и 1 горутина
		// замыкание исполняет роль воркера для каждого сервера, ответы пишет в список
		go func(server RecursorServer) {
			slog.Debug(fmt.Sprintf("The beginning of the survey of the Recursor %s", server.RecursorID))
			chDns := make(chan DnsResponseData, len(conf))
			defer wgAvailUpstrWg.Done()
			requestData := CreateDnsRequestData(server.RecursorID, server.Address, server.Fqdn, server.DnsPort)
			go DnsRequest(requestData, chDns, dnsClient, &wgAvailUpstrWg)

			data := <-chDns

			if data.Msg == nil { // если сервер не ответил, ставим rcode 111 (условно - рефьюз)
				rcode = int8(111)
			} else {
				rcode = int8(data.Msg.Rcode)
			}
			availList = append(availList, AvailabilityRecursor{
				RecursorID:   data.ServerID,
				Rcode:        rcode,
				ResponseTime: data.TimeToResponse,
			})
			slog.Debug(fmt.Sprintf("The survey of the %s Recursor has been completed", server.RecursorID))
			defer close(chDns)
		}(server)
	}
	wgAvailUpstrWg.Wait()
	chAvailUpstr <- availList
}
