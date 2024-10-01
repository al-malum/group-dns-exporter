package pdns

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// структура, которая идентифицирует авторити кластер и содержит отчет о доступности кластеров в его составе
type AvailabilityMegacluster struct {
	MegaClusterID             string
	AllSimpleClusters         int8
	AvailabileSimpleClusters  int8
	DisableSimpleClusters     int8
	MaintenanceSimpleClusters int8
}

// Функция по проверке доступности больших кластеров авторити
func CheckAvailabilityAuth(conf []AuthCluster, tlsSet MtlsRequests, chAvailMgcl chan []AvailabilityMegacluster) {
	var dataList []AvailabilityMegacluster
	// WaitGroup для воркеров, обрабатывающих большие кластера и запускающих другие воркеры
	var wgAvailAuth sync.WaitGroup
	// WaitGroup для воркеров, обрабатывающих кластера в составе больших
	var wgAvailAuthSimple sync.WaitGroup
	dnsClient := CreateDnsClient()
	httpClient := CreateHttpClient(tlsSet.Enabled, tlsSet.Cert, tlsSet.Key)
	for _, megacluster := range conf {
		var dataMCAvail AvailabilityMegacluster
		dataMCAvail.AllSimpleClusters = int8(len(megacluster.SimpleClusters))
		//dataMCAvail.MaintenanceSimpleClusters = int8(len(megacluster.))
		dataMCAvail.MegaClusterID = megacluster.MegaClusterID
		wgAvailAuth.Add(1)                 // 1 воркер, обрабатывает большие кластера
		go func(megacluster AuthCluster) { // воркер обработки, обрабатывает большие кластера
			//log.Printf("The beginning of the survey of the megacluster %s with %d simple clusters", megacluster.MegaClusterID, len(megacluster.SimpleClusters))
			slog.Debug(fmt.Sprintf("The beginning of the survey of the megacluster %s with %d simple clusters", megacluster.MegaClusterID, len(megacluster.SimpleClusters)))
			for _, simplecluster := range megacluster.SimpleClusters {
				slog.Debug(fmt.Sprintf("The beginning of the survey of the simple cluster %s, nodes: %s %s, http: %s", simplecluster.ClusterID, simplecluster.Master, simplecluster.Slave, simplecluster.Balancer))
				if simplecluster.Maintenance {
					dataMCAvail.MaintenanceSimpleClusters++
				}
				wgAvailAuthSimple.Add(4) // 1 воркер, в нем 3 горутины
				chDnsM := make(chan DnsResponseData, len(megacluster.SimpleClusters))
				chDnsS := make(chan DnsResponseData, len(megacluster.SimpleClusters))
				chHttp := make(chan HttpResponseData, len(megacluster.SimpleClusters))
				defer close(chDnsM)
				defer close(chDnsS)
				defer close(chHttp)
				go func(simplecluster SimpleCluster) { // воркер запросов, посылает запросы в хосты маленьких кластеров
					var dnsRespList []bool
					var httpRespList []bool
					// формируются данные для http и dns запросов
					drdMaster := CreateDnsRequestData(simplecluster.ClusterID, simplecluster.Master, simplecluster.RequestedRecord, simplecluster.DnsPort)
					drdSlave := CreateDnsRequestData(simplecluster.ClusterID, simplecluster.Slave, simplecluster.RequestedRecord, simplecluster.DnsPort)
					hrdBalancer := CreateHttpRequestData(simplecluster.ClusterID, simplecluster.Balancer, simplecluster.ApiToken, simplecluster.HttpPort, tlsSet.Enabled)
					go DnsRequest(drdMaster, chDnsM, dnsClient, &wgAvailAuthSimple)
					go DnsRequest(drdSlave, chDnsS, dnsClient, &wgAvailAuthSimple)
					go HttpRequest(hrdBalancer, chHttp, httpClient, &wgAvailAuthSimple)
				loop: // метка цикла, используется для его прерывания из блока select
					for {
						select {
						// сохраняется bool значение, которое интерпретируется как доступность
						// в дальнейшем можно переработать и отдавать больше данных наверх
						case mResp := <-chDnsM:
							dnsRespList = append(dnsRespList, mResp.Availability)
						case sResp := <-chDnsS:
							dnsRespList = append(dnsRespList, sResp.Availability)
						case hResp := <-chHttp:
							httpRespList = append(httpRespList, hResp.Availability)
						case <-time.After(500 * time.Millisecond): // таймаут, если ответы не пришли - выход из цикла ожидания
							break loop
						}
					}
					defer wgAvailAuthSimple.Done()
					// если удается получить из списка с bool true, значит сервис доступен
					checkDnsAvail := ContainBool(dnsRespList, true)
					checkHttpAvail := ContainBool(httpRespList, true)
					// если хоть одна из проверок не пройдена, кластер нерабочий
					if checkDnsAvail && checkHttpAvail {
						dataMCAvail.AvailabileSimpleClusters = dataMCAvail.AvailabileSimpleClusters + 1
					} else {
						dataMCAvail.DisableSimpleClusters = dataMCAvail.DisableSimpleClusters + 1
					}

					slog.Debug(fmt.Sprintf("The survey of the %s cluster has been completed", simplecluster.ClusterID))
				}(simplecluster)
			}
			wgAvailAuthSimple.Wait()
			dataList = append(dataList, dataMCAvail)
			slog.Debug(fmt.Sprintf("The survey of the %s megacluster has been completed", megacluster.MegaClusterID))
			defer wgAvailAuth.Done()
		}(megacluster)
	}
	wgAvailAuth.Wait()
	chAvailMgcl <- dataList
}
