package pdns

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"crypto/tls"
	"crypto/x509"

	"os"

	"sync"
	"time"

	"github.com/miekg/dns"
)

// Структура, где поля будут содержать результаты запроса
type DnsResponseData struct {
	ServerID       string
	TimeToResponse time.Duration
	Msg            *dns.Msg
	Availability   bool
}

// Структура, необходимая для днс запроса
type DnsRequestData struct {
	ServerID string
	Address  string
	Fqdn     string
	Port     int32
}

// Структура http ответа, можно расширить и собрать побольше данных из ответа
type HttpResponseData struct {
	ServerID     string
	ResponseCode int16
	Availability bool
}

// структура, необходимая для создания http запроса, формирования строки запроса и записи хедеров
type HttpRequestData struct {
	ServerID string
	Address  string
	ApiToken string
	Port     int32
	Tls      bool
}

// Функия для создание структуры с данными для запроса dns
func CreateDnsRequestData(clusterID, address, record string, dnsPort int32) DnsRequestData {
	return DnsRequestData{
		ServerID: clusterID,
		Address:  address,
		Fqdn:     record,
		Port:     dnsPort,
	}
}

// Функия для создание структуры с данными для запроса http/https
func CreateHttpRequestData(clusterID, address, apiToken string, port int32, tls bool) HttpRequestData {
	return HttpRequestData{
		ServerID: clusterID,
		Address:  address,
		Port:     port,
		ApiToken: apiToken,
		Tls:      tls,
	}
}

// Функция для создания http клиента (http/https)
func CreateHttpClient(tlsCheck bool, certPath, keyPath string) *http.Client {
	var httpClient *http.Client
	if !tlsCheck {
		httpClient = &http.Client{}
	} else {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			//log.Fatal(err.Error())
			slog.Error(err.Error())
		}
		// Create a CA certificate pool and add cert.pem to it
		caCert, err := os.ReadFile(certPath)
		if err != nil {
			slog.Error(err.Error())
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		// Create a HTTPS client and supply the created CA pool and certificate
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{cert},
				},
			},
		}
	}
	return httpClient
}

// Функция для создание днс клиента
func CreateDnsClient() *dns.Client {
	var dnsClient dns.Client
	dnsClient.Dialer = &net.Dialer{ // устанавливаем маскимальное время ожидания ответа (300 миллисекунд)
		Timeout: 300 * time.Millisecond,
	}
	return &dnsClient
}

// Функция для создание http запроса
func createHttpRequest(hrd HttpRequestData) (*http.Request, error) {
	var protocol string
	if !hrd.Tls {
		protocol = "http"
	} else {
		protocol = "https"
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s:%d/api/v1/servers", protocol, hrd.Address, hrd.Port), nil)
	if err != nil {
		return nil, err
	} else {
		req.Header.Set("X-API-Key", hrd.ApiToken)
		return req, nil
	}
}

// Функция по выполнению днс запросов
func DnsRequest(drd DnsRequestData, chDns chan DnsResponseData, dnsClient *dns.Client, Wg *sync.WaitGroup) {
	defer Wg.Done()
	var (
		msg        dns.Msg
		data       DnsResponseData
		checkAvail bool
	)
	data.ServerID = drd.ServerID
	fqdn := dns.Fqdn(drd.Fqdn)
	msg.SetQuestion(fqdn, dns.TypeA)
	resp, ttr, err := dnsClient.Exchange(&msg, fmt.Sprintf("%s:%d", drd.Address, drd.Port)) // выполнение запроса
	if err != nil {
		checkAvail = false
	} else {
		checkAvail = true
	}
	// время ответа возвращается в миллисекундах, 300 - порог
	responseDns := DnsResponseData{
		ServerID:       drd.ServerID,
		Availability:   checkAvail,
		TimeToResponse: time.Duration(ttr.Milliseconds()),
		Msg:            resp,
	}
	chDns <- responseDns
}

// Функция выполнения http запроса
func HttpRequest(hrd HttpRequestData, chHttp chan HttpResponseData, httpClient *http.Client, Wg *sync.WaitGroup) {
	defer Wg.Done()
	var checkAvail bool
	var respCode int16
	requestBalancer, errCreateHtR := createHttpRequest(hrd)
	if errCreateHtR != nil { // если ошибка создания запроса, логируем, возвращаем ошибку и структуру, не ронять процесс из-за одного итема
		slog.Error(fmt.Sprintf("Error create http request. f.HttpRequest.s154, target request: %s", hrd.Address))
		responseHttp := HttpResponseData{
			ServerID:     hrd.ServerID,
			ResponseCode: 400, // bad request
			Availability: false,
		}
		chHttp <- responseHttp
		return
	}
	resp, err := httpClient.Do(requestBalancer)

	if err != nil { // если есть ошибка (сеть, недоступен порт и тд), поставим код 503, пока нигде он не отражается
		checkAvail = false
		respCode = 503
	} else if resp.StatusCode != 200 { // проверка на код 200
		checkAvail = false
		respCode = int16(resp.StatusCode)
		defer resp.Body.Close()
	} else { // если сетевой ошибки нет, код ответа 200, то общая доступность true и добавим код ответа в структуру
		checkAvail = true
		respCode = int16(resp.StatusCode)
		defer resp.Body.Close()
	}

	responseHttp := HttpResponseData{ // возвращаем структуру, ее можно расширить для доп метрик, пока - код ответа и общая доступность
		ServerID:     hrd.ServerID,
		ResponseCode: respCode,
		Availability: checkAvail,
	}
	chHttp <- responseHttp
}
