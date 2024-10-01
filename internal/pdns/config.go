package pdns

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-playground/validator/v10"
)

// Структура конфигурационного файла, она состоит из других структур, отвечающих за конкретную часть конфига
type Conf struct {
	LogPath         string       `json:"logPath" validate:"required"`
	LogLevel        string       `json:"logLevel" validate:"oneof='DEBUG' 'INFO' 'WARN' 'ERROR'"`
	MtlsExporter    MtlsExporter `json:"mtlsExporter" validate:"required"`
	MtlsRequest     MtlsRequests `json:"mtlsRequests" validate:"required"`
	RecursorServers []RecursorServer
	AuthClusters    []AuthCluster
}

// Структура для части конфига отвечающего за mtls страницы экспортера
type MtlsExporter struct {
	Enabled   bool     `json:"enabled" validate:"boolean"`
	Key       string   `json:"key" validate:"required_with=Enabled"`
	Cert      string   `json:"cert" validate:"required_with=Enabled"`
	AllowedCN []string `json:"allowedCN" validate:"required_with=Enabled"`
}

// Структура для части конфига отвечающего за mtls при обращении к апи серверов авторити
type MtlsRequests struct {
	Enabled bool   `json:"enabled" validate:"boolean"`
	Key     string `json:"key" validate:"required_with=Enabled"`
	Cert    string `json:"cert" validate:"required_with=Enabled"`
}

// Структура, описывающая часть конфига с апстрим серверами для днс опросов
type RecursorDns struct {
	RecursorServers []string
}

// Структура, описывающая сам сервер (его параметры)
type RecursorServer struct {
	RecursorID string `json:"recursorID" validate:"required"`
	Address    string `json:"address" validate:"required"`
	Fqdn       string `json:"record" validate:"required"`
	DnsPort    int32  `json:"dnsPort" validate:"required"`
}

// Структура части конфига (группа больших авторити днс кластеров для опроса)
type AuthCluster struct {
	MegaClusterID  string          `json:"groupClusterID" validate:"required"`
	SimpleClusters []SimpleCluster `json:"authClusters" validate:"required"`
}

// Структура части конфига (группа маленьких днс кластеров для запросов в их сторону)
type SimpleCluster struct {
	ClusterID       string `json:"clusterID" validate:"required"`
	Master          string `json:"master" validate:"required"`
	Slave           string `json:"slave" validate:"required"`
	Balancer        string `json:"balancer" validate:"required"`
	HttpPort        int32  `json:"httpPort" validate:"required"`
	DnsPort         int32  `json:"dnsPort" validate:"required"`
	RequestedRecord string `json:"requestedPort" validate:"required"`
	ApiToken        string `json:"apiToken" validate:"required"`
	Maintenance     bool   `json:"maintenance" validate:"boolean"`
}

// Функция для чтения конфигурационного файла
func GetConfig() (*Conf, error) {
	var path string
	flag.StringVar(&path, "c", "/etc/ddidnser/config.json", "path to config file")
	flag.Parse()
	plan, errRead := os.ReadFile(path)
	if errRead != nil {
		slog.Error(errRead.Error())
		return nil, errRead
	}
	var Config Conf
	err := json.Unmarshal(plan, &Config)

	validate := validator.New()
	if err := validate.Struct(Config); err != nil {
		errs := err.(validator.ValidationErrors)
		for _, fieldErr := range errs {
			slog.Error(fmt.Sprintf("field %s %s %s\n", fieldErr.Namespace(), fieldErr.ActualTag(), fieldErr.Param()))
		}
		return nil, err
	}

	if err != nil {
		return &Config, err
	}
	return &Config, nil
}

func ContainBool(listing []bool, key bool) bool {
	for _, value := range listing {
		if key == value {
			return true
		}
	}
	return false
}

func ContainString(listing []string, key string) bool {
	for _, value := range listing {
		if key == value {
			return true
		}
	}
	return false
}
