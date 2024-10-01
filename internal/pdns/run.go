package pdns

import (
	"log/slog"
	"main/pkg/web"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Структура, где поля будут содержать дескрипторы метрик dns
type DnsMetricsDesc struct {
	AllSimpleClusters         *prometheus.Desc
	AvailabileSimpleClusters  *prometheus.Desc
	DisableSimpleClusters     *prometheus.Desc
	MaintenanceSimpleClusters *prometheus.Desc
	CodeFromRecursor          *prometheus.Desc
	TtrFromRecursor           *prometheus.Desc
}

// глобальное определение конфигурации и ошибки чтения (если есть)
var Config, ConfErr = GetConfig()

// Реализация интерфейса collector
// метод Describe возвращает описание(дескриптор) всех метрик собранных этим коллектором в выделенный канал
func (DnsMetrics *DnsMetricsDesc) Describe(ch chan<- *prometheus.Desc) {
	ch <- DnsMetrics.AllSimpleClusters // экземпляр DnsMetrics создается в функции NewDnsMetrics()
	ch <- DnsMetrics.AvailabileSimpleClusters
	ch <- DnsMetrics.DisableSimpleClusters
	ch <- DnsMetrics.MaintenanceSimpleClusters
	ch <- DnsMetrics.CodeFromRecursor
	ch <- DnsMetrics.TtrFromRecursor
}

// метод Collect возвращает в канал саму метрику и вызывается каждый раз при получении данных
// так же возвращается дескриптор метрики
// дескриптор, который передает Collect должен быть одним из тех, что возвращает Describe
// метрики, использующе один и тот же дескриптор должны отличаться лейблами
func (DnsMetrics *DnsMetricsDesc) Collect(ch chan<- prometheus.Metric) {
	chAvailMgcl := make(chan []AvailabilityMegacluster)
	chAvailUpstr := make(chan []AvailabilityRecursor)
	go CheckAvailabilityAuth(Config.AuthClusters, Config.MtlsRequest, chAvailMgcl)
	go CheckAvailabilityRecursor(Config.RecursorServers, chAvailUpstr)
	resultCheckingAuth := <-chAvailMgcl
	resultCheckingRecursor := <-chAvailUpstr
	defer close(chAvailMgcl)
	defer close(chAvailUpstr)
	for _, item := range resultCheckingAuth {
		// метрика - все кластеры в составе большого, которые получены из конфига
		ch <- prometheus.MustNewConstMetric( // Метрика кода ответа сервера
			DnsMetrics.AllSimpleClusters,    // дескриптор
			prometheus.GaugeValue,           // тип метрики
			float64(item.AllSimpleClusters), // метрика
			item.MegaClusterID,              // лейбл server представляет из себя ip адрес апстрима
		)
		// метрика - все доступные кластеры в составе большого
		ch <- prometheus.MustNewConstMetric( // Метрика времени ответа сервера
			DnsMetrics.AvailabileSimpleClusters,    // дескриптор
			prometheus.GaugeValue,                  // тип метрики
			float64(item.AvailabileSimpleClusters), // метрика в секундах
			item.MegaClusterID,                     // лейбл server представляет из себя ip адрес апстрима
		)
		// метрика - все недоступные кластеры в составе большого
		ch <- prometheus.MustNewConstMetric( // Метрика кода ответа сервера
			DnsMetrics.DisableSimpleClusters,    // дескриптор
			prometheus.GaugeValue,               // тип метрики
			float64(item.DisableSimpleClusters), // метрика
			item.MegaClusterID,                  // лейбл server представляет из себя имя авторити кластера
		)
		// метрика - все кластеры на обслуживании в составе большого
		ch <- prometheus.MustNewConstMetric( // Метрика кода ответа сервера
			DnsMetrics.MaintenanceSimpleClusters,    // дескриптор
			prometheus.GaugeValue,                   // тип метрики
			float64(item.MaintenanceSimpleClusters), // метрика
			item.MegaClusterID,                      // лейбл server представляет из себя имя авторити кластера
		)
	}
	for _, item := range resultCheckingRecursor {
		ch <- prometheus.MustNewConstMetric( // Метрика кода ответа сервера
			DnsMetrics.CodeFromRecursor, // дескриптор
			prometheus.GaugeValue,       // тип метрики
			float64(item.Rcode),         // метрика
			item.RecursorID,             // лейбл server представляет из себя ip адрес апстрима
		)
		ch <- prometheus.MustNewConstMetric( // Метрика времени ответа сервера
			DnsMetrics.TtrFromRecursor, // дескриптор
			prometheus.GaugeValue,      // тип метрики
			float64(item.ResponseTime), // метрика в секундах
			item.RecursorID,            // лейбл server представляет из себя ip адрес апстрима
		)
	}

}

// Создание нового объекта, структуры, полем которой является дескриптор (дескрипторы) метрик
func NewDnsMetrics() *DnsMetricsDesc {
	return &DnsMetricsDesc{
		AllSimpleClusters: prometheus.NewDesc(
			"all_simple_clusters", // имя метрики
			"Общее количество кластеров днс в составе большого кластера", // хелп метрики
			[]string{"cluster"}, // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{}, // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
		AvailabileSimpleClusters: prometheus.NewDesc(
			"available_simple_clusters", // имя метрики
			"Количество доступных кластеров днс в составе большого кластера", // хелп метрики
			[]string{"cluster"}, // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{}, // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
		DisableSimpleClusters: prometheus.NewDesc(
			"disable_simple_clusters", // имя метрики
			"Количество недоступных кластеров днс в составе большого кластера", // хелп метрики
			[]string{"cluster"}, // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{}, // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
		MaintenanceSimpleClusters: prometheus.NewDesc(
			"maintenance_simple_clusters", // имя метрики
			"Количество кластеров днс в составе большого кластера на обслуживании", // хелп метрики
			[]string{"cluster"}, // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{}, // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
		CodeFromRecursor: prometheus.NewDesc(
			"response_code_from_Recursor",         // имя метрики
			"Код ответа от астрима или рекурсора", // хелп метрики
			[]string{"RecursorID"},                // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{},                   // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
		TtrFromRecursor: prometheus.NewDesc(
			"ttr_from_Recursor", // имя метрики
			"Время ответа от апстрима или рекурсора", // хелп метрики
			[]string{"RecursorID"}, // variableLabels, лейблы метрики в зависимости от входящих данных при формировании метрики в методе Collect()
			prometheus.Labels{},    // constLabels, заранее определяемые лейблы метрик этого типа (опционально)
		),
	}
}

func Run() error {
	if ConfErr != nil {
		return ConfErr
	}
	initLogger(Config.LogPath, Config.LogLevel)
	reg := prometheus.NewPedanticRegistry()
	workerDns := NewDnsMetrics()
	mtlsSett := web.MtlsSettings{
		Enabled:   Config.MtlsExporter.Enabled,
		Key:       Config.MtlsExporter.Key,
		Cert:      Config.MtlsExporter.Cert,
		AllowedCN: Config.MtlsExporter.AllowedCN,
	}
	reg.MustRegister(workerDns)
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", web.AuthenticationCN(promHandler, mtlsSett))
	if Config.MtlsExporter.Enabled {
		slog.Info("Run server with mtls.")
		RunServerWithTls(promHandler, Config.MtlsExporter)
	} else {
		slog.Info("Run server without mtls.")
		RunServerWithousTls(promHandler)
	}
	return nil
}
