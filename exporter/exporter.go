package exporter

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	cpi = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pod_cycles_per_instruction",
			Help: "cycles per instruction of a pod",
		},
		[]string{"podUid"},
	)

	l3CacheMisses = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pod_l3_cache_misses",
			Help: "l3 cache misses of a pod",
		},
		[]string{"podUid"},
	)

	cycles = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pod_cycles_per_period",
			Help: "cycles per period of a pod",
		},
		[]string{"podUid"},
	)

	instructions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pod_instructions_per_period",
			Help: "instructions per period of a pod",
		},
		[]string{"podUid"},
	)
)

func init() {
	prometheus.MustRegister(cpi)
	prometheus.MustRegister(l3CacheMisses)
	prometheus.MustRegister(cycles)
	prometheus.MustRegister(instructions)
}

type Exporter struct {
	addr string
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	promhttp.Handler().ServeHTTP(w, req)
}

// ServeIndex serves index page
func ServeIndex(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-type", "text/html")
	res := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
	<meta name="viewport" content="width=device-width">
	<title>Disk Usage Prometheus Exporter</title>
</head>
<body>
<h1>PMU Prometheus Exporter</h1>
<p>
	<a href="/metrics">Metrics</a>
</p>
<p>
	<a href="https://github.com/justadogistaken/pmu_exporter">Homepage</a>
</p>
</body>
</html>
`
	fmt.Fprint(w, res)
}

// RunServer starts HTTP server loop
func (e *Exporter) RunServer() {
	http.Handle("/", http.HandlerFunc(ServeIndex))
	http.Handle("/metrics", e)

	log.Printf("Providing metrics at http://%s/metrics", e.addr)
	err := http.ListenAndServe(e.addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

func (*Exporter) reportItem() {
	uploads := digPmuMetrics()
	for _, u := range uploads {
		cpi.WithLabelValues(u.PodUID).Set(u.CPI)
		l3CacheMisses.WithLabelValues(u.PodUID).Set(u.L3CacheMisses)
		cycles.WithLabelValues(u.PodUID).Set(u.Cycles)
		instructions.WithLabelValues(u.PodUID).Set(u.Instructions)
	}
}

func NewExporter(addr string) *Exporter {
	return &Exporter{
		addr: addr,
	}
}
