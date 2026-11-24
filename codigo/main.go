// Monitoreo de Red - monitor de red para Raspberry Pi
// Solo usa la biblioteca estándar de Go.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

var version = "2.18.0"

func main() {
	port := flag.String("port", envOr("NETMON_PORT", "5000"), "puerto HTTP")
	dataFile := flag.String("data", envOr("NETMON_DATA", "monitoreo-data.json"), "archivo de datos")
	subnet := flag.String("subnet", envOr("NETMON_SUBNET", ""), "subred a escanear (ej. 192.168.1.0/24); vacío = automática")
	interval := flag.Int("interval", 30, "segundos entre chequeos")
	scanEvery := flag.Int("scan", 10, "minutos entre escaneos completos de la red")
	token := flag.String("token", envOr("MONITOREO_TOKEN", ""), "token de la API v1 para sistemas externos (vacío = API v1 apagada)")
	cors := flag.String("cors", envOr("MONITOREO_CORS", ""), "orígenes que pueden llamar la API v1 desde el navegador (coma) o *")
	detectar := flag.String("detectar", "", "solo detectar la red de esta interfaz (ej. eth0) y salir; lo usa monitoreo-autoip")
	actual := flag.String("actual", "", "con -detectar: IP actual de la Pi")
	puertaAct := flag.String("puerta", "", "con -detectar: puerta de enlace actual")
	segundos := flag.Int("segundos", 20, "con -detectar: segundos escuchando el cable")
	flag.Parse()
	if *detectar != "" {
		os.Exit(detectNetwork(*detectar, *actual, *puertaAct, *segundos))
	}

	store := NewStore(*dataFile)
	if err := store.Load(); err != nil {
		log.Printf("aviso: no se pudo cargar %s: %v (se crea nuevo)", *dataFile, err)
	}

	// guardar los datos al detener o reiniciar el servicio
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		store.Close() // guarda todo en SQLite y espera a que termine
		os.Exit(0)
	}()

	mon := NewMonitor(store, *subnet, time.Duration(*interval)*time.Second, time.Duration(*scanEvery)*time.Minute)
	go mon.Run()
	go sysCollector()
	startSNMP(store) // solo si existe /etc/monitoreo/snmp.conf con SNMP_IP

	var almacen cuentas.Almacen
	if store.db != nil {
		almacen = store.db // (un *DB nil dentro de la interfaz no sería nil)
	}
	auth := cuentas.Nuevo(almacen, store)
	web.Version = version
	web.RouterActivo = func() bool { return SNMPStatus().Active }
	// API v1 para sistemas externos: va con su propio token, aparte de la interfaz.
	api := newAPIv1(store, mon, *token, *cors)
	startWebhook(api, strings.TrimSpace(os.Getenv("MONITOREO_WEBHOOK_URL")), strings.TrimSpace(os.Getenv("MONITOREO_WEBHOOK_TOKEN")))
	if *token == "" {
		log.Printf("API v1 desactivada (falta MONITOREO_TOKEN)")
	}
	servir(*port, rutas(store, mon, auth, api)) // servidor.go
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// writeJSON responde en JSON; las respuestas de la API van comprimidas (gzip)
// cuando el navegador lo acepta: con cientos de equipos pesan ~10 veces menos.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if gz, ok := w.(gzipWriter); ok {
		gz.compress()
	}
	json.NewEncoder(w).Encode(v)
}

type gzipWriter interface{ compress() }

type gzResp struct {
	http.ResponseWriter
	accept bool
	gz     *gzip.Writer
}

func (g *gzResp) compress() {
	if g.accept && g.gz == nil {
		g.Header().Set("Content-Encoding", "gzip")
		g.Header().Add("Vary", "Accept-Encoding")
		g.gz, _ = gzip.NewWriterLevel(g.ResponseWriter, gzip.BestSpeed)
	}
}

func (g *gzResp) Write(b []byte) (int, error) {
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := &gzResp{ResponseWriter: w, accept: strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")}
		next.ServeHTTP(g, r)
		if g.gz != nil {
			g.gz.Close()
		}
	})
}

func registerAPI(mux chi.Router, store *Store, mon *Monitor) {
	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		// ?seg=10&f=bad&q=hp — la Pi filtra y ordena; el navegador solo dibuja.
		// Con seg y sin búsqueda manda el historial (para las gráficas chicas).
		// Las gráficas chicas (historial) van si son 300 equipos o menos.
		v := r.URL.Query()
		seg, q, f := v.Get("seg"), v.Get("q"), v.Get("f")
		list := store.Query(seg, q, f, true, 1000)
		if len(list) > 300 && (q != "" || f != "" || seg == "") {
			for i := range list {
				list[i].History = nil
			}
		}
		writeJSON(w, list)
	})
	mux.HandleFunc("/api/segments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, store.Segments())
	})
	mux.HandleFunc("/api/segcfg", func(w http.ResponseWriter, r *http.Request) {
		// GET: {config, seen}  |  POST {seg,name,gateway,manual,hidden}  |  DELETE ?seg=
		switch r.Method {
		case http.MethodGet:
			seen := map[string]int{}
			for _, d := range store.DeviceList() {
				seen[segOf(d.IP)]++
			}
			writeJSON(w, map[string]any{"config": SegConfigList(), "seen": seen, "hints": store.GatewayHints()})
		case http.MethodPost:
			var c SegCfg
			if json.NewDecoder(r.Body).Decode(&c) != nil {
				http.Error(w, "datos inválidos", 400)
				return
			}
			if err := store.SetSegCfg(c); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if c.Manual {
				go mon.Scan() // barre ya el segmento nuevo
			}
			writeJSON(w, map[string]bool{"ok": true})
		case http.MethodDelete:
			store.DeleteSegCfg(r.URL.Query().Get("seg"))
			writeJSON(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "método no permitido", 405)
		}
	})
	mux.HandleFunc("/api/device", func(w http.ResponseWriter, r *http.Request) {
		// POST {mac, name, known}  |  DELETE ?mac=
		switch r.Method {
		case http.MethodPost:
			var req struct {
				MAC      string  `json:"mac"`
				Name     string  `json:"name"`
				Location string  `json:"location"`
				Known    bool    `json:"known"`
				Kind     *string `json:"kind"` // ausente = no tocar; "auto" = quitar el fijado; o un tipo
			}
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.MAC == "" {
				http.Error(w, "datos inválidos", 400)
				return
			}
			if err := store.UpdateDevice(req.MAC, strings.TrimSpace(req.Name), strings.TrimSpace(req.Location), req.Known, req.Kind); err != nil {
				http.Error(w, "tipo de equipo no válido", 400)
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
		case http.MethodDelete:
			store.DeleteDevice(r.URL.Query().Get("mac"))
			writeJSON(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "método no permitido", 405)
		}
	})
	mux.HandleFunc("/api/targets", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, store.Targets())
		case http.MethodPost:
			var t Target
			if json.NewDecoder(r.Body).Decode(&t) != nil || strings.TrimSpace(t.Host) == "" {
				http.Error(w, "datos inválidos", 400)
				return
			}
			t.Host = strings.TrimSpace(t.Host)
			if t.Name == "" {
				t.Name = t.Host
			}
			store.AddTarget(t)
			go mon.CheckTargets()
			writeJSON(w, map[string]bool{"ok": true})
		case http.MethodDelete:
			store.DeleteTarget(r.URL.Query().Get("id"))
			writeJSON(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "método no permitido", 405)
		}
	})
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		// ?mac=&range=1h|24h|7d
		writeJSON(w, store.History(r.URL.Query().Get("mac"), r.URL.Query().Get("range")))
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		// sin parámetros: los últimos 300 (Resumen). Con ?filtro=1&seg=&tipo=&q=&dias=
		// se consulta la base (1 año). seg "-" = generales; tipo: imp, con, new, info.
		v := r.URL.Query()
		if v.Get("filtro") == "" || store.db == nil {
			writeJSON(w, store.Events())
			return
		}
		kinds := map[string][]string{
			"imp":  {"offline", "corte", "online"},
			"con":  {"conectado", "desconectado"},
			"new":  {"new"},
			"info": {"info"},
		}[v.Get("tipo")]
		days, _ := strconv.Atoi(v.Get("dias"))
		if days <= 0 || days > 366 {
			days = 7
		}
		since := time.Now().AddDate(0, 0, -days).Unix()
		writeJSON(w, store.db.QueryEvents(v.Get("seg"), kinds, strings.TrimSpace(v.Get("q")), since, 500))
	})
	mux.HandleFunc("/api/outages", func(w http.ResponseWriter, r *http.Request) {
		// ?days=30 : registro de cortes de internet (más recientes primero)
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		if days <= 0 || days > 366 {
			days = 30
		}
		out := store.Outages(days)
		if out == nil {
			out = []Outage{}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		s := currentSys()
		s.Subnet = mon.Subnet()
		s.Scanning = mon.Scanning()
		s.LastScan = mon.LastScan()
		s.Version = version
		rd, rn, every := mon.Round()
		s.RoundSecs, s.RoundN, s.EverySecs = rd.Seconds(), rn, every.Seconds()
		writeJSON(w, s)
	})
	mux.HandleFunc("/api/snmp", func(w http.ResponseWriter, r *http.Request) {
		// estado del router leído por SNMP; {activo:false} si no está configurado
		writeJSON(w, SNMPStatus())
	})
	mux.HandleFunc("/api/snmp/equipos", func(w http.ResponseWriter, r *http.Request) {
		// equipos de un segmento según la tabla ARP del router (?red=192.168.10.0/24),
		// con nombre y fabricante si la Pi ya los conoce
		type row struct {
			SNMPARPRow
			ID     string `json:"id,omitempty"` // para abrir su panel
			Nombre string `json:"nombre,omitempty"`
			Fab    string `json:"fabricante,omitempty"`
			Online bool   `json:"enLinea"`
		}
		arp := SNMPARPIn(r.URL.Query().Get("red"))
		byIP := map[string]Device{}
		if len(arp) > 0 {
			for _, d := range store.DeviceList() {
				if d.Alias {
					continue
				}
				if o, ok := byIP[d.IP]; !ok || (!o.Online && d.Online) {
					byIP[d.IP] = d
				}
			}
		}
		out := make([]row, 0, len(arp))
		for _, a := range arp {
			x := row{SNMPARPRow: a, Fab: vendorOf(a.MAC)}
			if d, ok := byIP[a.IP]; ok && strings.EqualFold(d.MAC, a.MAC) {
				x.ID, x.Online = d.ID, d.Online
				x.Nombre = d.Name
				for _, n := range []string{d.Hostname, d.NetBIOS, d.MDNS} {
					if x.Nombre == "" {
						x.Nombre = n
					}
				}
				if d.Vendor != "" {
					x.Fab = d.Vendor
				}
			}
			out = append(out, x)
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/snmp/equipo", func(w http.ResponseWriter, r *http.Request) {
		// cable e internet de un equipo según el router; {activo:false} si no es de sus redes
		writeJSON(w, SNMPDeviceInfo(r.URL.Query().Get("ip")))
	})
	mux.HandleFunc("/api/identify", func(w http.ResponseWriter, r *http.Request) {
		// POST ?mac=  → vuelve a buscar pistas del equipo (tarda unos segundos)
		if r.Method != http.MethodPost {
			http.Error(w, "usa POST", 405)
			return
		}
		mon.IdentifyOne(r.URL.Query().Get("mac"))
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "usa POST", 405)
			return
		}
		go mon.Scan()
		writeJSON(w, map[string]bool{"ok": true})
	})
}
