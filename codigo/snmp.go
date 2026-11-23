// snmp.go — lectura opcional de UN router por SNMP (solo lectura).
//
// Se configura en /etc/monitoreo/snmp.conf (o MONITOREO_SNMP_CONF). Si el archivo
// no existe o no tiene SNMP_IP, todo esto queda apagado y la app funciona igual
// que sin SNMP. Cada 30 s lee del router su nombre, encendido y la tabla de
// interfaces (IF-MIB): estado, velocidad, tráfico y errores. Anota eventos solo
// cuando algo cambia: interfaz caída/volvió, errores nuevos, router sin respuesta.
package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	snmpEvery      = 30 * time.Second
	snmpFailsDown  = 2                // lecturas fallidas seguidas para decir "no responde"
	snmpErrQuiet   = 10 * time.Minute // sin errores nuevos este tiempo = se da por resuelto
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidIfDescr     = ".1.3.6.1.2.1.2.2.1.2"
	oidIfType      = ".1.3.6.1.2.1.2.2.1.3"
	oidIfSpeed     = ".1.3.6.1.2.1.2.2.1.5"
	oidIfAdmin     = ".1.3.6.1.2.1.2.2.1.7"
	oidIfOper      = ".1.3.6.1.2.1.2.2.1.8"
	oidIfInOct     = ".1.3.6.1.2.1.2.2.1.10"
	oidIfInDisc    = ".1.3.6.1.2.1.2.2.1.13"
	oidIfInErr     = ".1.3.6.1.2.1.2.2.1.14"
	oidIfOutOct    = ".1.3.6.1.2.1.2.2.1.16"
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOct   = ".1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOct  = ".1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed = ".1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias     = ".1.3.6.1.2.1.31.1.1.1.18"
	// IP-MIB: redes del router, su tabla ARP y la ruta por omisión (todo opcional)
	oidIpAdIfIndex = ".1.3.6.1.2.1.4.20.1.2"
	oidIpAdMask    = ".1.3.6.1.2.1.4.20.1.3"
	oidArpPhys     = ".1.3.6.1.2.1.4.22.1.2"
	oidDefRouteIf  = ".1.3.6.1.2.1.4.21.1.2.0.0.0.0"
	oidRouteIf     = ".1.3.6.1.2.1.4.21.1.2"
	oidRouteNext   = ".1.3.6.1.2.1.4.21.1.7"
	oidRouteMask   = ".1.3.6.1.2.1.4.21.1.11"
)

// rtNet: una red que el router tiene en una interfaz (ej. 192.168.10.254/24 en eth1).
type rtNet struct {
	ip, mask net.IP
	ifIndex  int
}

type arpEnt struct {
	mac     string
	ifIndex int
}

// extras de IP-MIB leídos en cada consulta
type rtExtra struct {
	nets []rtNet
	arp  map[string]arpEnt // IP → MAC e interfaz donde el router la ve
	wan  int               // interfaz de la ruta por omisión (0 = no se sabe)
	conn []rtNet           // rutas directas (sin siguiente salto): red → interfaz
}

// SNMPSeg: un segmento que el router alcanza directo por un cable.
type SNMPSeg struct {
	Red     string `json:"red"`              // ej. 192.168.10.0/24
	Router  string `json:"router,omitempty"` // IP del router en ese segmento ("" = solo tiene la ruta)
	Equipos int    `json:"equipos"`          // IPs del segmento en la tabla ARP del router
}

// SNMPARPRow: un equipo de la tabla ARP del router.
type SNMPARPRow struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// SNMPDevice: lo que el router sabe de UN equipo (/api/snmp/equipo?ip=).
type SNMPDevice struct {
	Active   bool       `json:"activo"` // el equipo está en una red del router
	Router   string     `json:"router,omitempty"`
	RouterIP string     `json:"routerIP,omitempty"`
	Red      string     `json:"red,omitempty"` // ej. 192.168.10.254/24
	Cable    *SNMPIface `json:"cable,omitempty"`
	Internet *SNMPIface `json:"internet,omitempty"`
	EnARP    bool       `json:"enARP"`
	MAC      string     `json:"mac,omitempty"` // MAC con la que el router lo tiene
	Last     *time.Time `json:"ultimo,omitempty"`
	Down     bool       `json:"sinRespuesta"`
}

// SNMPConf: lo que dice snmp.conf.
type SNMPConf struct {
	IP, Version, Community, Name, Uplink         string
	User, AuthProto, AuthKey, PrivProto, PrivKey string
	Port                                         uint16
}

// SNMPIface: una interfaz del router, tal como la ve el panel.
type SNMPIface struct {
	Index      int       `json:"indice"`
	Name       string    `json:"nombre"`
	Alias      string    `json:"alias,omitempty"`
	Up         bool      `json:"arriba"`
	AdminUp    bool      `json:"habilitada"`
	SpeedMbps  float64   `json:"velocidad"` // Mb/s negociados (0 = no se sabe)
	InMbps     float64   `json:"entrada"`
	OutMbps    float64   `json:"salida"`
	Errors     uint64    `json:"errores"`             // errores + descartes de entrada en la última lectura
	ErrorTotal uint64    `json:"erroresTotal"`        // contador del router
	ErrActive  bool      `json:"conErrores"`          // hubo errores en los últimos 10 min
	Fell       bool      `json:"caida"`               // estuvo arriba y ahora está abajo (un puerto sin usar no cuenta)
	Segmentos  []SNMPSeg `json:"segmentos,omitempty"` // segmentos que alcanza directo por esta interfaz
	Equipos    int       `json:"equipos"`             // IPs en la tabla ARP del router por esta interfaz
	Internet   bool      `json:"internet,omitempty"`  // por aquí sale la ruta por omisión
}

// SNMPState: respuesta de /api/snmp.
type SNMPState struct {
	Active   bool        `json:"activo"`
	Name     string      `json:"nombre"`
	IP       string      `json:"ip"`
	SysName  string      `json:"sysName,omitempty"`
	SysDescr string      `json:"sysDescr,omitempty"`
	Uptime   int64       `json:"uptime"` // segundos encendido
	Last     *time.Time  `json:"ultimo,omitempty"`
	Error    string      `json:"error,omitempty"`
	Down     bool        `json:"sinRespuesta"`
	Uplink   string      `json:"principal,omitempty"` // interfaz de la que salen entrada/salida
	InMbps   float64     `json:"entradaMbps"`
	OutMbps  float64     `json:"salidaMbps"`
	UpN      int         `json:"arriba"`
	Total    int         `json:"total"`
	ErrN     int         `json:"conErrores"`
	FellN    int         `json:"caidas"`
	Ifaces   []SNMPIface `json:"interfaces"`
	Inet     SNMPInet    `json:"inet"` // internet del router por tráfico (lectura rápida)
}

type eventSink interface{ AddEvent(kind, msg string) }

type ifCounters struct {
	in, out, errs uint64
	hc            bool
}

type ifMemo struct {
	everUp, up bool
	errUntil   time.Time
}

type SNMPMon struct {
	mu    sync.RWMutex
	conf  *SNMPConf
	ev    eventSink
	state SNMPState
	prev  map[int]ifCounters
	prevT time.Time
	memo  map[int]*ifMemo
	fails int
	down  bool
	first bool
	extra rtExtra
}

var snmpMon *SNMPMon

// loadSNMPConf lee el archivo; nil si no existe o no tiene IP (= SNMP apagado).
func loadSNMPConf(path string) (*SNMPConf, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	c := &SNMPConf{Version: "2c", Port: 161}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.ToUpper(k) {
		case "SNMP_IP":
			c.IP = v
		case "SNMP_VERSION":
			c.Version = strings.ToLower(strings.TrimPrefix(strings.ToLower(v), "v"))
		case "SNMP_COMUNIDAD":
			c.Community = v
		case "SNMP_USUARIO":
			c.User = v
		case "SNMP_AUTH_PROTO":
			c.AuthProto = strings.ToUpper(v)
		case "SNMP_AUTH_CLAVE":
			c.AuthKey = v
		case "SNMP_PRIV_PROTO":
			c.PrivProto = strings.ToUpper(v)
		case "SNMP_PRIV_CLAVE":
			c.PrivKey = v
		case "SNMP_PUERTO":
			if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
				c.Port = uint16(p)
			}
		case "SNMP_NOMBRE":
			c.Name = v
		case "SNMP_INTERFAZ_PRINCIPAL":
			c.Uplink = v
		}
	}
	if c.IP == "" {
		return nil, nil
	}
	if c.Name == "" {
		c.Name = "Router"
	}
	switch c.Version {
	case "2c", "2":
		c.Version = "2c"
		if c.Community == "" {
			return nil, fmt.Errorf("falta SNMP_COMUNIDAD")
		}
	case "3":
		if c.User == "" {
			return nil, fmt.Errorf("falta SNMP_USUARIO")
		}
	default:
		return nil, fmt.Errorf("SNMP_VERSION debe ser 2c o 3")
	}
	return c, nil
}

// startSNMP arranca la lectura si hay configuración. Sin ella no hace nada.
func startSNMP(ev eventSink) {
	path := envOr("MONITOREO_SNMP_CONF", "/etc/monitoreo/snmp.conf")
	c, err := loadSNMPConf(path)
	if err != nil {
		log.Printf("SNMP apagado: %s: %v", path, err)
		return
	}
	if c == nil {
		return
	}
	snmpMon = newSNMPMon(c, ev)
	log.Printf("SNMP: leyendo %s (%s, v%s) cada %s", c.IP, c.Name, c.Version, snmpEvery)
	go snmpMon.Run()
	go snmpMon.wanLoop()
}

func newSNMPMon(c *SNMPConf, ev eventSink) *SNMPMon {
	return &SNMPMon{conf: c, ev: ev, prev: map[int]ifCounters{}, memo: map[int]*ifMemo{}, first: true,
		state: SNMPState{Active: true, Name: c.Name, IP: c.IP, Ifaces: []SNMPIface{}, Inet: SNMPInet{Estado: "nd"}}}
}

func (m *SNMPMon) Run() {
	for {
		m.Poll()
		time.Sleep(snmpEvery)
	}
}

// State: copia para la API. Sin SNMP configurado devuelve {activo:false}.
func SNMPStatus() SNMPState {
	if snmpMon == nil {
		return SNMPState{Ifaces: []SNMPIface{}}
	}
	snmpMon.mu.RLock()
	defer snmpMon.mu.RUnlock()
	s := snmpMon.state
	s.Ifaces = append([]SNMPIface(nil), s.Ifaces...)
	return s
}

// SNMPDeviceInfo: el cable (interfaz del router en su red) y el internet (ruta por
// omisión) de un equipo. Ancho de banda y errores son de la interfaz, compartidos
// por todos los equipos de esa red: el router no los da por equipo.
func SNMPDeviceInfo(ipStr string) SNMPDevice {
	ip := net.ParseIP(ipStr).To4()
	if snmpMon == nil || ip == nil {
		return SNMPDevice{}
	}
	m := snmpMon
	m.mu.RLock()
	defer m.mu.RUnlock()
	ifc := func(i int) *SNMPIface {
		for k := range m.state.Ifaces {
			if m.state.Ifaces[k].Index == i {
				f := m.state.Ifaces[k]
				return &f
			}
		}
		return nil
	}
	d := SNMPDevice{Router: m.state.Name, RouterIP: m.state.IP, Last: m.state.Last, Down: m.state.Down}
	for _, n := range m.extra.nets {
		if ip.Mask(net.IPMask(n.mask)).Equal(n.ip.Mask(net.IPMask(n.mask))) && !n.ip.IsLoopback() {
			ones, _ := net.IPMask(n.mask).Size()
			d.Active = true
			d.Red = fmt.Sprintf("%s/%d", n.ip, ones)
			d.Cable = ifc(n.ifIndex)
			break
		}
	}
	if a, ok := m.extra.arp[ip.String()]; ok {
		d.Active, d.EnARP, d.MAC = true, true, a.mac
		if d.Cable == nil {
			d.Cable = ifc(a.ifIndex)
		}
	}
	if !d.Active {
		return SNMPDevice{}
	}
	if wan := m.wanIndex(m.state.Ifaces); wan != 0 && (d.Cable == nil || d.Cable.Index != wan) {
		d.Internet = ifc(wan)
	}
	return d
}

// segmentsOf: segmentos de una interfaz = redes propias del router + rutas directas,
// con cuántos equipos de cada uno tiene el router en su tabla ARP.
func (m *SNMPMon) segmentsOf(idx int) []SNMPSeg {
	segs := map[string]*SNMPSeg{}
	cidr := func(n rtNet) (string, *net.IPNet) {
		ones, _ := net.IPMask(n.mask).Size()
		_, nw, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", n.ip, ones))
		return nw.String(), nw
	}
	nets := map[string]*net.IPNet{}
	for _, n := range append(append([]rtNet{}, m.extra.conn...), m.extra.nets...) {
		if n.ifIndex != idx || n.mask == nil {
			continue
		}
		k, nw := cidr(n)
		if segs[k] == nil {
			segs[k] = &SNMPSeg{Red: k}
			nets[k] = nw
		}
		if !n.ip.Equal(nw.IP) { // es una dirección del router, no la red
			segs[k].Router = n.ip.String()
		}
	}
	for ipS, a := range m.extra.arp {
		if a.ifIndex != idx {
			continue
		}
		ip := net.ParseIP(ipS)
		for k, nw := range nets {
			if nw.Contains(ip) {
				segs[k].Equipos++
				break
			}
		}
	}
	out := make([]SNMPSeg, 0, len(segs))
	for _, s := range segs {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Equipos > out[j].Equipos || out[i].Equipos == out[j].Equipos && out[i].Red < out[j].Red
	})
	return out
}

// SNMPARPIn: los equipos de un segmento (CIDR) según la tabla ARP del router.
func SNMPARPIn(cidr string) []SNMPARPRow {
	rows := []SNMPARPRow{}
	_, nw, err := net.ParseCIDR(cidr)
	if snmpMon == nil || err != nil {
		return rows
	}
	snmpMon.mu.RLock()
	defer snmpMon.mu.RUnlock()
	for ip, a := range snmpMon.extra.arp {
		if nw.Contains(net.ParseIP(ip)) {
			rows = append(rows, SNMPARPRow{IP: ip, MAC: a.mac})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return bytesLess(net.ParseIP(rows[i].IP).To4(), net.ParseIP(rows[j].IP).To4())
	})
	return rows
}

func bytesLess(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// wanIndex: interfaz de internet = la de la ruta por omisión; si el router no la
// da, la que se llame internet/wan. 0 = no se sabe.
func (m *SNMPMon) wanIndex(list []SNMPIface) int {
	if m.extra.wan != 0 {
		return m.extra.wan
	}
	for _, f := range list {
		if s := strings.ToLower(f.Alias + " " + f.Name); strings.Contains(s, "internet") || strings.Contains(s, "wan") {
			return f.Index
		}
	}
	return 0
}

func (m *SNMPMon) client() *gosnmp.GoSNMP {
	c := m.conf
	g := &gosnmp.GoSNMP{Target: c.IP, Port: c.Port, Timeout: 3 * time.Second, Retries: 1,
		MaxOids: gosnmp.MaxOids, MaxRepetitions: 20}
	if c.Version == "3" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		up := &gosnmp.UsmSecurityParameters{UserName: c.User}
		level := gosnmp.NoAuthNoPriv
		if c.AuthKey != "" {
			level = gosnmp.AuthNoPriv
			up.AuthenticationPassphrase = c.AuthKey
			up.AuthenticationProtocol = map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA,
				"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}[c.AuthProto]
			if up.AuthenticationProtocol == 0 {
				up.AuthenticationProtocol = gosnmp.SHA
			}
			if c.PrivKey != "" {
				level = gosnmp.AuthPriv
				up.PrivacyPassphrase = c.PrivKey
				up.PrivacyProtocol = map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES,
					"AES192": gosnmp.AES192, "AES256": gosnmp.AES256}[c.PrivProto]
				if up.PrivacyProtocol == 0 {
					up.PrivacyProtocol = gosnmp.AES
				}
			}
		}
		g.MsgFlags = level
		g.SecurityParameters = up
	} else {
		g.Version = gosnmp.Version2c
		g.Community = c.Community
	}
	return g
}

type rawIf struct {
	name, descr, alias              string
	typ, admin, oper                int
	speed, highSpeed                uint64
	in32, out32, hcIn, hcOut, errs  uint64
	hasHC, hasHighSpeed, hasCounter bool
}

// read hace la consulta completa al router.
func (m *SNMPMon) read() (sys map[string]gosnmp.SnmpPDU, ifs map[int]*rawIf, ex rtExtra, err error) {
	g := m.client()
	if err = g.Connect(); err != nil {
		return
	}
	defer g.Conn.Close()
	r, err := g.Get([]string{oidSysDescr, oidSysUpTime, oidSysName})
	if err != nil {
		return
	}
	if r.Error != gosnmp.NoError {
		err = fmt.Errorf("el router respondió %s", r.Error)
		return
	}
	sys = map[string]gosnmp.SnmpPDU{}
	for _, p := range r.Variables {
		sys[p.Name] = p
	}
	ifs = map[int]*rawIf{}
	get := func(i int) *rawIf {
		if ifs[i] == nil {
			ifs[i] = &rawIf{}
		}
		return ifs[i]
	}
	walk := func(root string, f func(x *rawIf, p gosnmp.SnmpPDU)) error {
		pdus, e := g.BulkWalkAll(root)
		if e != nil {
			return e
		}
		for _, p := range pdus {
			if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || p.Type == gosnmp.EndOfMibView {
				continue
			}
			idx, e := strconv.Atoi(p.Name[strings.LastIndex(p.Name, ".")+1:])
			if e != nil {
				continue
			}
			f(get(idx), p)
		}
		return nil
	}
	str := func(p gosnmp.SnmpPDU) string {
		if b, ok := p.Value.([]byte); ok {
			return strings.TrimSpace(strings.Trim(string(b), "\x00"))
		}
		return fmt.Sprint(p.Value)
	}
	num := func(p gosnmp.SnmpPDU) uint64 {
		if v := gosnmp.ToBigInt(p.Value); v != nil && v.Sign() >= 0 && v.IsUint64() {
			return v.Uint64()
		}
		return 0
	}
	// la tabla básica (IF-MIB ifTable) es obligatoria; la extendida (ifXTable) es opcional
	for _, w := range []struct {
		oid string
		f   func(x *rawIf, p gosnmp.SnmpPDU)
	}{
		{oidIfDescr, func(x *rawIf, p gosnmp.SnmpPDU) { x.descr = str(p) }},
		{oidIfType, func(x *rawIf, p gosnmp.SnmpPDU) { x.typ = int(num(p)) }},
		{oidIfSpeed, func(x *rawIf, p gosnmp.SnmpPDU) { x.speed = num(p) }},
		{oidIfAdmin, func(x *rawIf, p gosnmp.SnmpPDU) { x.admin = int(num(p)) }},
		{oidIfOper, func(x *rawIf, p gosnmp.SnmpPDU) { x.oper = int(num(p)) }},
		{oidIfInOct, func(x *rawIf, p gosnmp.SnmpPDU) { x.in32 = num(p); x.hasCounter = true }},
		{oidIfOutOct, func(x *rawIf, p gosnmp.SnmpPDU) { x.out32 = num(p) }},
		{oidIfInErr, func(x *rawIf, p gosnmp.SnmpPDU) { x.errs += num(p) }},
		{oidIfInDisc, func(x *rawIf, p gosnmp.SnmpPDU) { x.errs += num(p) }},
	} {
		if err = walk(w.oid, w.f); err != nil {
			return
		}
	}
	for _, w := range []struct {
		oid string
		f   func(x *rawIf, p gosnmp.SnmpPDU)
	}{
		{oidIfName, func(x *rawIf, p gosnmp.SnmpPDU) { x.name = str(p) }},
		{oidIfAlias, func(x *rawIf, p gosnmp.SnmpPDU) { x.alias = str(p) }},
		{oidIfHighSpeed, func(x *rawIf, p gosnmp.SnmpPDU) { x.highSpeed = num(p); x.hasHighSpeed = true }},
		{oidIfHCInOct, func(x *rawIf, p gosnmp.SnmpPDU) { x.hcIn = num(p); x.hasHC = true }},
		{oidIfHCOutOct, func(x *rawIf, p gosnmp.SnmpPDU) { x.hcOut = num(p) }},
	} {
		_ = walk(w.oid, w.f) // equipos viejos no tienen ifXTable: se usan los de 32 bits
	}
	ex = m.readExtra(g, num)
	return sys, ifs, ex, nil
}

// readExtra: redes del router, ARP y ruta por omisión. Si algo falla queda vacío.
func (m *SNMPMon) readExtra(g *gosnmp.GoSNMP, num func(gosnmp.SnmpPDU) uint64) rtExtra {
	ex := rtExtra{arp: map[string]arpEnt{}}
	// sufijo del OID después de la raíz, ej. "3.192.168.10.20"
	suffix := func(name, root string) string { return strings.TrimPrefix(strings.TrimPrefix(name, root), ".") }
	ok := func(p gosnmp.SnmpPDU) bool {
		return p.Type != gosnmp.NoSuchObject && p.Type != gosnmp.NoSuchInstance && p.Type != gosnmp.EndOfMibView
	}
	byIP := map[string]*rtNet{}
	if pdus, err := g.BulkWalkAll(oidIpAdIfIndex); err == nil {
		for _, p := range pdus {
			if ip := net.ParseIP(suffix(p.Name, oidIpAdIfIndex)).To4(); ok(p) && ip != nil {
				byIP[ip.String()] = &rtNet{ip: ip, ifIndex: int(num(p))}
			}
		}
	}
	if pdus, err := g.BulkWalkAll(oidIpAdMask); err == nil {
		for _, p := range pdus {
			n := byIP[suffix(p.Name, oidIpAdMask)]
			if mk, isStr := p.Value.(string); ok(p) && n != nil && isStr {
				n.mask = net.ParseIP(mk).To4()
			}
		}
	}
	for _, n := range byIP {
		if n.mask != nil && !n.ip.IsLoopback() {
			ex.nets = append(ex.nets, *n)
		}
	}
	if pdus, err := g.BulkWalkAll(oidArpPhys); err == nil {
		for _, p := range pdus {
			s := suffix(p.Name, oidArpPhys)
			i := strings.Index(s, ".")
			b, isB := p.Value.([]byte)
			if !ok(p) || i < 0 || !isB || len(b) != 6 {
				continue
			}
			idx, _ := strconv.Atoi(s[:i])
			if ip := net.ParseIP(s[i+1:]).To4(); ip != nil {
				ex.arp[ip.String()] = arpEnt{mac: net.HardwareAddr(b).String(), ifIndex: idx}
			}
		}
	}
	if r, err := g.Get([]string{oidDefRouteIf}); err == nil && len(r.Variables) == 1 && ok(r.Variables[0]) {
		ex.wan = int(num(r.Variables[0]))
	}
	// rutas directas (siguiente salto 0.0.0.0): segmentos que el router alcanza por el cable
	routes := map[string]*rtNet{}
	next := map[string]string{}
	if pdus, err := g.BulkWalkAll(oidRouteIf); err == nil {
		for _, p := range pdus {
			if ip := net.ParseIP(suffix(p.Name, oidRouteIf)).To4(); ok(p) && ip != nil {
				routes[ip.String()] = &rtNet{ip: ip, ifIndex: int(num(p))}
			}
		}
	}
	if pdus, err := g.BulkWalkAll(oidRouteNext); err == nil {
		for _, p := range pdus {
			if v, isStr := p.Value.(string); ok(p) && isStr {
				next[suffix(p.Name, oidRouteNext)] = v
			}
		}
	}
	if pdus, err := g.BulkWalkAll(oidRouteMask); err == nil {
		for _, p := range pdus {
			if r, isStr := p.Value.(string); ok(p) && isStr && routes[suffix(p.Name, oidRouteMask)] != nil {
				routes[suffix(p.Name, oidRouteMask)].mask = net.ParseIP(r).To4()
			}
		}
	}
	for k, r := range routes {
		if r.mask != nil && k != "0.0.0.0" && next[k] == "0.0.0.0" && !r.ip.IsLoopback() {
			ex.conn = append(ex.conn, *r)
		}
	}
	return ex
}

// delta entre dos lecturas de un contador; los de 32 bits se dan la vuelta.
func counterDelta(prev, cur uint64, hc bool) (uint64, bool) {
	if cur >= prev {
		return cur - prev, true
	}
	if !hc && prev <= 1<<32 {
		return cur + (1 << 32) - prev, true
	}
	return 0, false // reinicio del router o contador borrado: no se calcula esta vez
}

// Poll lee una vez y actualiza el estado y los eventos.
func (m *SNMPMon) Poll() {
	sys, ifs, ex, err := m.read()
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	name := m.conf.Name
	if err != nil {
		m.fails++
		m.state.Error = simplifySNMPErr(err)
		if m.fails >= snmpFailsDown && !m.down {
			m.down = true
			m.state.Down = true
			m.event("offline", fmt.Sprintf("%s (%s) no responde por SNMP: %s", name, m.conf.IP, m.state.Error))
		}
		return
	}
	if m.down {
		m.event("online", fmt.Sprintf("%s (%s) volvió a responder por SNMP", name, m.conf.IP))
	}
	m.fails, m.down = 0, false
	if len(ex.nets) > 0 || len(ex.arp) > 0 {
		m.extra = ex
	}
	m.state.Down, m.state.Error = false, ""
	m.state.Last = &now
	if p, ok := sys[oidSysName]; ok {
		if b, ok := p.Value.([]byte); ok {
			m.state.SysName = string(b)
		}
	}
	if p, ok := sys[oidSysDescr]; ok {
		if b, ok := p.Value.([]byte); ok {
			m.state.SysDescr = strings.TrimSpace(string(b))
		}
	}
	if p, ok := sys[oidSysUpTime]; ok {
		up := gosnmp.ToBigInt(p.Value)
		if up == nil {
			up = big.NewInt(0)
		}
		newUp := up.Int64() / 100
		if !m.first && m.state.Uptime > 0 && newUp+60 < m.state.Uptime {
			m.event("info", fmt.Sprintf("%s se reinició (llevaba encendido %s)", name, fmtUptime(m.state.Uptime)))
		}
		m.state.Uptime = newUp
	}

	dt := now.Sub(m.prevT).Seconds()
	idxs := make([]int, 0, len(ifs))
	for i := range ifs {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	list := make([]SNMPIface, 0, len(idxs))
	cur := map[int]ifCounters{}
	for _, i := range idxs {
		x := ifs[i]
		if x.typ == 24 { // loopback: no es un puerto
			continue
		}
		f := SNMPIface{Index: i, Name: x.name, Alias: x.alias, Up: x.oper == 1, AdminUp: x.admin != 2, ErrorTotal: x.errs}
		if f.Name == "" {
			f.Name = x.descr
		}
		if f.Name == "" {
			f.Name = "if" + strconv.Itoa(i)
		}
		switch {
		case x.hasHighSpeed && x.highSpeed > 0:
			f.SpeedMbps = float64(x.highSpeed)
		case x.speed > 0 && x.speed < 1<<32-1:
			f.SpeedMbps = float64(x.speed) / 1e6
		}
		c := ifCounters{in: x.in32, out: x.out32, errs: x.errs}
		if x.hasHC && (x.hcIn > 0 || x.hcOut > 0 || x.in32 == 0) {
			c = ifCounters{in: x.hcIn, out: x.hcOut, errs: x.errs, hc: true}
		}
		cur[i] = c
		if p, ok := m.prev[i]; ok && dt > 1 && p.hc == c.hc {
			if d, ok := counterDelta(p.in, c.in, c.hc); ok {
				f.InMbps = round1(float64(d) * 8 / dt / 1e6)
			}
			if d, ok := counterDelta(p.out, c.out, c.hc); ok {
				f.OutMbps = round1(float64(d) * 8 / dt / 1e6)
			}
			if c.errs >= p.errs {
				f.Errors = c.errs - p.errs
			}
		}
		// eventos: solo cambios, y nunca en la primera lectura
		mm := m.memo[i]
		if mm == nil {
			mm = &ifMemo{}
			m.memo[i] = mm
		}
		label := f.Name
		if f.Alias != "" {
			label += " (" + f.Alias + ")"
		}
		// el puerto de internet lo avisa la lectura rápida (snmp_wan.go) si está funcionando
		if !m.first && f.AdminUp && !(m.state.Inet.Rapida && i == m.extra.wan) {
			if mm.up && !f.Up && mm.everUp {
				m.event("offline", fmt.Sprintf("%s: la interfaz %s se cayó", name, label))
			} else if !mm.up && f.Up && mm.everUp {
				m.event("online", fmt.Sprintf("%s: la interfaz %s volvió", name, label))
			}
		}
		if f.Errors > 0 {
			if !mm.errUntil.After(now) && !m.first {
				m.event("info", fmt.Sprintf("%s: errores en la interfaz %s (%d en 30 s). Puede ser cable o puerto dañado", name, label, f.Errors))
			}
			mm.errUntil = now.Add(snmpErrQuiet)
		}
		f.ErrActive = mm.errUntil.After(now)
		mm.up = f.Up
		if f.Up {
			mm.everUp = true
		}
		f.Fell = f.AdminUp && !f.Up && mm.everUp
		list = append(list, f)
	}
	m.prev, m.prevT, m.first = cur, now, false

	// por cable: sus redes, cuántos equipos ve el router ahí y cuál es el de internet
	hosts := map[int]int{}
	for _, a := range m.extra.arp {
		hosts[a.ifIndex]++
	}
	for k := range list {
		f := &list[k]
		f.Equipos = hosts[f.Index]
		f.Segmentos = m.segmentsOf(f.Index)
	}
	if w := m.wanIndex(list); w != 0 {
		for k := range list {
			list[k].Internet = list[k].Index == w
		}
	}

	// resumen: entrada/salida de la interfaz principal (la configurada o la más usada)
	st := &m.state
	st.Ifaces, st.Total, st.UpN, st.ErrN, st.FellN = list, 0, 0, 0, 0
	best := -1
	for k, f := range list {
		if !f.AdminUp {
			continue
		}
		st.Total++
		if f.Up {
			st.UpN++
		}
		if f.ErrActive {
			st.ErrN++
		}
		if f.Fell {
			st.FellN++
		}
		if m.conf.Uplink != "" {
			if strings.EqualFold(f.Name, m.conf.Uplink) || strings.EqualFold(f.Alias, m.conf.Uplink) {
				best = k
			}
		} else if best < 0 || f.InMbps+f.OutMbps > list[best].InMbps+list[best].OutMbps {
			best = k
		}
	}
	st.InMbps, st.OutMbps, st.Uplink = 0, 0, ""
	if best >= 0 {
		st.InMbps, st.OutMbps, st.Uplink = list[best].InMbps, list[best].OutMbps, list[best].Name
	}
}

func (m *SNMPMon) event(kind, msg string) {
	if m.ev != nil {
		m.ev.AddEvent(kind, msg)
	}
}

func simplifySNMPErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout"):
		return "no contesta (revisa IP, comunidad/usuario y que el router permita la IP de la Pi)"
	case strings.Contains(s, "authentication") || strings.Contains(s, "wrong digest") || strings.Contains(s, "unknown user"):
		return "usuario o claves SNMP incorrectos"
	}
	return s
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

func fmtUptime(s int64) string {
	d := s / 86400
	if d > 0 {
		return fmt.Sprintf("%d días", d)
	}
	return fmt.Sprintf("%d h %d min", s/3600, s%3600/60)
}
