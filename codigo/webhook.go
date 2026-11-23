package main

// Avisos (webhook) al sistema de tickets.
// Config en /etc/monitoreo/api.conf:
//   MONITOREO_WEBHOOK_URL=https://tickets.midominio.com/api/monitoreo   (vacío = apagado)
//   MONITOREO_WEBHOOK_TOKEN=...   (va como  Authorization: Bearer <token>)
//
//   MONITOREO_WEBHOOK_CONFIRMAR=180   segundos que la falla debe seguir SIN interrupción antes del ticket
//   MONITOREO_WEBHOOK_HORARIO=9-18    horario de avisos por segmento ("0-0" = siempre); internet general: siempre
//
// Cuidados para no levantar tickets falsos:
// - nada se avisa hasta que la falla sigue sin interrupción el tiempo de confirmación; si se recupera antes,
//   se olvida sin aviso (parpadeo). Al arrancar la Pi se espera ese tiempo antes de juzgar.
// - internet general = 8.8.8.8 Y 1.1.1.1 sin responder por el cable de la Pi.
// - con internet general caído o más de la mitad de segmentos sin internet: UN ticket, no uno por segmento.
// - segmento sin internet solo si su puerta contestaba antes y tiene equipos conectados.
// Eventos: sin_internet, internet_volvio, falla_general_segmentos, segmento_sin_internet, segmento_volvio,
//   segmento_caido, segmento_recuperado, falla_general_resuelta.  (los cierres solo se mandan si antes se mandó la apertura)
// "id" es estable por incidente (mismo corte = mismo id): el sistema de tickets lo usa para no
// duplicar y para cerrar el ticket con el aviso de "volvio".
// Si el envío falla (p. ej. la Pi no tiene internet y el dominio está afuera) se reintenta cada 30 s
// hasta 48 h; los avisos guardan la hora real del corte.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type hookMsg struct {
	Evento     string   `json:"evento"`
	ID         string   `json:"id"`
	Hora       int64    `json:"hora"`            // unix: cuándo se detectó el cambio
	Desde      int64    `json:"desde,omitempty"` // unix: inicio del problema
	DuracionS  int64    `json:"duracionSeg,omitempty"`
	Seg        string   `json:"seg,omitempty"`
	Segs       []string `json:"segs,omitempty"` // segmentos_caidos: todos los del grupo
	Nombre     string   `json:"nombre,omitempty"`
	Puerta     string   `json:"puerta,omitempty"`
	Conectados int      `json:"conectados,omitempty"`
	Mensaje    string   `json:"mensaje"`
	Origen     string   `json:"origen"`
	Version    string   `json:"version"`
	intentos   int
}

type webhook struct {
	url, token string
	api        *apiV1
	mu         sync.Mutex
	cola       []*hookMsg
	client     *http.Client
	confirmar  int64 // segundos que la falla debe seguir sin interrupción antes de avisar
	horaIni    int   // horario para avisos de segmento (internet general: siempre)
	horaFin    int
}

func startWebhook(api *apiV1, url, token string) {
	if url == "" {
		return
	}
	h := &webhook{url: url, token: token, api: api, client: &http.Client{Timeout: 15 * time.Second},
		confirmar: 180, horaIni: 9, horaFin: 18}
	if n, err := strconv.Atoi(os.Getenv("MONITOREO_WEBHOOK_CONFIRMAR")); err == nil && n >= 30 {
		h.confirmar = int64(n)
	}
	if v := os.Getenv("MONITOREO_WEBHOOK_HORARIO"); v != "" { // "9-18"; "0-0" = siempre
		var a, b int
		if _, err := fmt.Sscanf(v, "%d-%d", &a, &b); err == nil && a >= 0 && b <= 24 {
			h.horaIni, h.horaFin = a, b
		}
	}
	log.Printf("avisos (webhook) activados → %s (confirmar %d s, horario segmentos %d-%d)", url, h.confirmar, h.horaIni, h.horaFin)
	go h.vigilar()
	go h.enviarLoop()
}

func (h *webhook) push(m hookMsg) {
	m.Origen, m.Version = "Monitoreo de Red", version
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cola) >= 500 { // no crecer sin límite si el destino no responde
		h.cola = h.cola[1:]
	}
	h.cola = append(h.cola, &m)
}

// incidente: una falla vista; solo se avisa (ticket) si sigue sin interrupción "confirmar" segundos.
type incidente struct {
	abre    hookMsg
	visto   int64 // primera vez que lo vio ESTE vigilante (no la hora del corte)
	enviado bool
}

// paso compara lo que falla ahora contra los incidentes abiertos:
// - nuevo: se apunta, NO se avisa todavía
// - sigue ≥ confirmar: se manda el aviso de apertura (una sola vez)
// - ya no falla: si se había avisado, se manda el cierre; si no, se olvida sin avisar (fue un parpadeo)
func (h *webhook) paso(inc map[string]*incidente, activos map[string]hookMsg, cierre string, now int64) {
	for k, m := range activos {
		i, ok := inc[k]
		if !ok {
			i = &incidente{abre: m, visto: now}
			inc[k] = i
		}
		if !i.enviado && now-i.visto >= h.confirmar {
			i.abre.Hora = now
			h.push(i.abre)
			i.enviado = true
		}
	}
	for k, i := range inc {
		if _, sigue := activos[k]; sigue {
			continue
		}
		if i.enviado {
			c := i.abre
			c.Evento, c.Hora, c.DuracionS = cierre, now, now-c.Desde
			c.Mensaje = "Se resolvió: " + c.Mensaje
			h.push(c)
		}
		delete(inc, k)
	}
}

func dentroHorario(t time.Time, desde, hasta int) bool {
	if desde == hasta {
		return true // sin horario
	}
	h := t.Hour()
	return h >= desde && h < hasta
}

func (h *webhook) vigilar() {
	inet := map[string]*incidente{}
	general := map[string]*incidente{}
	generalCaidos := map[string]*incidente{}
	sinNet := map[string]*incidente{}
	caidos := map[string]*incidente{}
	arranque := time.Now().Unix()
	for {
		time.Sleep(10 * time.Second)
		e := h.api.estado()
		now := time.Now().Unix()
		// al arrancar la Pi se espera el tiempo de confirmación antes de juzgar nada
		if e.Internet.Estado == "revisando" || now-arranque < h.confirmar {
			continue
		}

		// 1) Internet general: 8.8.8.8 y 1.1.1.1 sin responder (ya confirmado por WatchInternet)
		act := map[string]hookMsg{}
		inetCaido := e.Internet.Estado == "sin"
		if inetCaido {
			act["internet"] = hookMsg{Evento: "sin_internet", ID: fmt.Sprintf("internet-%d", e.Internet.Desde),
				Desde: e.Internet.Desde, Mensaje: "Se cayó el internet de la red"}
		}
		// Más de la mitad de los segmentos sin internet a la vez = una sola falla general (un ticket),
		// no un ticket por segmento.
		masivo := e.Resumen.ConInternet+e.Resumen.SinInternet >= 4 &&
			e.Resumen.SinInternet*2 > e.Resumen.ConInternet+e.Resumen.SinInternet
		h.paso(inet, act, "internet_volvio", now)
		act = map[string]hookMsg{}
		if masivo && !inetCaido {
			act["masivo"] = hookMsg{Evento: "falla_general_segmentos", ID: fmt.Sprintf("masivo-%d", now),
				Desde: now, Conectados: e.Resumen.SinInternet,
				Mensaje: fmt.Sprintf("%d de %d segmentos sin internet a la vez", e.Resumen.SinInternet, e.Resumen.ConInternet+e.Resumen.SinInternet)}
		}
		h.paso(general, act, "falla_general_resuelta", now)

		// Si se cayó el internet general o hay falla masiva, NO se abren tickets por segmento (misma causa).
		// Fuera de horario tampoco: los equipos se apagan y no es falla.
		enHorario := dentroHorario(time.Now(), h.horaIni, h.horaFin)

		// 2) Segmento sin internet: su puerta contestaba y dejó de contestar, y hay gente conectada
		act = map[string]hookMsg{}
		for _, s := range e.SegmentosSinInternet {
			{
				if s.Conectados == 0 {
					continue
				}
				desde := s.Desde
				if desde == 0 {
					desde = now
				}
				act[s.Seg] = hookMsg{Evento: "segmento_sin_internet", ID: fmt.Sprintf("seg-%s-%d", s.Seg, desde),
					Desde: desde, Seg: s.Seg, Nombre: s.Nombre, Puerta: s.Puerta, Conectados: s.Conectados,
					Mensaje: "Segmento sin internet: " + segLabel(s.Seg)}
			}
		}
		if inetCaido || !enHorario || masivo {
			act = soloAvisados(sinNet, act) // no abrir nuevos; los ya avisados se cierran solo si de verdad se resolvieron
		}
		h.paso(sinNet, act, "segmento_volvio", now)

		// 3) Segmento caído completo (todos sus equipos dejaron de responder juntos)
		act = map[string]hookMsg{}
		{
			for _, s := range h.api.store.Segments() {
				if !s.Down {
					continue
				}
				desde := s.DownSince.Unix()
				if s.DownSince.IsZero() {
					desde = now
				}
				act[s.Seg] = hookMsg{Evento: "segmento_caido", ID: fmt.Sprintf("caido-%s-%d", s.Seg, desde),
					Desde: desde, Seg: s.Seg, Nombre: s.Name, Puerta: s.Gateway, Conectados: s.DownCount,
					Mensaje: "Segmento sin respuesta: " + segLabel(s.Seg)}
			}
		}
		// Muchos segmentos caídos a la vez (o internet caído) = la Pi perdió la red o se apagó un switch
		// central: lo cubre el ticket general, no uno por segmento.
		caidosMasivo := e.Resumen.Segmentos >= 4 && len(act)*2 > e.Resumen.Segmentos
		gen := map[string]hookMsg{}
		if caidosMasivo && !inetCaido {
			gen["caidos"] = hookMsg{Evento: "falla_general_segmentos", ID: fmt.Sprintf("caidos-%d", now),
				Desde: now, Conectados: len(act),
				Mensaje: fmt.Sprintf("%d de %d segmentos sin respuesta a la vez (¿switch central apagado?)", len(act), e.Resumen.Segmentos)}
		}
		h.paso(generalCaidos, gen, "falla_general_resuelta", now)
		act = agrupar(act, 120)
		if !enHorario || inetCaido || caidosMasivo {
			act = soloAvisados(caidos, act)
		}
		h.paso(caidos, act, "segmento_recuperado", now)
	}
}

// agrupar: segmentos que cayeron con ≤ventana segundos de diferencia = una sola falla
// (probable switch que maneja varios segmentos) → un ticket "segmentos_caidos" con la lista.
// La clave del grupo es la hora del primero que cayó, así sigue siendo el mismo ticket.
func agrupar(act map[string]hookMsg, ventana int64) map[string]hookMsg {
	list := make([]hookMsg, 0, len(act))
	for _, m := range act {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Desde != list[j].Desde {
			return list[i].Desde < list[j].Desde
		}
		return list[i].Seg < list[j].Seg
	})
	out := map[string]hookMsg{}
	for i := 0; i < len(list); {
		j := i + 1
		for j < len(list) && list[j].Desde-list[i].Desde <= ventana {
			j++
		}
		if j-i == 1 {
			out[list[i].Seg] = list[i]
		} else {
			g := hookMsg{Evento: "segmentos_caidos", ID: fmt.Sprintf("grupo-%d", list[i].Desde), Desde: list[i].Desde}
			var nombres []string
			for _, m := range list[i:j] {
				g.Segs = append(g.Segs, m.Seg)
				g.Conectados += m.Conectados
				nombres = append(nombres, segLabel(m.Seg))
			}
			g.Mensaje = fmt.Sprintf("%d segmentos sin respuesta a la vez (probable switch): %s", j-i, strings.Join(nombres, ", "))
			out[g.ID] = g
		}
		i = j
	}
	return out
}

// soloAvisados: de lo que falla ahora, deja solo lo que ya tenía ticket (no se abren nuevos).
func soloAvisados(inc map[string]*incidente, act map[string]hookMsg) map[string]hookMsg {
	out := map[string]hookMsg{}
	for k, m := range act {
		if i, ok := inc[k]; ok && i.enviado {
			out[k] = m
		}
	}
	return out
}

func (h *webhook) enviarLoop() {
	for {
		h.mu.Lock()
		var m *hookMsg
		if len(h.cola) > 0 {
			m = h.cola[0]
		}
		h.mu.Unlock()
		if m == nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if err := h.enviar(m); err != nil {
			m.intentos++
			if m.intentos == 1 || m.intentos%20 == 0 {
				log.Printf("webhook: no se pudo mandar %s (%s), reintento: %v", m.Evento, m.ID, err)
			}
			if time.Since(time.Unix(m.Hora, 0)) > 48*time.Hour {
				log.Printf("webhook: se descarta %s (%s) tras 48 h", m.Evento, m.ID)
				h.quitar(m)
			}
			time.Sleep(30 * time.Second)
			continue
		}
		h.quitar(m)
	}
}

func (h *webhook) quitar(m *hookMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cola) > 0 && h.cola[0] == m {
		h.cola = h.cola[1:]
	}
}

func (h *webhook) enviar(m *hookMsg) error {
	b, _ := json.Marshal(m)
	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "monitoreo-de-red/"+version)
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("respuesta %d", resp.StatusCode)
	}
	return nil
}
