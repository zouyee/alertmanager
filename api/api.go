// Copyright 2015 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bufio"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/prometheus/common/version"
	"github.com/prometheus/prometheus/pkg/labels"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/pkg/parse"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/silence"
	"github.com/prometheus/alertmanager/silence/silencepb"
	"github.com/prometheus/alertmanager/types"
	"github.com/weaveworks/mesh"
)

var (
	numReceivedAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "alertmanager",
		Name:      "alerts_received_total",
		Help:      "The total number of received alerts.",
	}, []string{"status"})

	numInvalidAlerts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "alertmanager",
		Name:      "alerts_invalid_total",
		Help:      "The total number of received alerts that were invalid.",
	})
)

func init() {
	prometheus.Register(numReceivedAlerts)
	prometheus.Register(numInvalidAlerts)
}

// API provides registration of handlers for API routes.
type API struct {
	alerts         provider.Alerts
	silences       *silence.Silences
	config         *config.Config
	route          *dispatch.Route
	resolveTimeout time.Duration
	uptime         time.Time
	mrouter        *mesh.Router

	groups         groupsFn
	getAlertStatus getAlertStatusFn

	mtx sync.RWMutex
}

type groupsFn func([]*labels.Matcher) dispatch.AlertOverview
type getAlertStatusFn func(model.Fingerprint) types.AlertStatus

// New returns a new API.
func New(alerts provider.Alerts, silences *silence.Silences, gf groupsFn, sf getAlertStatusFn, router *mesh.Router) *API {
	return &API{
		alerts:         alerts,
		silences:       silences,
		groups:         gf,
		getAlertStatus: sf,
		uptime:         time.Now(),
		mrouter:        router,
	}
}

type Labels struct {
	AlertSeverity string `json:"severity"`
}

type AlertJsonStruct struct {
	AlertName        string `json:"alert"`
	AlertAddition    string `json:"if"`
	AlertTime        string `json:"for"`
	AlertSeverity    Labels `json:"labels"`
	AlertDescription string `json:"annotations"`
}

type alertsResponseJSONStruct struct {
	Array []AlertJsonStruct `json:"alerts"`
}

type AlertInfo struct {
	Status       string     `json:"status"`
	Labels       Label      `json:"labels"`
	Annotations  Annotation `json:"annotations"`
	StartsAt     string     `json:"startsAt"`
	EndsAt       string     `json:"endsAt"`
	GeneratorURL string     `json:"generatorURL"`
}

type Annotation struct {
	Description string `json:"description"`
	Summary     string `json:"summary"`
}

type Label struct {
	AlertName string `json:"alertname，omitempty"`
	Group     string `json:"group，omitempty"`
	Instance  string `json:"instance，omitempty"`
	Job       string `json:"job，omitempty"`
	Monitor   string `json:"monitor，omitempty"`
	Severity  string `json:"severity，omitempty"`
}
type GroupLabel struct {
	AlertName string `json:"alertname，omitempty"`
}

type AlarmJsonStruct struct {
	Receiver     string      `json:"-"`
	Status       string      `json:"-"`
	Alerts       []AlertInfo `json:"alerts"`
	GroupLabels  GroupLabel  `json:"groupLabels"`
	CommonLabels Label       `json:"commonLabels"`
	ExternalURL  string      `json:"externalURL"`
	Version      string      `json:"version"`
	GroupKey     uint64      `json:"groupKey"`
}

type Member struct {
	Source      string `xml:"source,attr"`
	Code        string `xml:"code,attr"`
	Grade       string `xml:"grade,attr"`
	Time        string `xml:"time,attr"`
	CaseId      string `xml:"caseid,attr"`
	Description string `xml:",chardata"`
}

type Struct struct {
	Name    string `xml:"dn,attr"`
	Members Member `xml:"alarm"`
}

type Result struct {
	XMLName xml.Name `xml:"dc"`
	Structs []Struct `xml:"mo"`
}

type UserModal struct {
	Uid      int     `json:"uid"`
	Uname    string  `json:"uname"`
	Mname    string  `json:"mname"`
	Cpus     float64 `json:"cpus"`
	Mem      float64 `json:"mem"`
	Disk     float64 `json:"disk"`
	Instance float64 `json:"instances"`
}
type ModalResponseJSONStruct struct {
	Array []UserModal `json:"modals"`
}

// alert teml
const templ = `
{{range .Array}}
ALERT {{.AlertName}}
IF {{.AlertAddition}}
FOR {{.AlertTime}}
LABELS { severity = '{{.AlertSeverity.AlertSeverity}}' }
ANNOTATIONS {
    summary = '{{.AlertDescription}}',
    description = '{{.AlertDescription}}',
}
{{end}}
`

func GetMd5String(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// Register registers the API handlers under their correct routes
// in the given router.
func (api *API) Register(r *route.Router) {
	ihf := func(name string, f http.HandlerFunc) http.HandlerFunc {
		return prometheus.InstrumentHandlerFunc(name, func(w http.ResponseWriter, r *http.Request) {
			f(w, r)
		})
	}

	r.Options("/*path", ihf("options", func(w http.ResponseWriter, r *http.Request) {}))

	// Register legacy forwarder for alert pushing.
	r.Post("/alerts", ihf("legacy_add_alerts", api.legacyAddAlerts))

	// Register actual API.
	r = r.WithPrefix("/v1")

	r.Get("/status", ihf("status", api.status))
	r.Get("/receivers", ihf("receivers", api.receivers))
	r.Get("/alerts/groups", ihf("alert_groups", api.alertGroups))

	r.Get("/alerts", ihf("list_alerts", api.listAlerts))
	r.Post("/alerts", ihf("add_alerts", api.addAlerts))

	// alarms crud api
	r.Get("/alarms", ihf("list_alarms", api.listAlarms))
	r.Post("/alarms", ihf("add_alarm", api.addAlarm))
	r.Post("/alarms/:alarmname", ihf("edit_alarm", api.editAlarm))
	r.Del("/alarms/:alarmname", ihf("del_alarm", api.delAlarm))

	// bomc alarm
	r.Post("/bomc/webhook", ihf("webhook", api.webhook))
	r.Get("/bomc", ihf("list_bomcs", api.listBomcs))
	r.Post("/bomc", ihf("add_bomcs", api.addBomcs))
	r.Put("/bomc/:bomcid", ihf("update_bomcs", api.updateBomc))
	r.Del("/bomc/:bomcid", ihf("delete_bomcs", api.deleteBomc))

	r.Get("/silences", ihf("list_silences", api.listSilences))
	r.Post("/silences", ihf("add_silence", api.setSilence))
	r.Get("/silence/:sid", ihf("get_silence", api.getSilence))
	r.Del("/silence/:sid", ihf("del_silence", api.delSilence))

	// modal crub
	r.Get("/modals/:username", ihf("list_modals", api.listModals))
	r.Post("/modals/:username", ihf("add_modal", api.addModal))
	r.Put("/modals/:modalid", ihf("update_modal", api.updateModal))
	r.Del("/modals/:modalid", ihf("delete_modal", api.deleteModal))

}

// Bomc define
type Bomc struct {
	BomcID      string `json:"bomcID"`
	Description string `json:"description"`
}

func (api *API) webhook(w http.ResponseWriter, r *http.Request) {
	var s []model.Alert
	/*
		grade := map[string]string{
			"critical": "4",
			"major":    "3",
			"minor":    "2",
			"warning":  "1",
		}
		fmt.Printf("json post reciver %s", r)
	*/

	if err := receive(r, &s); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	for _, alert := range s {
		var Source, caseID, ALARMID string

		if instance, ok := alert.Labels["instance"]; ok {
			caseID = string(alert.Labels["alertname"]) + string(instance)
		}
		caseID = string(alert.Labels["alertname"])

		startAt, err := time.Parse("2006-01-02__15:04:05", alert.StartsAt.String())
		if err != nil {
			panic(err)
		}

		description := strings.Split(string(alert.Annotations["description"]), ":")
		ALARM := strings.Split(string(alert.Annotations["description"]), "#")

		if len(ALARM) == 3 {
			ALARMID = ALARM[2]
		}
		if strings.Split(string(alert.Annotations["description"]), ":")[1] == "node" {
			Source = string(alert.Labels["instance"])
		} else {
			Source = strings.Split(string(alert.Annotations["description"]), ":")[7]
		}

		cmd := exec.Command("trap4j", `$OID`, `$COMPONENT`, `$ALERTGROUP`,
			`$ALARMID`, `$INSTANCE`, `$ALARMCONTENT`,
			`$REVOKEID`, `$VALUE`, `$TIME`)

		cmd.Env = append(os.Environ(),
			"OID=9001.221",
			"COMPONENT="+Source,
			"ALERTGROUP="+description[1],
			"ALARMID="+ALARMID,
			"INSTANCE="+caseID,
			"ALARMCONTENT="+string(alert.Annotations["description"]),
			"REVOKEID=1",
			"VALUE="+description[4],
			"TIME="+startAt.String(),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("output:=======%s", out)

	}

	respond(w, nil)
}

// Update sets the configuration string to a new value.
func (api *API) Update(cfg *config.Config, resolveTimeout time.Duration) error {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	api.resolveTimeout = resolveTimeout
	api.config = cfg
	api.route = dispatch.NewRoute(cfg.Route, nil)
	return nil
}

type errorType string

const (
	errorNone     errorType = ""
	errorInternal           = "server_error"
	errorBadData            = "bad_data"
)

type apiError struct {
	typ errorType
	err error
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s", e.typ, e.err)
}

func (api *API) receivers(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()

	receivers := make([]string, 0, len(api.config.Receivers))
	for _, r := range api.config.Receivers {
		receivers = append(receivers, r.Name)
	}

	respond(w, receivers)
}

func (api *API) status(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()

	var status = struct {
		ConfigYAML  string            `json:"configYAML"`
		ConfigJSON  *config.Config    `json:"configJSON"`
		VersionInfo map[string]string `json:"versionInfo"`
		Uptime      time.Time         `json:"uptime"`
		MeshStatus  *meshStatus       `json:"meshStatus"`
	}{
		ConfigYAML: api.config.String(),
		ConfigJSON: api.config,
		VersionInfo: map[string]string{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"buildUser": version.BuildUser,
			"buildDate": version.BuildDate,
			"goVersion": version.GoVersion,
		},
		Uptime:     api.uptime,
		MeshStatus: getMeshStatus(api),
	}

	api.mtx.RUnlock()

	respond(w, status)
}

type meshStatus struct {
	Name     string       `json:"name"`
	NickName string       `json:"nickName"`
	Peers    []peerStatus `json:"peers"`
}

type peerStatus struct {
	Name     string `json:"name"`     // e.g. "00:00:00:00:00:01"
	NickName string `json:"nickName"` // e.g. "a"
	UID      uint64 `json:"uid"`      // e.g. "14015114173033265000"
}

func getMeshStatus(api *API) *meshStatus {
	if api.mrouter == nil {
		return nil
	}

	status := mesh.NewStatus(api.mrouter)
	strippedStatus := &meshStatus{
		Name:     status.Name,
		NickName: status.NickName,
		Peers:    make([]peerStatus, len(status.Peers)),
	}

	for i := 0; i < len(status.Peers); i++ {
		strippedStatus.Peers[i] = peerStatus{
			Name:     status.Peers[i].Name,
			NickName: status.Peers[i].NickName,
			UID:      uint64(status.Peers[i].UID),
		}
	}

	return strippedStatus
}

func (api *API) alertGroups(w http.ResponseWriter, r *http.Request) {
	var err error
	matchers := []*labels.Matcher{}

	if filter := r.FormValue("filter"); filter != "" {
		matchers, err = parse.Matchers(filter)
		if err != nil {
			respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return
		}
	}

	groups := api.groups(matchers)

	respond(w, groups)
}

func (api *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		re  *regexp.Regexp
		// Initialize result slice to prevent api returning `null` when there
		// are no alerts present
		res          = []*dispatch.APIAlert{}
		matchers     = []*labels.Matcher{}
		showSilenced = true
	)

	if filter := r.FormValue("filter"); filter != "" {
		matchers, err = parse.Matchers(filter)
		if err != nil {
			respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return
		}
	}

	if silencedParam := r.FormValue("silenced"); silencedParam != "" {
		if silencedParam == "false" {
			showSilenced = false
		} else if silencedParam != "true" {
			respondError(w, apiError{
				typ: errorBadData,
				err: fmt.Errorf(
					"parameter 'silenced' can either be 'true' or 'false', not '%v'",
					silencedParam,
				),
			}, nil)
			return
		}
	}

	if receiverParam := r.FormValue("receiver"); receiverParam != "" {
		re, err = regexp.Compile("^(?:" + receiverParam + ")$")
		if err != nil {
			respondError(w, apiError{
				typ: errorBadData,
				err: fmt.Errorf(
					"failed to parse receiver param: %s",
					receiverParam,
				),
			}, nil)
			return
		}
	}

	alerts := api.alerts.GetPending()
	defer alerts.Close()

	// TODO(fabxc): enforce a sensible timeout.
	for a := range alerts.Next() {
		if err = alerts.Err(); err != nil {
			break
		}

		routes := api.route.Match(a.Labels)
		receivers := make([]string, 0, len(routes))
		for _, r := range routes {
			receivers = append(receivers, r.RouteOpts.Receiver)
		}

		if re != nil && !regexpAny(re, receivers) {
			continue
		}

		if !alertMatchesFilterLabels(&a.Alert, matchers) {
			continue
		}

		// Continue if alert is resolved
		if !a.Alert.EndsAt.IsZero() && a.Alert.EndsAt.Before(time.Now()) {
			continue
		}

		status := api.getAlertStatus(a.Fingerprint())

		if !showSilenced && len(status.SilencedBy) != 0 {
			continue
		}

		apiAlert := &dispatch.APIAlert{
			Alert:       &a.Alert,
			Status:      status,
			Receivers:   receivers,
			Fingerprint: a.Fingerprint().String(),
		}

		res = append(res, apiAlert)
	}

	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Fingerprint < res[j].Fingerprint
	})
	respond(w, res)
}

func regexpAny(re *regexp.Regexp, ss []string) bool {
	for _, s := range ss {
		if re.MatchString(s) {
			return true
		}
	}

	return false
}

func alertMatchesFilterLabels(a *model.Alert, matchers []*labels.Matcher) bool {
	for _, m := range matchers {
		if v, prs := a.Labels[model.LabelName(m.Name)]; !prs || !m.Matches(string(v)) {
			return false
		}
	}

	return true
}

func (api *API) legacyAddAlerts(w http.ResponseWriter, r *http.Request) {
	var legacyAlerts = []struct {
		Summary     model.LabelValue `json:"summary"`
		Description model.LabelValue `json:"description"`
		Runbook     model.LabelValue `json:"runbook"`
		Labels      model.LabelSet   `json:"labels"`
		Payload     model.LabelSet   `json:"payload"`
	}{}
	if err := receive(r, &legacyAlerts); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var alerts []*types.Alert
	for _, la := range legacyAlerts {
		a := &types.Alert{
			Alert: model.Alert{
				Labels:      la.Labels,
				Annotations: la.Payload,
			},
		}
		if a.Annotations == nil {
			a.Annotations = model.LabelSet{}
		}
		a.Annotations["summary"] = la.Summary
		a.Annotations["description"] = la.Description
		a.Annotations["runbook"] = la.Runbook

		alerts = append(alerts, a)
	}

	api.insertAlerts(w, r, alerts...)
}

func (api *API) addAlerts(w http.ResponseWriter, r *http.Request) {
	var alerts []*types.Alert
	if err := receive(r, &alerts); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	api.insertAlerts(w, r, alerts...)
}

func (api *API) insertAlerts(w http.ResponseWriter, r *http.Request, alerts ...*types.Alert) {
	now := time.Now()

	for _, alert := range alerts {
		alert.UpdatedAt = now

		// Ensure StartsAt is set.
		if alert.StartsAt.IsZero() {
			alert.StartsAt = now
		}
		// If no end time is defined, set a timeout after which an alert
		// is marked resolved if it is not updated.
		if alert.EndsAt.IsZero() {
			alert.Timeout = true
			alert.EndsAt = now.Add(api.resolveTimeout)

			numReceivedAlerts.WithLabelValues("firing").Inc()
		} else {
			numReceivedAlerts.WithLabelValues("resolved").Inc()
		}
	}

	// Make a best effort to insert all alerts that are valid.
	var (
		validAlerts    = make([]*types.Alert, 0, len(alerts))
		validationErrs = &types.MultiError{}
	)
	for _, a := range alerts {
		if err := a.Validate(); err != nil {
			validationErrs.Add(err)
			numInvalidAlerts.Inc()
			continue
		}
		validAlerts = append(validAlerts, a)
	}
	if err := api.alerts.Put(validAlerts...); err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	if validationErrs.Len() > 0 {
		respondError(w, apiError{
			typ: errorBadData,
			err: validationErrs,
		}, nil)
		return
	}

	respond(w, nil)
}

func (api *API) setSilence(w http.ResponseWriter, r *http.Request) {
	var sil types.Silence
	if err := receive(r, &sil); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	psil, err := silenceToProto(&sil)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sid, err := api.silences.Set(psil)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	respond(w, struct {
		SilenceID string `json:"silenceId"`
	}{
		SilenceID: sid,
	})
}

func (api *API) getSilence(w http.ResponseWriter, r *http.Request) {
	sid := route.Param(r.Context(), "sid")

	sils, err := api.silences.Query(silence.QIDs(sid))
	if err != nil || len(sils) == 0 {
		http.Error(w, fmt.Sprint("Error getting silence: ", err), http.StatusNotFound)
		return
	}
	sil, err := silenceFromProto(sils[0])
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	respond(w, sil)
}

func (api *API) listAlarms(w http.ResponseWriter, r *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()
	var rs alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	defer file.Close()
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		if err != nil || io.EOF == err {
			break
		}
		switch {
		case strings.Contains(line, "ALERT"):
			al.AlertName = strings.Split(line, " ")[1]
		case strings.Contains(line, "IF"):
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1], " ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity: strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			fmt.Printf("Alert list %#v", al)
			rs.Array = append(rs.Array, al)

		}
	}
	respond(w, &rs)
}

func (api *API) addAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	var rs alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	var result AlertJsonStruct
	fmt.Printf("request body", r.Body)
	if err := receive(r, &result); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	fmt.Printf("add alarm %#v", result)
	for {
		line, err := rd.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		if err != nil || io.EOF == err {
			break
		}
		switch {
		case strings.Contains(line, "ALERT"):
			al.AlertName = strings.Split(line, " ")[1]
			if result.AlertName == al.AlertName {
				respondError(w, apiError{
					typ: errorBadData,
					err: fmt.Errorf("%s conflict", result.AlertName),
				}, nil)
			}

		case strings.Contains(line, "IF"):
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1], " ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity: strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			fmt.Printf("Alert list %#v\n", al)
			rs.Array = append(rs.Array, al)

		}
	}
	rs.Array = append(rs.Array, result)

	file.Close()
	// write into alert.rules
	tmpl, err := template.New("alert").Parse(templ)
	if err != nil {
		panic(err)
	}
	filew, err := os.Create("/etc/alertmanager/alert.rules")
	err = tmpl.Execute(filew, rs)
	if err != nil {
		panic(err)
	}
	filew.Close()

	//reload promethues
	//w.Header().Set("My-Awesome-Header", "Rocks")

	client := &http.Client{}
	req, err := http.NewRequest("POST", "http://127.0.0.1:9090/-/reload", nil)
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	//respond(w, res)
	fmt.Printf("reload config %#v", res)
	return

}
func (api *API) editAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	var rs alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	alertName := route.Param(r.Context(), "alarmname")

	var result AlertJsonStruct
	if err := receive(r, &result); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	fmt.Printf("add alarm %#v", result)
	for {
		line, err := rd.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		if err != nil || io.EOF == err {
			break
		}
		switch {
		case strings.Contains(line, "ALERT"):
			al.AlertName = strings.Split(line, " ")[1]
			if alertName == al.AlertName && result.AlertName != alertName {
				respondError(w, apiError{
					typ: errorBadData,
					err: fmt.Errorf("%s must not be edited", result.AlertName),
				}, nil)
			} else if alertName == al.AlertName && result.AlertName == alertName {
				break
			}
		case strings.Contains(line, "IF"):
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1], " ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity: strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]

			if alertName == al.AlertName {
				rs.Array = append(rs.Array, result)
			} else {
				rs.Array = append(rs.Array, al)
			}
			fmt.Printf("Alert list %#v\n", al)

		}
	}

	file.Close()
	// write into alert.rules
	tmpl, err := template.New("alert").Parse(templ)
	if err != nil {
		panic(err)
	}
	filew, err := os.Create("/etc/alertmanager/alert.rules")
	err = tmpl.Execute(filew, rs)
	if err != nil {
		panic(err)
	}
	filew.Close()

	//reload promethues
	//w.Header().Set("My-Awesome-Header", "Rocks")
	client := &http.Client{}
	req, err := http.NewRequest("POST", "http://127.0.0.1:9090/-/reload", nil)
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	//respond(w, res)
	fmt.Printf("reload config %#v", res)
	return

}

func (api *API) delAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	var rs alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	result := route.Param(r.Context(), "alarmname")

	for {
		line, err := rd.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		if err != nil || io.EOF == err {
			break
		}
		switch {
		case strings.Contains(line, "ALERT"):
			al.AlertName = strings.Split(line, " ")[1]
		case strings.Contains(line, "IF"):
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1], " ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity: strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			if result == al.AlertName {
				fmt.Printf("alarmname %s", result)
				break
			} else {
				rs.Array = append(rs.Array, al)
			}
		}
	}
	// write into alert.rules
	tmpl, err := template.New("alert").Parse(templ)
	if err != nil {
		panic(err)
	}
	filew, err := os.Create("/etc/alertmanager/alert.rules")
	err = tmpl.Execute(filew, rs)
	if err != nil {
		panic(err)

	}
	filew.Close()

	//reload promethues
	//w.Header().Set("My-Awesome-Header", "Rocks")
	client := &http.Client{}
	req, err := http.NewRequest("POST", "http://127.0.0.1:9090/-/reload", nil)
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	fmt.Printf("reload config %#v", res)

	//respond(w, res)
	return
}

func checkErr(w http.ResponseWriter, err error) {
	if err != nil {
		fmt.Printf("found err %s", err)
		return
	}
}

func (api *API) listModals(w http.ResponseWriter, r *http.Request) {

	username := route.Param(r.Context(), "username")
	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS userinfo(Uid INTEGER PRIMARY KEY AUTOINCREMENT,Uname VARCHAR(64) NOT NULL,Mname VARCHAR(64) NOT NULL,Cpus FLOAT NOT NULL DEFAULT 0,Mem FLOAT NOT NULL DEFAULT 0,Disk FLOAT NOT NULL DEFAULT 0,Instance FLOAT NOT NULL DEFAULT 0)")
	sqlStr := fmt.Sprintf("SELECT * FROM userinfo where Uname=%q", username)
	rows, err := db.Query(sqlStr)
	defer rows.Close()
	checkErr(w, err)
	var result []UserModal
	for rows.Next() {
		var user UserModal

		err = rows.Scan(&user.Uid, &user.Uname, &user.Mname, &user.Cpus, &user.Mem, &user.Disk, &user.Instance)
		checkErr(w, err)
		result = append(result, user)
	}

	respond(w, &result)
}

func (api *API) addModal(w http.ResponseWriter, r *http.Request) {

	username := route.Param(r.Context(), "username")

	var user UserModal
	if err := receive(r, &user); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	checkErr(w, err)
	stmt, err := db.Prepare("INSERT INTO userinfo(Uname,Mname, Cpus, Mem, Disk, Instance) values(?,?,?,?,?,?)")
	checkErr(w, err)

	res, err := stmt.Exec(username, user.Mname, user.Cpus, user.Mem, user.Disk, user.Instance)
	checkErr(w, err)

	respond(w, res)
}

func (api *API) updateModal(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	modalId := route.Param(r.Context(), "modalid")
	var user UserModal
	if err := receive(r, &user); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()

	checkErr(w, err)
	stmt, err := db.Prepare("update userinfo set Mname=?,Cpus=?, Mem=?, Disk=?, Instance=? where Uid=?")
	checkErr(w, err)

	res, err := stmt.Exec(user.Mname, user.Cpus, user.Mem, user.Disk, user.Instance, modalId)
	checkErr(w, err)

	affect, err := res.RowsAffected()
	checkErr(w, err)

	respond(w, affect)

}

func (api *API) deleteModal(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	modalId := route.Param(r.Context(), "modalid")

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()

	checkErr(w, err)
	stmt, err := db.Prepare("delete from userinfo where Uid=?")
	checkErr(w, err)

	res, err := stmt.Exec(modalId)
	checkErr(w, err)

	respond(w, res)

}

func GetRandomString(leng int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < leng; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func (api *API) delSilence(w http.ResponseWriter, r *http.Request) {
	sid := route.Param(r.Context(), "sid")

	if err := api.silences.Expire(sid); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	respond(w, nil)
}

func (api *API) listSilences(w http.ResponseWriter, r *http.Request) {
	psils, err := api.silences.Query()
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	matchers := []*labels.Matcher{}
	if filter := r.FormValue("filter"); filter != "" {
		matchers, err = parse.Matchers(filter)
		if err != nil {
			respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return
		}
	}

	sils := []*types.Silence{}
	for _, ps := range psils {
		s, err := silenceFromProto(ps)
		if err != nil {
			respondError(w, apiError{
				typ: errorInternal,
				err: err,
			}, nil)
			return
		}

		if !matchesFilterLabels(s, matchers) {
			continue
		}
		sils = append(sils, s)
	}

	var active, pending, expired, silences []*types.Silence

	for _, s := range sils {
		switch s.Status.State {
		case "active":
			active = append(active, s)
		case "pending":
			pending = append(pending, s)
		case "expired":
			expired = append(expired, s)
		}
	}

	sort.Slice(active, func(i int, j int) bool {
		return active[i].EndsAt.Before(active[j].EndsAt)
	})
	sort.Slice(pending, func(i int, j int) bool {
		return pending[i].StartsAt.Before(pending[j].EndsAt)
	})
	sort.Slice(expired, func(i int, j int) bool {
		return expired[i].EndsAt.After(expired[j].EndsAt)
	})

	silences = append(silences, active...)
	silences = append(silences, pending...)
	silences = append(silences, expired...)

	respond(w, silences)
}

func matchesFilterLabels(s *types.Silence, matchers []*labels.Matcher) bool {
	sms := map[string]string{}
	for _, m := range s.Matchers {
		sms[m.Name] = m.Value
	}
	for _, m := range matchers {
		if v, prs := sms[m.Name]; !prs || !m.Matches(v) {
			return false
		}
	}

	return true
}

func silenceToProto(s *types.Silence) (*silencepb.Silence, error) {
	sil := &silencepb.Silence{
		Id:        s.ID,
		StartsAt:  s.StartsAt,
		EndsAt:    s.EndsAt,
		UpdatedAt: s.UpdatedAt,
		Comment:   s.Comment,
		CreatedBy: s.CreatedBy,
	}
	for _, m := range s.Matchers {
		matcher := &silencepb.Matcher{
			Name:    m.Name,
			Pattern: m.Value,
			Type:    silencepb.Matcher_EQUAL,
		}
		if m.IsRegex {
			matcher.Type = silencepb.Matcher_REGEXP
		}
		sil.Matchers = append(sil.Matchers, matcher)
	}
	return sil, nil
}

func silenceFromProto(s *silencepb.Silence) (*types.Silence, error) {
	sil := &types.Silence{
		ID:        s.Id,
		StartsAt:  s.StartsAt,
		EndsAt:    s.EndsAt,
		UpdatedAt: s.UpdatedAt,
		Status: types.SilenceStatus{
			State: types.CalcSilenceState(s.StartsAt, s.EndsAt),
		},
		Comment:   s.Comment,
		CreatedBy: s.CreatedBy,
	}
	for _, m := range s.Matchers {
		matcher := &types.Matcher{
			Name:  m.Name,
			Value: m.Pattern,
		}
		switch m.Type {
		case silencepb.Matcher_EQUAL:
		case silencepb.Matcher_REGEXP:
			matcher.IsRegex = true
		default:
			return nil, fmt.Errorf("unknown matcher type")
		}
		sil.Matchers = append(sil.Matchers, matcher)
	}

	return sil, nil
}

type status string

const (
	statusSuccess status = "success"
	statusError          = "error"
)

type response struct {
	Status    status      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func respond(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	b, err := json.Marshal(&response{
		Status: statusSuccess,
		Data:   data,
	})
	if err != nil {
		log.Errorf("errorr: %v", err)
		return
	}
	w.Write(b)
}

func respondError(w http.ResponseWriter, apiErr apiError, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	switch apiErr.typ {
	case errorBadData:
		w.WriteHeader(http.StatusBadRequest)
	case errorInternal:
		w.WriteHeader(http.StatusInternalServerError)
	default:
		panic(fmt.Sprintf("unknown error type %q", apiErr))
	}

	b, err := json.Marshal(&response{
		Status:    statusError,
		ErrorType: apiErr.typ,
		Error:     apiErr.err.Error(),
		Data:      data,
	})
	if err != nil {
		return
	}
	log.Errorf("api error: %v", apiErr.Error())

	w.Write(b)
}

func receive(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	defer r.Body.Close()

	err := dec.Decode(v)
	if err != nil {
		log.Debugf("Decoding request failed: %v", err)
	}
	return err
}

// bomc
func (api *API) listBomcs(w http.ResponseWriter, r *http.Request) {

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS bomc(Bid INTEGER PRIMARY KEY AUTOINCREMENT,bomcID VARCHAR(50) NOT NULL,description VARCHAR(128) NOT NULL)")
	sqlStr := fmt.Sprintf("SELECT bomcID, description FROM bomc ")
	rows, err := db.Query(sqlStr)
	defer rows.Close()
	checkErr(w, err)
	var result []Bomc
	for rows.Next() {
		var user Bomc

		err = rows.Scan(&user.BomcID, &user.Description)
		checkErr(w, err)
		result = append(result, user)
	}

	respond(w, &result)
}

func (api *API) addBomcs(w http.ResponseWriter, r *http.Request) {

	var users []Bomc
	if err := receive(r, &users); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	checkErr(w, err)
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS bomc(Bid INTEGER PRIMARY KEY AUTOINCREMENT,bomcID VARCHAR(50) NOT NULL,description VARCHAR(128) NOT NULL)")
	for _, user := range users {
		stmt, err := db.Prepare("INSERT INTO bomc(bomcID,description) values(?,?)")
		checkErr(w, err)
		_, err = stmt.Exec(user.BomcID, user.Description)
		checkErr(w, err)
	}

	respond(w, nil)
}

func (api *API) updateBomc(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	bomcID := route.Param(r.Context(), "bomcID")
	var user Bomc
	if err := receive(r, &user); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()

	checkErr(w, err)
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS bomc(Bid INTEGER PRIMARY KEY AUTOINCREMENT,bomcID VARCHAR(50) NOT NULL,description VARCHAR(128) NOT NULL)")

	stmt, err := db.Prepare("update bomc set description=? where bomcID=?")
	checkErr(w, err)

	res, err := stmt.Exec(user.Description, bomcID)
	checkErr(w, err)

	affect, err := res.RowsAffected()
	checkErr(w, err)

	respond(w, affect)

}

func (api *API) deleteBomc(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	bomcID := route.Param(r.Context(), "bomcID")

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS bomc(Bid INTEGER PRIMARY KEY AUTOINCREMENT,bomcID VARCHAR(50) NOT NULL,description VARCHAR(128) NOT NULL)")

	checkErr(w, err)
	stmt, err := db.Prepare("delete from bomc where bomcID=?")
	checkErr(w, err)

	res, err := stmt.Exec(bomcID)
	checkErr(w, err)

	respond(w, res)

}
