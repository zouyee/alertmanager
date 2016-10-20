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
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
	"encoding/xml"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/prometheus/common/version"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"

	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/types"
	"os"
	"bufio"
	"strings"
	"io"
	"io/ioutil"
	"text/template"
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"

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
	silences       provider.Silences
	config         string
	resolveTimeout time.Duration
	uptime         time.Time

	groups func() dispatch.AlertOverview

	// context is an indirection for testing.
	context func(r *http.Request) context.Context
	mtx     sync.RWMutex
}

// New returns a new API.
func New(alerts provider.Alerts, silences provider.Silences, gf func() dispatch.AlertOverview) *API {
	return &API{
		context:  route.Context,
		alerts:   alerts,
		silences: silences,
		groups:   gf,
		uptime:   time.Now(),
	}
}

// alert struct

type Labels struct {
	AlertSeverity	string `json:"severity"`
}
type AlertJsonStruct struct {
	AlertName	string `json:"alert"`
	AlertAddition	string   `json:"if"`
	AlertTime	string	`json:"for"`
	AlertSeverity	Labels	`json:"labels"`
	AlertDescription	string `json:"annotations"`
}


type alertsResponseJSONStruct struct {
	Array []AlertJsonStruct	`json:"alerts"`
}

type AlertInfo struct {
	Status string `json:"status"`
	Labels Label `json:"labels"`
	Annotations Annotation `json:"annotations"`
	StartsAt string `json:"startsAt"`
	EndsAt string `json:"endsAt"`
	GeneratorURL string `json:"generatorURL"`

}
type Annotation struct{
	Description string `json:"description"`
	Summary string `json:"summary"`
}
type Label struct{
	AlertName string `json:"alertname，omitempty"`
	Group string `json:"group，omitempty"`
	Instance string `json:"instance，omitempty"`
	Job string `json:"job，omitempty"`
	Monitor string `json:"monitor，omitempty"`
	Severity string `json:"severity，omitempty"`
}
type GroupLabel struct {
	AlertName string `json:"alertname，omitempty"`
}

type AlarmJsonStruct struct{
	Receiver string `json:"-"`
	Status string `json:"-"`
	Alerts []AlertInfo `json:"alerts"`
	GroupLabels GroupLabel `json:"groupLabels"`
	CommonLabels Label `json:"commonLabels"`
	ExternalURL string `json:"externalURL"`
	Version string `json:"version"`
	GroupKey uint64 `json:"groupKey"`

}

type Member struct{
	Source string `xml:"source,attr"`
	Code string `xml:"code,attr"`
	Grade string `xml:"grade,attr"`
	Time string `xml:"time,attr"`
	CaseId string `xml:"caseid,attr"`
	Description string `xml:",chardata"`

}

type Struct struct{
	Name string `xml:"dn,attr"`
	Members Member `xml:"alarm"`
}

type Result struct{
	XMLName xml.Name `xml:"dc"`
	Structs []Struct `xml:"mo"`
}

type UserModal struct{
	Uid int `json:"uid"`
	Uname string `json:"uname"`
	Mname string `json:"mname"`
	Cpus float64 `json:"cpus"`
	Mem float64 `json:"mem"`
	Disk float64 `json:"disk"`
	Instance float64 `json:"instances"`
}
type ModalResponseJSONStruct struct {
	Array []UserModal	`json:"modals"`
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

const Header = `<?xml version="1.0" encoding="gb2312"?>` + "\n"
// Register registers the API handlers under their correct routes
// in the given router.
func (api *API) Register(r *route.Router) {
	ihf := prometheus.InstrumentHandlerFunc

	// Register legacy forwarder for alert pushing.
	r.Post("/alerts", ihf("legacy_add_alerts", api.legacyAddAlerts))

	// Register actual API.
	r = r.WithPrefix("/v1")

	// alerts api
	r.Get("/status", ihf("status", api.status))
	r.Get("/alerts/groups", ihf("alert_groups", api.alertGroups))
	r.Get("/alerts", ihf("list_alerts", api.listAlerts))
	r.Post("/alerts", ihf("add_alerts", api.addAlerts))

	// silences config api and crud
	r.Get("/silences", ihf("list_silences", api.listSilences))
	r.Post("/silences", ihf("add_silence", api.addSilence))
	r.Get("/silence/:sid", ihf("get_silence", api.getSilence))
	r.Del("/silence/:sid", ihf("del_silence", api.delSilence))
	// alarms crud api
	r.Get("/alarms", ihf("list_alarms", api.listAlarms))
	r.Post("/alarms", ihf("add_alarm", api.addAlarm))
	r.Post("/alarms/:alarmname", ihf("edit_alarm", api.editAlarm))
	r.Del("/alarms/:alarmname", ihf("del_alarm", api.delAlarm))
	// alarms event reciver
	r.Post("/monitor", ihf("monitor", api.monitor))
	//proxy
	r.Get("/proxy/:address",ihf("proxy",api.proxy))
	// modal crub
	r.Get("/modals/:username",ihf("list_modals",api.listModals))
	r.Post("/modals/:username",ihf("add_modal",api.addModal))
	r.Put("/modals/:modalid",ihf("update_modal",api.updateModal))
	r.Del("/modals/:modalid",ihf("delete_modal",api.deleteModal))
}

// Update sets the configuration string to a new value.
func (api *API) Update(config string, resolveTimeout time.Duration) {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	api.config = config
	api.resolveTimeout = resolveTimeout
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

func (api *API) status(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()

	var status = struct {
		Config      string            `json:"config"`
		VersionInfo map[string]string `json:"versionInfo"`
		Uptime      time.Time         `json:"uptime"`
	}{
		Config: api.config,
		VersionInfo: map[string]string{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"buildUser": version.BuildUser,
			"buildDate": version.BuildDate,
			"goVersion": version.GoVersion,
		},
		Uptime: api.uptime,
	}

	api.mtx.RUnlock()

	respond(w, status)
}

func (api *API) alertGroups(w http.ResponseWriter, req *http.Request) {
	respond(w, api.groups())
}

func (api *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := api.alerts.GetPending()
	defer alerts.Close()

	var (
		err error
		res []*types.Alert
	)
	// TODO(fabxc): enforce a sensible timeout.
	for a := range alerts.Next() {
		if err = alerts.Err(); err != nil {
			break
		}
		res = append(res, a)
	}

	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, types.Alerts(res...))
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

func (api *API) addSilence(w http.ResponseWriter, r *http.Request) {
	var sil types.Silence
	if err := receive(r, &sil); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	if err := sil.Init(); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sid, err := api.silences.Set(&sil)
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	respond(w, struct {
		SilenceID uuid.UUID `json:"silenceId"`
	}{
		SilenceID: sid,
	})
}

func (api *API) getSilence(w http.ResponseWriter, r *http.Request) {
	sids := route.Param(api.context(r), "sid")
	sid, err := uuid.FromString(sids)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sil, err := api.silences.Get(sid)
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting silence: ", err), http.StatusNotFound)
		return
	}

	respond(w, &sil)
}
func (api *API) listAlarms(w http.ResponseWriter, r *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()
	var rs  alertsResponseJSONStruct
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
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1]," ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity:strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			fmt.Printf("Alert list %#v",al)
			rs.Array = append(rs.Array, al)

		}
	}
	respond(w, &rs)
}

func (api *API) addAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	var rs  alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	var result AlertJsonStruct
	fmt.Printf("request body",r.Body)
	if err := receive(r, &result); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	fmt.Printf("add alarm %#v",result)
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
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1]," ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity:strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			fmt.Printf("Alert list %#v\n",al)
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
	res,err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	//respond(w, res)
	fmt.Printf("reload config %#v",res)
	return




}
func (api *API) editAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	var rs  alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	alertName := route.Param(api.context(r), "alarmname")

	var result AlertJsonStruct
	if err := receive(r, &result); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	fmt.Printf("add alarm %#v",result)
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
			}else if alertName == al.AlertName && result.AlertName == alertName{
				break
			}
		case strings.Contains(line, "IF"):
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1]," ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity:strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]

			if alertName == al.AlertName {
				rs.Array = append(rs.Array, result)
			}else{
				rs.Array = append(rs.Array, al)
			}
			fmt.Printf("Alert list %#v\n",al)

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
	res,err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	//respond(w, res)
	fmt.Printf("reload config %#v",res)
	return


}

func (api *API) delAlarm(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	var rs  alertsResponseJSONStruct
	var al AlertJsonStruct
	file, err := os.Open("/etc/alertmanager/alert.rules")
	if err != nil {
		http.Error(w, fmt.Sprint("Error getting alarms: ", err), http.StatusNotFound)
		return
	}
	rd := bufio.NewReader(file)
	result := route.Param(api.context(r), "alarmname")

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
			al.AlertAddition = strings.Trim(strings.Split(line, "IF")[1]," ")
		case strings.Contains(line, "FOR"):
			al.AlertTime = strings.Split(line, " ")[1]
		case strings.Contains(line, "LABELS"):
			al.AlertSeverity = Labels{AlertSeverity:strings.Split(line, "'")[1]}
		case strings.Contains(line, "summary"):
			al.AlertDescription = strings.Split(line, "'")[1]
			if result == al.AlertName {
				fmt.Printf("alarmname %s",result)
				break
			}else{
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
	res,err := client.Do(req)
	if err != nil {
		fmt.Printf("post reload error %# v", err)
	}
	fmt.Printf("reload config %#v",res)

	//respond(w, res)
	return
}

func (api *API) proxy(w http.ResponseWriter, r *http.Request) {
	url := "http://" + route.Param(api.context(r), "address") + ":9090/haproxy?stats;csv"
	req, err := http.NewRequest("GET",url, nil)
	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		panic(err)
	}
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil && err != io.EOF {
		panic(err)
	}
	w.Write(result)
}

func checkErr(w http.ResponseWriter, err error) {
	if err != nil {
		fmt.Printf("found err %s", err)
		return
	}
}

func (api *API) listModals(w http.ResponseWriter, r *http.Request) {

	username := route.Param(api.context(r), "username")
	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS userinfo(Uid INTEGER PRIMARY KEY AUTOINCREMENT,Uname VARCHAR(64) NOT NULL,Mname VARCHAR(64) NOT NULL,Cpus FLOAT NOT NULL DEFAULT 0,Mem FLOAT NOT NULL DEFAULT 0,Disk FLOAT NOT NULL DEFAULT 0,Instance FLOAT NOT NULL DEFAULT 0)")
	sqlStr := fmt.Sprintf("SELECT * FROM userinfo where Uname=%q",username)
	rows, err := db.Query(sqlStr)
	defer rows.Close()
	checkErr(w, err)
	var result []UserModal
	for rows.Next() {
		var user UserModal

		err = rows.Scan(&user.Uid,&user.Uname,&user.Mname,&user.Cpus,&user.Mem,&user.Disk,&user.Instance)
		checkErr(w, err)
		result = append(result, user)
	}

	respond(w, &result)
}

func (api *API) addModal(w http.ResponseWriter, r *http.Request) {

	username := route.Param(api.context(r), "username")


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

	res, err := stmt.Exec(username, user.Mname, user.Cpus, user.Mem, user.Disk,user.Instance)
	checkErr(w, err)

	respond(w, res)
}

func (api *API) updateModal(w http.ResponseWriter, r *http.Request) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	modalId := route.Param(api.context(r), "modalid")
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
	modalId := route.Param(api.context(r), "modalid")

	db, err := sql.Open("sqlite3", "./modal.db")
	defer db.Close()

	checkErr(w, err)
	stmt, err := db.Prepare("delete from userinfo where Uid=?")
	checkErr(w, err)

	res, err := stmt.Exec(modalId)
	checkErr(w, err)

	respond(w, res)

}

func GetRandomString(leng int) string{
   str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
   bytes := []byte(str)
   result := []byte{}
   r := rand.New(rand.NewSource(time.Now().UnixNano()))
   for i := 0; i < leng; i++ {
      result = append(result, bytes[r.Intn(len(bytes))])
   }
   return string(result)
}
// monitor:convert post json to xml
func (api *API) monitor(w http.ResponseWriter, r *http.Request) {
	var s AlarmJsonStruct
	var m Result
	var st Struct
	grade := map[string]string{
		"critical": "4",
		"major": "3",
		"minor": "2",
		"warning": "1",
	}
	//fmt.Printf("json post reciver %s", r)
	if err := receive(r, &s); err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	for i:=0; i< len(s.Alerts);i++{
		//fmt.Printf("%#v", s.Alerts[i].Labels)
		caseId := s.Alerts[i].Labels.AlertName + s.Alerts[i].Labels.Instance

		startAt, err := time.Parse(time.RFC3339Nano,s.Alerts[i].StartsAt)
		if err != nil {
			panic(err)
		}
		fmt.Printf("s.Alerts[i].Labels.Group :%#v,len:%#v\n",s.Alerts[i].Labels.Group,len(s.Alerts[i].Labels.Group))
		fmt.Printf("s description :%#v",strings.Split(s.Alerts[i].Annotations.Description,":"))
		if(strings.Split(s.Alerts[i].Annotations.Description,":")[1] == "node"){
			st.Name = s.Alerts[i].Labels.Group
			st.Members = Member{Source:s.Alerts[i].Labels.Instance,Code:s.Alerts[i].Labels.AlertName,Grade:grade[s.Alerts[i].Labels.Severity],Time:startAt.Format("2006-01-02 15:04:05"),CaseId:GetMd5String(caseId),Description: s.Alerts[i].Annotations.Description}
		}else{
			st.Name = strings.Split(s.Alerts[i].Annotations.Description,":")[1]
			st.Members = Member{Source:strings.Split(s.Alerts[i].Annotations.Description,":")[7],Code:s.Alerts[i].Labels.AlertName,Grade:grade[s.Alerts[i].Labels.Severity],Time:startAt.Format("2006-01-02 15:04:05"),CaseId:GetMd5String(caseId),Description: s.Alerts[i].Annotations.Description}
		}


		m.Structs = append(m.Structs, st)
	}
	//fmt.Printf("%#v", m)
	output, err := xml.MarshalIndent(m, " "," ")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	file, err := os.Create("/home/prometheus/"+fmt.Sprintf("%d~%s",time.Now().Unix(),GetRandomString(28)) + "~stdxml.dat")
	file.Write([]byte(Header))
	file.Write(output)
	respond(w, "convert success")
}

func (api *API) delSilence(w http.ResponseWriter, r *http.Request) {
	sids := route.Param(api.context(r), "sid")
	sid, err := uuid.FromString(sids)
	if err != nil {
		respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	if err := api.silences.Del(sid); err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, nil)
}

func (api *API) listSilences(w http.ResponseWriter, r *http.Request) {
	sils, err := api.silences.All()
	if err != nil {
		respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	respond(w, sils)
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
	log.Errorf("api error: %s", apiErr)

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
