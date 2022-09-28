package yzjapidecryption_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	yzjdecryption "github.com/cnmaple/yzjapidecryption"
)

func TestDecodeBody(t *testing.T) {
	bodyStr := "xUCqrAxA/cxr0oXA7AyrCmRUs1890qjZgjDiAak/a5n2Lhq1bDLipgEpiKME66uwUHoyDzadAwo9jgJeG/D0IfmYytnyig/LFYNKPaF+szhfAQnQzJufKT3Q8kRpbu9vaHra+mmzcjtyIfwkMPpZEelzSAGDtbkEfv131ZTYgXhQEKqRwP9YYGYxObecPp7uGBNPabpTPCSuFR4AAKaXotZoMFTcD4jQzrsM1C0xSfxdbBEc+jkXOaIHtfdlvmLAHAElq2PzXRFZIlBD1gZf3wV7Uhe3egxeG5MvP4C/A57c2oN6AfACakFXun2sLN+v8wsK2OOt71EJPn29VGGk67322IkvJALrRQLjFreEDuugTwJFSIwmxNHVLzoTp6/ZCveseCO/5k6xW8sOftTxdu2Y/ev3SLgaDxpNim/z94Du3uARpCd6bYAlZL7TKIOm870J0iFL3bx9Zj2XWdiRIttGakhxjOf7oR6cNwPNfahdX4v/J6Pb+RVYOt2q+lq7DDr6t8cSPNWdLe9zTGy+CunnKG8hbPDwXyhS++senoR7NVYAvT/EmsMtnES6ZL9rZv0VsHCmMF+JYbq1fLOr39NSDta20OB5ZCmOxJHHuquacVEzmawC8yAU0cYhZ9H+pACgnIXn7AhY/ODB7IRkOW2Uu7DKPCpajMEH2MMFdVO+Ub2O6Qm49zRN7RsgbXIt6VHsGej/PADER9e+bEs8/JaHA1aRI09tlX3rJrYOzPi7tmRnn3y8Pc93grw0QMaeDzfyC/kMB3AYB1lYArCoIlwa/4Scw043UQcZLP/5298="
	key := "CnMapleComTest01"
	jsonStr, err := yzjdecryption.DecodeBody(bodyStr, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("decodeBody:", jsonStr)
}

func TestYzjDecryptionPlugin(t *testing.T) {
	cfg := yzjdecryption.CreateConfig()

	cfg.CloudFlowKey = "CnMapleComTest01"
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := yzjdecryption.New(ctx, next, cfg, "yzj-api-decryption-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	bodyStr := "xUCqrAxA/cxr0oXA7AyrCmRUs1890qjZgjDiAak/a5n2Lhq1bDLipgEpiKME66uwUHoyDzadAwo9jgJeG/D0IfmYytnyig/LFYNKPaF+szhfAQnQzJufKT3Q8kRpbu9vaHra+mmzcjtyIfwkMPpZEelzSAGDtbkEfv131ZTYgXhQEKqRwP9YYGYxObecPp7uGBNPabpTPCSuFR4AAKaXotZoMFTcD4jQzrsM1C0xSfxdbBEc+jkXOaIHtfdlvmLAHAElq2PzXRFZIlBD1gZf3wV7Uhe3egxeG5MvP4C/A57c2oN6AfACakFXun2sLN+v8wsK2OOt71EJPn29VGGk67322IkvJALrRQLjFreEDuugTwJFSIwmxNHVLzoTp6/ZCveseCO/5k6xW8sOftTxdu2Y/ev3SLgaDxpNim/z94Du3uARpCd6bYAlZL7TKIOm870J0iFL3bx9Zj2XWdiRIttGakhxjOf7oR6cNwPNfahdX4v/J6Pb+RVYOt2q+lq7DDr6t8cSPNWdLe9zTGy+CunnKG8hbPDwXyhS++senoR7NVYAvT/EmsMtnES6ZL9rZv0VsHCmMF+JYbq1fLOr39NSDta20OB5ZCmOxJHHuquacVEzmawC8yAU0cYhZ9H+pACgnIXn7AhY/ODB7IRkOW2Uu7DKPCpajMEH2MMFdVO+Ub2O6Qm49zRN7RsgbXIt6VHsGej/PADER9e+bEs8/JaHA1aRI09tlX3rJrYOzPi7tmRnn3y8Pc93grw0QMaeDzfyC/kMB3AYB1lYArCoIlwa/4Scw043UQcZLP/5298="
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost", ioutil.NopCloser(strings.NewReader(bodyStr)))
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
	assertBody(t, req, "{\"data\":{\"formInfo\":{\"widgetMap\":{\"Ds_0\":{\"eid\":\"112345\",\"codeId\":\"Ds_0\",\"extendFieldMap\":{},\"deptSpecify\":[],\"deptTypeSetting\":\"allBusinessUnit\",\"title\":\"发起部门\",\"type\":\"departmentSelectWidget\",\"deptInfo\":[],\"selectCompanyOnly\":false,\"option\":\"single\"},\"_S_SERIAL\":{\"codeId\":\"_S_SERIAL\",\"title\":\"流水号\",\"type\":\"serialNumWidget\"},\"_S_DATE\":{\"codeId\":\"_S_DATE\",\"fromNowOn\":false,\"title\":\"申请日期\",\"type\":\"dateWidget\",\"value\":123},\"_S_APPLY\":{\"eid\":\"112345\",\"codeId\":\"_S_APPLY\",\"existEcosphere\":false,\"title\":\"提交人\",\"type\":\"personSelectWidget\"},\"success\":true,\"errorCode\":0}}}}")
}

func assertBody(t *testing.T, req *http.Request, expected string) {
	t.Helper()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		t.Errorf("read Body value: %s", err.Error())
	}
	decryption := req.Header.Get("decryption")
	if decryption == "true" {
		if string(body) != expected {
			t.Errorf("invalid Body value: %s  the expected:%s", string(body), expected)
		}
	} else {
		errorMsg := req.Header.Get("errorMsg")
		t.Errorf("decryption Body error,the decryption:%v,error message: %v ", decryption, errorMsg)
	}
}
