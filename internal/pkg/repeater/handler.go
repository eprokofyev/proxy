package repeater

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"proxy/internal/pkg/database"
	"strconv"
)

type Handler struct {
	db *database.DB
}

func NewHandler(db *database.DB) *Handler {
	return &Handler {
		db,
	}
}

func (h *Handler) GetRequests(w http.ResponseWriter, r *http.Request) {
	req, err := h.db.Select()
	if err != nil {
		log.Println("here", err)
		return
	}

	outStr := ""
	strSeparator := "\n*******************************************************************\n"
	for _, element := range req {
		vulnerability := ""
		for _, item := range element.Vulnerabilities {
			vulnerability += item + "\n"
		}
		outStr += "Id: " + strconv.Itoa(element.Id) + " ## Host: " + element.Host + " ## Scheme: " + element.Scheme + "\n"
		if len(vulnerability) > 0 {
			outStr += "## Vulnerability: " + vulnerability
		}

		outStr += element.Req + strSeparator
	}

	fmt.Fprint(w, outStr)
}


func (h *Handler) SendRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	id, errGetInt := strconv.Atoi(idStr)
	if errGetInt != nil {
		panic("need use integer id!")
	}

	req, err := h.db.Find(id)
	if err != nil {
		log.Println("here", err)
		return
	}

	request, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(req.Req)))
	if err != nil {
		return
	}
	request.URL.Scheme = req.Scheme
	request.URL.Host = req.Host

	strResp := ""
	b := bytes.NewBuffer([] byte{})
	response, err := http.DefaultTransport.RoundTrip(request)
	if err == nil {
		response.Write(b)
		strResp = string(b.Bytes())
		defer response.Body.Close()
	} else {
		log.Println(err)
	}

	response.Write(b)
	outStr := ""
	strSeparator := "\n*******************************************************************\n"
	outStr += "Id:" + strconv.Itoa(req.Id) + "  ## Host:" + req.Host + "  ## " + "Url Scheme:" + req.Scheme + "  " + req.Req + strSeparator + strResp
	fmt.Fprint(w, outStr)
}
