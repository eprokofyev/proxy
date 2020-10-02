package analyzer

import (
	"fmt"
	"net/http"
	"strings"
)

func XSSCheck(r *http.Request) []string {
	result := make([]string, 0)
	err := r.ParseForm()
	if err != nil {
		return nil
	}

	str, ok := r.Header["Referer"]
	if ok {
		result = append(result, "Referer" + strings.Join(str, " "))
	}

	for k, v := range r.Form {
		fmt.Println("gffffffffffffffffff", k, v)
		str := strings.Join(v, " ")
		if strings.Contains(str, "\"><img src onerror=alert()>") {
			result = append(result, k + "=" + str)
		}
	}

	for k, v := range r.PostForm {
		fmt.Println(k, v)
		str := strings.Join(v, " ")
		if strings.Contains(str, "\"><img src onerror=alert()>") {
			result = append(result, k + "=" + str)
		}
	}

	return result
}
