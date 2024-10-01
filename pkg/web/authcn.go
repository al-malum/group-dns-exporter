package web

import (
	"encoding/json"
	"log"
	"main/pkg/contain"
	"net/http"
)

type MtlsSettings struct {
	Enabled   bool     `json:"enabled"`
	Key       string   `json:"key"`
	Cert      string   `json:"cert"`
	AllowedCN []string `json:"allowedCN"`
}

func AuthenticationCN(next http.Handler, mtlsSetting MtlsSettings) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			var commonName = r.TLS.VerifiedChains[0][0].Subject.CommonName // Получаем CN
			if contain.ContainString(mtlsSetting.AllowedCN, commonName) {  // если CN прописал в конфиге - ОК
				log.Printf("Authentification successful. CN: %s, Remote address: %s", commonName, r.RemoteAddr)
				next.ServeHTTP(w, r) // если все ок - передаем запрос следующему обработчику
			} else if len(mtlsSetting.AllowedCN) == 0 || !mtlsSetting.Enabled {
				log.Printf("Mtls disable. Request without mtls successful. Remote address: %s", r.RemoteAddr)
				next.ServeHTTP(w, r)
			} else { // если CN не прописан в конфиге - возвращаем ошибку
				log.Printf("Authentification failed - incorrect CN: %s, Remote address: %s", commonName, r.RemoteAddr)
				w.WriteHeader(http.StatusForbidden)
				w.Header().Set("Content-Type", "application/json")
				response := make(map[string]string)
				response["message"] = "Incorrect CN of the certificate"
				jsonResponse, _ := json.Marshal(response)
				w.Write(jsonResponse)
			}
		} else {
			log.Printf("Mtls disable. Request without mtls successful. Remote address: %s", r.RemoteAddr)
			next.ServeHTTP(w, r)
		}
	})
}
