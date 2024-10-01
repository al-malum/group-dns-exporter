package pdns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func AuthenticationCN(next http.Handler, mtlsSetting MtlsExporter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			var commonName = r.TLS.VerifiedChains[0][0].Subject.CommonName // Получаем CN
			if ContainString(mtlsSetting.AllowedCN, commonName) {          // если CN прописал в конфиге - ОК
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

func RunServerWithTls(handler http.Handler, mtlsSetting MtlsExporter) error {
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := os.ReadFile(mtlsSetting.Cert)
	if err != nil {
		log.Printf("%s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":9100",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	serverErr := server.ListenAndServeTLS(mtlsSetting.Cert, mtlsSetting.Key)
	if serverErr != nil {
		return serverErr
	}
	return nil
}

func RunServerWithousTls(handler http.Handler) error {
	server := &http.Server{
		Addr:    ":9100",
		Handler: handler,
	}
	serverErr := server.ListenAndServe()
	if serverErr != nil {
		return serverErr
	}
	return nil
}
