package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// This is a cross-platform go tool to demonstrate the implementation of mTLS (Mutual TLS) and how useful it can help
// to setup authorization on top of TLS certificate - known as Certificate Bound Token. This program could be run into
// client or server mode through the mention of flag --client or --server respectivively. Only the server mode generates
// both Root/server and Client CA certificates. These are saved to fixed location on disk and deleted once server exits.

// Version  : 1.0
// Author   : Jerome AMON
// Created  : 06 September 2021

// in client mode defines the path as default
// location of the "certificates" folder.
var certsFolder string

// location of server and client CA certs.
const clientcertspath = "certificates/client/"
const servercertspath = "certificates/server/"

// fixed name of server and client CA certs.
const servercacerts = "server-ca.crt"
const clientcacerts = "client-ca.crt"

// client CA private key.
const clientcaprivkey = "client-ca.key"

// store server CA private key and certificate in PEM format.
var rootCAPEM *bytes.Buffer
var rootCAPrivKeyPEM *bytes.Buffer

// store client CA private key and certificate in PEM format.
var clientsCAPEM *bytes.Buffer
var clientsCAPrivKeyPEM *bytes.Buffer

var serverIP string
var serverPort string

// map console cleaning function based on OS type.
var clear map[string]func()

func init() {

	// enforce the usage of all available cores on the computer
	runtime.GOMAXPROCS(runtime.NumCPU())

	// initialize the map of functions
	clear = make(map[string]func())
	// add function tp clear linux-based console
	clear["linux"] = func() {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	// add function to clear windows-based console
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// clearConsole is a function that clears the console
// it exits the program if the OS is not supported.
func clearConsole() {
	if clearFunc, ok := clear[runtime.GOOS]; ok {
		clearFunc()
		fmt.Println()
	} else {
		fmt.Println(" Program aborted // failed to clear the console // platform unsupported")
		os.Exit(0)
	}
}

// makes sure that "certificates/client" and "certificates/server"
// directories are presents - if not then it will creates them.
func createCertsFolders() {

	info, err := os.Stat(clientcertspath)
	if !os.IsExist(err) {
		// path does not exist.
		err := os.MkdirAll(clientcertspath, 0755)
		if err != nil {
			log.Printf("failed create %q folder - errmsg : %v\n", clientcertspath, err)
			os.Exit(1)
		}
	} else {
		// path already exists but could be file or directory.
		if !info.IsDir() {
			log.Printf("path %q exists but it is not a folder so please check before continue - errmsg : %v\n", clientcertspath, err)
			os.Exit(0)
		}
	}

	// check and construct server related certificates folder.
	info, err = os.Stat(servercertspath)
	if !os.IsExist(err) {
		// path does not exist.
		err := os.MkdirAll(servercertspath, 0755)
		if err != nil {
			log.Printf("failed create %q folder - errmsg : %v\n", servercertspath, err)
			os.Exit(1)
		}
	} else {
		if !info.IsDir() {
			// path already exists but not a directory.
			log.Printf("path %q exists but it is not a folder so please check before continue - errmsg : %v\n", servercertspath, err)
			os.Exit(0)
		}
	}
}

// GenerateServerCACerts creates <server-ca.crt> which is the self-signed certificate authority for only signing
// the https web servers certificate. It will later be used by https clients to authenticate servers.
func GenerateServerCACerts() (*x509.Certificate, *ecdsa.PrivateKey) {
	// https://pkg.go.dev/crypto/x509#Certificate
	rootCA := &x509.Certificate{
		// https://pkg.go.dev/crypto/x509#SignatureAlgorithm
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		// https://pkg.go.dev/crypto/x509#PublicKeyAlgorithm
		PublicKeyAlgorithm: x509.ECDSA,
		// generate a random serial number
		SerialNumber: big.NewInt(2021),
		// define the PKIX (Internet Public Key Infrastructure Using X.509).
		Subject: pkix.Name{
			Organization:  []string{"Localhost Servers CA, LLC."},
			Country:       []string{"CI"},
			Province:      []string{"Abidjan"},
			Locality:      []string{"Cocody"},
			StreetAddress: []string{"Rue CA"},
			PostalCode:    []string{"000-ca"},
		},

		NotBefore: time.Now(),
		// make it valid for 1 year.
		NotAfter: time.Now().AddDate(1, 0, 0),
		// means this is the CA certificate.
		IsCA: true,
		// https://pkg.go.dev/crypto/x509#ExtKeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// https://pkg.go.dev/crypto/x509#KeyUsage
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,

		EmailAddresses: []string{"ca-email@localhost.local"},
	}

	// generate a public & private key for the certificate.
	rootCAPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("failed to generate server CA private key - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created ecdsa key for server CA certificate.")

	// create the CA certificate. https://pkg.go.dev/crypto/x509#CreateCertificate
	rootCABytes, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, &rootCAPrivKey.PublicKey, rootCAPrivKey)
	if err != nil {
		log.Printf("failed to create server CA certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	// pem encode the certificate.
	rootCAPEM = new(bytes.Buffer)
	err = pem.Encode(rootCAPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCABytes,
	})

	if err != nil {
		log.Printf("failed to pem encode server CA certificate - errmsg : %v\n", err)
		os.Exit(2)
	}

	b, err := x509.MarshalECPrivateKey(rootCAPrivKey)
	if err != nil {
		// serious error happened. exit code 2.
		log.Printf("failed to marshal server CA ECDSA private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	// pem encode the private key.
	rootCAPrivKeyPEM = new(bytes.Buffer)
	err = pem.Encode(rootCAPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	})

	if err != nil {
		log.Printf("failed to pem encode server CA private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	// dump CA certificate into a file.
	if err := os.WriteFile(servercertspath+servercacerts, rootCAPEM.Bytes(), 0644); err != nil {
		log.Printf("failed to save on disk the server CA certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created and saved server CA certificate.")

	return rootCA, rootCAPrivKey
}

// GenerateClientCACerts creates <client-ca.crt> which is the self-signed certificate authority for only signing
// the https clients certificate. It will later be used by https web servers to authenticate clients thus mTLS.
func GenerateClientCACerts() {
	// https://pkg.go.dev/crypto/x509#Certificate
	clientsCA := &x509.Certificate{

		SignatureAlgorithm: x509.SHA384WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		// generate a random serial number
		SerialNumber: big.NewInt(2021),
		// define the PKIX (Internet Public Key Infrastructure Using X.509).
		Subject: pkix.Name{
			Organization:  []string{"Localhost Clients CA, LLC."},
			Country:       []string{"CI"},
			Province:      []string{"Abidjan"},
			Locality:      []string{"Cocody"},
			StreetAddress: []string{"Rue CA"},
			PostalCode:    []string{"000-ca"},
		},

		NotBefore: time.Now(),
		// make it valid for 1 year.
		NotAfter: time.Now().AddDate(1, 0, 0),
		// means this is the CA certificate.
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,

		EmailAddresses: []string{"ca-email@localhost.local"},
	}

	// generate a public & private key for the certificate.
	clientsCAPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("failed to generate clients CA private key - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created rsa key for clients CA certificate.")

	// create the CA certificate. https://pkg.go.dev/crypto/x509#CreateCertificate
	clientsCABytes, err := x509.CreateCertificate(rand.Reader, clientsCA, clientsCA, &clientsCAPrivKey.PublicKey, clientsCAPrivKey)
	if err != nil {
		log.Printf("failed to create clients CA certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created clients CA certificate.")

	// pem encode the certificate.
	clientsCAPEM = new(bytes.Buffer)
	err = pem.Encode(clientsCAPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientsCABytes,
	})

	if err != nil {
		log.Printf("failed to pem encode clients CA certificate - errmsg : %v\n", err)
		os.Exit(2)
	}

	// dump CA certificate into a file.
	if err := os.WriteFile(clientcertspath+clientcacerts, clientsCAPEM.Bytes(), 0644); err != nil {
		log.Printf("failed to save on disk the clients CA certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully pem encoded and saved clients CA private key.")

	// pem encode the private key.
	clientsCAPrivKeyPEM = new(bytes.Buffer)
	err = pem.Encode(clientsCAPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientsCAPrivKey),
	})

	if err != nil {
		log.Printf("failed to pem encode clients CA private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	// dump CA private key into a file.
	if err := os.WriteFile(clientcertspath+clientcaprivkey, clientsCAPrivKeyPEM.Bytes(), 0644); err != nil {
		log.Printf("failed to save on disk the clients CA private key - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully pem encoded and saved clients CA private key.")

	// flush the memory buffer.
	clientsCAPrivKeyPEM.Reset()
}

// GenerateServerCerts auto creates web server certificate and signs it with root CA certs.
func GenerateServerCerts(rootCA *x509.Certificate, rootCAPrivKey *ecdsa.PrivateKey) ([]byte, []byte) {
	// https://pkg.go.dev/crypto/x509#Certificate
	serverCerts := &x509.Certificate{
		// https://pkg.go.dev/crypto/x509#SignatureAlgorithm
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		// https://pkg.go.dev/crypto/x509#PublicKeyAlgorithm
		PublicKeyAlgorithm: x509.ECDSA,
		// generate a random serial number.
		SerialNumber: big.NewInt(20210),
		// define the PKIX (Internet Public Key Infrastructure Using X.509).
		Subject: pkix.Name{
			Organization:  []string{"Localhost Servers, LLC."},
			Country:       []string{"CI"},
			Province:      []string{"Abidjan"},
			Locality:      []string{"Cocody"},
			StreetAddress: []string{"Rue Servers"},
			PostalCode:    []string{"000-srv"},
		},

		NotBefore: time.Now(),
		// make it valid for 30 days.
		NotAfter: time.Now().Add(time.Hour * 24 * 30),
		// means this is not the CA certificate.
		IsCA: false,
		// https://pkg.go.dev/crypto/x509#ExtKeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// https://pkg.go.dev/crypto/x509#KeyUsage
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,

		EmailAddresses: []string{"server-email@localhost.local"},
	}

	// set ip addresses and/or dns/hostnames.
	if serverIP == "localhost" || serverIP == "127.0.0.1" || serverIP == "::1" {
		// user wants using server on localhost so set all options.
		serverCerts.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		serverCerts.DNSNames = []string{"localhost"}
	} else {
		// check either user provided IP or DNS Name of the server.
		if ip := net.ParseIP(serverIP); ip != nil {
			// ip address provided.
			serverCerts.IPAddresses = append(serverCerts.IPAddresses, ip)
		} else {
			// dns name provided.
			serverCerts.DNSNames = append(serverCerts.DNSNames, serverIP)
		}
	}

	// generate a public & private key for the certificate.
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("failed to generate server private key - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created ecdsa-based key for server certificate.")

	// create the server certificate and sign with root CA certificate.
	// https://pkg.go.dev/crypto/x509#CreateCertificate
	serverCertsBytes, err := x509.CreateCertificate(rand.Reader, serverCerts, rootCA, &serverPrivKey.PublicKey, rootCAPrivKey)
	if err != nil {
		log.Printf("failed to create server certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	// pem encode the certificate.
	serverCertsPEM := new(bytes.Buffer)
	err = pem.Encode(serverCertsPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertsBytes,
	})

	if err != nil {
		log.Printf("failed to pem encode server certificate - errmsg : %v\n", err)
		os.Exit(2)
	}

	b, err := x509.MarshalECPrivateKey(serverPrivKey)
	if err != nil {
		// serious error happened. exit code 2.
		log.Printf("failed to marshal server private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	// pem encode the private key.
	serverPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	})

	if err != nil {
		log.Printf("failed to pem encode server private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	log.Println("successfully created & pem encoded server certificate & private key.")

	return serverCertsPEM.Bytes(), serverPrivKeyPEM.Bytes()
}

// GenerateClientCerts auto creates https client certificate and signs it with Clients CA certs.
func GenerateClientCerts(clientsCA *x509.Certificate, clientsCAPrivKey *rsa.PrivateKey) ([]byte, []byte) {

	// https://pkg.go.dev/crypto/x509#Certificate
	clientCerts := &x509.Certificate{
		// https://pkg.go.dev/crypto/x509#SignatureAlgorithm
		SignatureAlgorithm: x509.SHA384WithRSA,
		// https://pkg.go.dev/crypto/x509#PublicKeyAlgorithm
		PublicKeyAlgorithm: x509.RSA,
		// generate a random serial number.
		SerialNumber: big.NewInt(20210),
		// define the PKIX (Internet Public Key Infrastructure Using X.509).
		Subject: pkix.Name{
			Organization:  []string{"Localhost Clients, LLC."},
			Country:       []string{"CI"},
			Province:      []string{"Abidjan"},
			Locality:      []string{"Cocody"},
			StreetAddress: []string{"Rue Clients"},
			PostalCode:    []string{"000-client"},
			CommonName:    "Client A",
		},

		NotBefore: time.Now(),
		// make it valid for 1 day.
		NotAfter: time.Now().Add(time.Hour * 24),
		// means this is not the CA certificate.
		IsCA: false,
		// https://pkg.go.dev/crypto/x509#ExtKeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// https://pkg.go.dev/crypto/x509#KeyUsage
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,

		EmailAddresses: []string{"client-email@localhost.local"},
	}

	// generate a public & private key for the certificate.
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate client private key - errmsg : %v\n", err)
		os.Exit(1)
	}

	log.Println("successfully created rsa-based key for client certificate.")

	// create the client certificate and sign with ClientsCA certificate.
	// https://pkg.go.dev/crypto/x509#CreateCertificate
	clientCertsBytes, err := x509.CreateCertificate(rand.Reader, clientCerts, clientsCA, &clientPrivKey.PublicKey, clientsCAPrivKey)
	if err != nil {
		log.Printf("failed to create client certificate - errmsg : %v\n", err)
		os.Exit(1)
	}

	// pem encode the certificate.
	clientCertsPEM := new(bytes.Buffer)
	err = pem.Encode(clientCertsPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertsBytes,
	})

	if err != nil {
		log.Printf("failed to pem encode client certificate - errmsg : %v\n", err)
		os.Exit(2)
	}
	// pem encode the private key.
	clientPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(clientPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey),
	})

	if err != nil {
		log.Printf("failed to pem encode client private key - errmsg : %v\n", err)
		os.Exit(2)
	}

	log.Println("successfully created & pem encoded client certificate & private key.")

	return clientCertsPEM.Bytes(), clientPrivKeyPEM.Bytes()
}

// loadClientsCAInfos reads (from the disk) the content of clients CA's certs and
// private key files then parse them to return the x509 certificate and private key.
func loadClientsCAInfosFromDisk() (clientsCA *x509.Certificate, clientsCAPrivKey *rsa.PrivateKey) {
	var err error
	// load the clients CA pem-encoded certificate from disk.
	clientsCAFileData, err := ioutil.ReadFile(filepath.Join(certsFolder, clientcertspath+clientcacerts))
	if err != nil {
		log.Printf("failed to read client CA certificate file from disk - errmsg : %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(clientsCAFileData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Printf("failed to decode PEM block containing clients CA certificate")
		os.Exit(2)
	}

	clientsCA, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("failed to parse client CA certificate from disk - errmsg : %v\n", err)
		os.Exit(1)
	}

	// load the clients CA pem-encoded private key from disk.
	clientsCAPrivKeyFileData, err := ioutil.ReadFile(clientcertspath + clientcaprivkey)
	if err != nil {
		log.Printf("failed to load client CA certificate from disk - errmsg : %v\n", err)
		os.Exit(1)
	}

	block, _ = pem.Decode(clientsCAPrivKeyFileData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Printf("failed to decode PEM block containing clients CA private key")
		os.Exit(2)
	}

	clientsCAPrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("failed to parse client CA private key from disk - errmsg : %v\n", err)
		os.Exit(1)
	}

	return
}

func startHTTPSClient(clientCertsPEMBytes []byte, clientPrivKeyPEMBytes []byte, exit <-chan struct{}) {
	// constructs client TLS certificate from generated certs & private key.
	clientTLSCerts, err := tls.X509KeyPair(clientCertsPEMBytes, clientPrivKeyPEMBytes)
	if err != nil {
		log.Printf("failed to load server pem certificate and key - errmsg : %v\n", err)
		os.Exit(1)
	}

	// load the root (servers) CA PEM-encoded certificate from disk.
	rootCACert, err := ioutil.ReadFile(filepath.Join(certsFolder, servercertspath+servercacerts))
	if err != nil {
		log.Printf("failed to load root/server CA certificate from disk - errmsg : %v\n", err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(rootCACert)

	// create a HTTPS client and supply the created CA pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientTLSCerts},
				RootCAs:      caCertPool,
			},
		},
	}

	// initiate a GET Request towards the https server with context.
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost:8443/", nil)
	if err != nil {
		log.Printf("failed to constructs the request - errmsg : %v\n", err)
		os.Exit(1)
	}

	// async to cancel the request if requested by user.
	go func() {
		<-exit
		cancel()
	}()

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed to send the request to server - errmsg : %v\n", err)
		os.Exit(1)
	}

	// read the response body.
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read the server response - errmsg : %v\n", err)
	}

	fmt.Printf("%s\n", body)
}

// runIntoClientMode runs each functions needed to spin up the client.
func runIntoClientMode() {

	// background routine to handle signals.
	exit := make(chan struct{}, 1)
	go handleSignal(exit, false)

	clientsCA, clientsCAPrivKey := loadClientsCAInfosFromDisk()

	// generate client private key and certificate then sign it with clients CA.
	clientCertsPEMBytes, clientPrivKeyPEMBytes := GenerateClientCerts(clientsCA, clientsCAPrivKey)

	startHTTPSClient(clientCertsPEMBytes, clientPrivKeyPEMBytes, exit)
}

// runIntoServerMode runs each functions needed to spin up the server.
func runIntoServerMode() {

	// background routine to handle signals.
	exit := make(chan struct{}, 1)
	go handleSignal(exit, true)
	createCertsFolders()

	// generate root/server CA certs.
	rootCA, rootCAPrivKey := GenerateServerCACerts()
	// generate clients CA certs.
	GenerateClientCACerts()
	// generate server keys and certs.
	serverCertsPEMBytes, serverPrivKeyPEMBytes := GenerateServerCerts(rootCA, rootCAPrivKey)
	// start the secure web server and block until shut down.
	startHTTPSServer(serverCertsPEMBytes, serverPrivKeyPEMBytes, exit)
}

func startHTTPSServer(serverCertsPEMBytes []byte, serverPrivKeyPEMBytes []byte, exit <-chan struct{}) {

	serverCerts, err := tls.X509KeyPair(serverCertsPEMBytes, serverPrivKeyPEMBytes)
	if err != nil {
		log.Printf("failed to load server pem certificate and key - errmsg : %v\n", err)
		os.Exit(1)
	}

	// build server TLS configurations.
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(clientsCAPEM.Bytes())
	serverTLSConf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCerts},
		// server must requests from client to send a valid certificate.
		ClientAuth: tls.RequireAndVerifyClientCert,
		// CA certificate to authenticate clients.
		ClientCAs: certpool,
	}

	// base http router.
	router := http.NewServeMux()

	// simple inline handler function to compute client certificate fingerprint.
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[ip: %s] [method: %s] [url: %s] [browser: %s]", r.RemoteAddr, r.Method, r.URL.Path, r.UserAgent())

		// PeerCertificates are the parsed certificates sent by the peer, in the
		// order in which they were sent. The first element is the leaf certificate
		// that the connection is verified against.it cannot be empty because
		// Config.ClientAuth is RequireAndVerifyClientCert on server side.
		clientCerts := r.TLS.PeerCertificates[0]
		// compute the fingerprint and display into hexadecimal.
		fingerprint := sha1.Sum(clientCerts.Raw)
		var buf bytes.Buffer
		for i, f := range fingerprint {
			if i > 0 {
				fmt.Fprintf(&buf, ":")
			}
			fmt.Fprintf(&buf, "%02X", f)
		}
		// this fingerprint could be used as token so for further
		// authorization validation. This is certificate bound token.
		response := fmt.Sprintf("[Common Name]: %s - [Fingerprint]: %s\n", clientCerts.Subject.CommonName, buf.String())
		fmt.Println(response)
		io.WriteString(w, fmt.Sprintf("Hello From mTLS Server. Please Find Below Your Certificate Details.\n%s", response))
		buf.Reset()
	})

	// non-secure and secure webservers parameters.
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", serverIP, serverPort),
		Handler:      router,
		ErrorLog:     log.New(os.Stdout, "", log.LstdFlags),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    serverTLSConf,
	}

	done := make(chan struct{}, 1)

	// async function in charge of shutting down the server when triggered.
	go func() {
		// ensure this goroutine terminated before program exits.
		defer close(done)

		// wait until closed by handleSignal goroutine.
		<-exit

		log.Printf("shutting down the mTLS web server ... wait for 60 secs max")
		ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)

		// Shutdown gracefully shuts down the server.
		if err := server.Shutdown(ctx); err != nil {
			// error due to closing listeners, or context timeout.
			log.Printf("failed to shutdown gracefully the mTLS server - errmsg: %v", err)
			if err == context.DeadlineExceeded {
				log.Printf("the web server did not gracefully shutdown before 45 secs deadline.")
			} else {
				log.Printf("an error occured when closing underlying listeners.")
			}

			return
		}

		// err = nil - successfully shutdown the server.
		log.Printf("the mTLS web server was successfully shut down.")

	}()

	log.Printf("started secure mTLS web server at %s:%s ...", serverIP, serverPort)
	// start the HTTPS web server and block until error event happen.
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		// ListenAndServeTLS always returns a non-nil error. Shutdown or Close triggers ErrServerClosed.
		log.Printf("failed to start https web server on %s:%s - errmsg: %v\n", serverIP, serverPort, err)
	}

	<-done
}

// handleSignal is a function that process SIGTERM from kill command or CTRL-C or more.
func handleSignal(exit chan struct{}, isServerMode bool) {

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL,
		syscall.SIGTERM, syscall.SIGHUP, os.Interrupt, os.Kill)

	// block until something comes in.
	<-sigch
	signal.Stop(sigch)
	if isServerMode {
		log.Println("exit signal received. certificates folder will be removed.")
		os.RemoveAll("certificates")
	}

	// below triggers exit
	close(exit)
	return
}

func main() {

	// declare all flags.
	clientPtr := flag.Bool("client", false, "specify if wanted to run into client mode")
	serverPtr := flag.Bool("server", false, "specify if wanted to run into server mode")
	helpPtr := flag.Bool("help", false, "specify if wanted to view help details")
	versionPtr := flag.Bool("version", false, "specify if wanted to view version details")

	flag.StringVar(&serverIP, "ip", "localhost", "specify the server ip address")
	flag.StringVar(&serverPort, "port", "8443", "specify the server port")
	flag.StringVar(&certsFolder, "certs", ".", "specify the location of certificates directory")

	clearConsole()

	if len(os.Args) == 1 {
		// program launched without mode specified.
		fmt.Printf("\n%s\n", usage)
		os.Exit(0)
	}

	flag.Parse()

	if *helpPtr || (*clientPtr && *serverPtr) {
		// help or both mode mentionned so display howto.
		fmt.Printf("\n%s\n", usage)
		os.Exit(0)
	}

	if *versionPtr {
		fmt.Printf("\n%s\n", version)
		os.Exit(0)
	}

	if *serverPtr {
		// user requested to launch the tool into server mode.
		log.Printf("starting the program into server mode at %s:%s\n", serverIP, serverPort)
		runIntoServerMode()
		os.Exit(0)
	}

	if *clientPtr {
		// launch the tool for server mode.
		log.Printf("starting the client to connect to the server at %s:%s\n", serverIP, serverPort)
		runIntoClientMode()
		os.Exit(0)
	}
}

const version = "This tool is auto <mtls-client-server-cli> • version 1.0 By Jerome AMON"

const usage = `Usage:
    
    mtls-client-server-cli [--client] [--server] [--help] [--version] [--certs <path-to-ca-certificates>] 


Options:

    -client   Specify to run the program into client mode.
    -server   Specify to run the program into server mode.
    -version  Display the current version of this program.
    -help     Display the help - how to use this program.
    -port     Specify the port where the server should listen.
    -ip       Specify the ip address where to bind the server.


Arguments:

    <path-to-ca-certificates>  path to both root & clients CA certificates folder.


You can run this tool into two different modes (client or server) by specifying the flags --client or
--server. In both mode, you can define the server's ip address and/or port number. By default --ip 
address is localhost (127.0.0.1) and --port is 8443. When these values are mentionned into client mode,
it means the address where the client should connect. Also, in client mode, you can specify the path of 
the parent folder (with --certs flag) from where to load the root/server CA certificate (to authenticate
the server) and client CA certificate (to sign the client auto-generated certificate). If not provided
the client will expect to find them from a folder named certificates inside the same working directory.
Only into server mode that both CA certificates are generated, this means you must run the server before.
Finally, you can display the instructions with the --help flag and the version with --version flag.


Examples:

    $ mtls-client-server-cli --version
    $ mtls-client-server-cli --help
    $ mtls-client-server-cli --client
    $ mtls-client-server-cli --server
    $ mtls-client-server-cli --client --ip 127.0.0.1 --port 8443 --certs certificates
    $ mtls-client-server-cli --client --ip 127.0.0.1 --port 8443
    $ mtls-client-server-cli --server --ip 127.0.0.1 --port 8443`
