package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/miekg/pkcs11"
)

//pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --init-token --label test3  --so-pin 5462
//softhsm2-util --init-token --slot 1 --label "test2" --so-pin 5462 --pin 8764329
//softhsm2-util --init-token --slot 0 --label "test" --so-pin 5462 --pin 8764329

// GET http://localhost:3000/

// POST http://localhost:3000/
/*
 {
   Name: "Heisenberg"
  }
*/

func main() {
	rotas := mux.NewRouter().StrictSlash(true)

	rotas.HandleFunc("/hash", hash).Methods("POST")
	var port = ":3000"
	fmt.Println("Server running in port:", port)
	log.Fatal(http.ListenAndServe(port, rotas))

}

type HashResponse struct {
	Hash   string
	Status string
}

type HashRequest struct {
	ReturnCode string
	Pin        string
	Data       string
}

func hash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var hashRequest HashRequest
	var hashResponse HashResponse

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		panic(err)
	}

	if err := r.Body.Close(); err != nil {
		panic(err)
	}

	if err := json.Unmarshal(body, &hashRequest); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			panic(err)
		}
	}

	json.Unmarshal(body, &hashRequest)

	p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	err = p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	fmt.Println(slots)

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, hashRequest.Pin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := p.Digest(session, []byte(hashRequest.Data))
	if err != nil {
		panic(err)
	}

	hashResponse.Hash = string(hash[:])
	hashResponse.Status = "Ok"

	fmt.Println(hashResponse.Hash)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(hashResponse); err != nil {
		panic(err)
	}
}
