package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

//pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --init-token --label test3  --so-pin 5462
//softhsm2-util --init-token --slot 1 --label "test2" --so-pin 5462 --pin 8764329
//softhsm2-util --init-token --slot 0 --label "test" --so-pin 5462 --pin 8764329^

func main() {
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "8764329")
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := p.Digest(session, []byte("this is a string"))
	if err != nil {
		panic(err)
	}

	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()
}
