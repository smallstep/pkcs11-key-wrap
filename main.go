package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"

	"github.com/miekg/pkcs11"
)

const CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD = pkcs11.CKM_VENDOR_DEFINED | 0x0000216F

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(2)
}

func softhsm2Path() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/lib/softhsm/libsofthsm2.so"
	case "linux":
		return "/usr/lib/softhsm/libsofthsm2.so"
	default:
		return ""
	}
}

func debug(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
}

func main() {
	var slot int
	var module, pin string
	var key, wrappingKey string
	var cloudhsm bool
	flag.StringVar(&module, "module", softhsm2Path(), "The path to the PKCS#11 module.")
	flag.IntVar(&slot, "slot", 0, "The PKCS#11 slot.")
	flag.StringVar(&pin, "pin", "", "The PKCS#11 ping.")
	flag.StringVar(&key, "key", "", "The object id of the key to wrap.")
	flag.StringVar(&wrappingKey, "wrapping-key", "", "The file with the RSA public key used as a wrapping key.")
	flag.BoolVar(&cloudhsm, "cloudhsm", false, "Specify if it is cloudhsm to use a vendor defined operations.")
	flag.Parse()

	switch {
	case module == "":
		fail("flag --module is required")
	case pin == "":
		fail("flag --pin is required")
	case key == "":
		fail("flag --key is required")
	case wrappingKey == "":
		fail("flag --wrapping-key is required")
	}

	keyID, err := objectID(key)
	if err != nil {
		fail("flag --key is invalid")
	}

	rsaPub, err := readRSAPublicKey(wrappingKey)
	if err != nil {
		fatal("error reading rsa public key: %v", err)
	}

	ctx := pkcs11.New(module)
	if err := ctx.Initialize(); err != nil {
		fatal("error initializing module: %v", err)
	}

	defer ctx.Destroy()
	defer ctx.Finalize()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		fatal("error getting slots: %v", err)
	}
	if slot >= len(slots) || slot < 0 {
		fail("fail --slot is invalid")
	}

	session, err := ctx.OpenSession(slots[slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		fatal("error opening session: %v", err)
	}
	defer ctx.CloseSession(session)

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		fatal("error logging in: %v", err)
	}
	defer ctx.Logout(session)

	debug("Finding key to wrap.")
	keyHandle, err := findKey(ctx, session, pkcs11.CKO_PRIVATE_KEY, keyID)
	if err != nil {
		fatal("error finding key: %v", err)
	}

	debug("Importing wrapping key.")
	wrappingHandle, err := importWrappingKey(ctx, session, rsaPub)
	if err != nil {
		fatal("error importing wrapping key: %v", err)
	}

	debug("Creating AES wrapping key.")
	aesHandle, err := createAESWrappingKey(ctx, session)
	if err != nil {
		fatal("error creating AES wrapping key: %v", err)
	}

	debug("Wrapping AES key using RSA key.")
	wrappedAESKey, err := ctx.WrapKey(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, &pkcs11.OAEPParams{
			HashAlg:    pkcs11.CKM_SHA_1,
			MGF:        pkcs11.CKG_MGF1_SHA1,
			SourceType: pkcs11.CKZ_DATA_SPECIFIED,
			SourceData: []byte(""),
		}),
	}, wrappingHandle, aesHandle)
	if err != nil {
		fatal("error wrapping AES key: %v", err)
	}

	debug("Wrapping key using AES.")
	var mechanism uint
	if cloudhsm {
		mechanism = CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD
	} else {
		mechanism = pkcs11.CKM_AES_KEY_WRAP_PAD
	}
	wrappedKey, err := ctx.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(
		mechanism, nil),
	}, aesHandle, keyHandle)
	if err != nil {
		fatal("error wrapping key: %v", err)
	}

	debug("Destroying AES wrapping key.")
	if err := ctx.DestroyObject(session, aesHandle); err != nil {
		debug("error destroying AES wrapping key: %v", err)
	}

	result := append(wrappedAESKey, wrappedKey...)
	os.Stdout.Write(result)

	// m := pkcs11.NewMechanism(pkcs11.CKM_RSA_AES_KEY_WRAP, &pkcs11.OAEPParams{
	// 	HashAlg:    pkcs11.CKM_SHA_1,
	// 	MGF:        pkcs11.CKG_MGF1_SHA1,
	// 	SourceType: pkcs11.CKZ_DATA_SPECIFIED,
	// 	SourceData: []byte(""),
	// })

	// fmt.Println("Wrapping key.")
	// b, err := ctx.WrapKey(session, []*pkcs11.Mechanism{m}, wrappingHandle, keyHandle)
	// if err != nil {
	// 	fatal("error wrapping key: %v", err)
	// }
}

func objectID(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	return hex.DecodeString(s)
}

func readRSAPublicKey(fn string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("pem block not found on %s", fn)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pem type on %s is not PUBLIC KEY", fn)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA key", fn)
	}

	return key, nil
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, id []byte) (handle pkcs11.ObjectHandle, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	// CloudHSM does not support CKO_PRIVATE_KEY set to false
	if class == pkcs11.CKO_PRIVATE_KEY {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true))
	}

	if err = ctx.FindObjectsInit(session, template); err != nil {
		return
	}
	defer func() {
		finalErr := ctx.FindObjectsFinal(session)
		if err == nil {
			err = finalErr
		}
	}()

	var handles []pkcs11.ObjectHandle
	handles, _, err = ctx.FindObjects(session, 20)
	if err != nil {
		return
	}

	switch len(handles) {
	case 0:
		err = fmt.Errorf("key not found")
	case 1:
		handle = handles[0]
	default:
		err = fmt.Errorf("multiple key found")
	}

	return
}

func importWrappingKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, key *rsa.PublicKey) (pkcs11.ObjectHandle, error) {
	e := big.NewInt(int64(key.E))
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte("wrapping-key")),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, e.Bytes()),
	}
	return ctx.CreateObject(session, template)
}

func createAESWrappingKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, error) {
	return ctx.GenerateKey(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
	}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "aes-wrapping-key"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	})
}
