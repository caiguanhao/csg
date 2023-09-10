package csg

import (
	"context"
	"os"
	"strings"
	"testing"
)

const (
	plaintext  = "hello"
	ciphertext = "D0Ij172wf3bU8euALlcx0A=="
)

func Test_encrypt(t *testing.T) {
	encrypted, err := encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == ciphertext {
		t.Log("encrypt test passed")
	} else {
		t.Error("encrypt test failed")
	}
}

func Test_decrypt(t *testing.T) {
	decrypted, err := decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted == plaintext {
		t.Log("decrypt test passed")
	} else {
		t.Error("decrypt test failed")
	}
}

func Test_Login(t *testing.T) {
	login := os.Getenv("CSG_LOGIN")
	parts := strings.Split(login, ",")
	if len(parts) < 2 {
		t.Fatal("Set env first: CSG_LOGIN=PHONE,PASSWORD")
	}
	ctx := context.Background()
	c, err := Login(ctx, parts[0], parts[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Log("using access token", c.AccessToken)
	accounts, err := c.GetAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v\n", accounts)
	bills, err := c.GetBills(ctx, accounts[0], 2023)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v\n", bills)
	accounts2, err := c.GetAccountsWithMeteringPointId(ctx, accounts[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Log(accounts2[0])
	usages, err := c.GetDailyUsages(ctx, accounts2[0], 2023, 9)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v\n", usages)
}
