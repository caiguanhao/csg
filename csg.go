package csg

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	apiPrefix = "https://95598.csg.cn/ucs/ma/zt"
)

var (
	aesKey = []byte("cOdHFNHUNkZrjNaN")
	aesIV  = []byte("oMChoRLZnTivcQyR")
	pubKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1RJE6GBKJlFQvTU6g0ws9R
+qXFccKl4i1Rf4KVR8Rh3XtlBtvBxEyTxnVT294RVvYz6THzHGQwREnlgdkjZyGBf7tmV2CgwaHF+ttvupuzOmRVQ
/difIJtXKM+SM0aCOqBk0fFaLiHrZlZS4qI2/rBQN8VBoVKfGinVMM+USswwIDAQAB
-----END PUBLIC KEY-----
`)
)

type (
	Client struct {
		AccessToken string
	}
)

// Login with phone and password, return client with access token if success.
func Login(ctx context.Context, phone, password string) (*Client, error) {
	c, err := encryptCredential(password)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(map[string]string{
		"acctId":      phone,
		"credentials": c,
		"credType":    "10",
		"logonChan":   "4",
	})
	if err != nil {
		return nil, err
	}
	p, err := encrypt(string(b))
	if err != nil {
		return nil, err
	}
	reqBody, err := jsonRequestBody(map[string]string{
		"param": p,
	})
	if err != nil {
		return nil, err
	}
	var response response
	resp, err := makeRequest(ctx, "/center/login", map[string]string{
		"need-crypto": "true",
	}, reqBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	return &Client{
		AccessToken: resp.Header.Get("x-auth-token"),
	}, nil
}

type (
	Account struct {
		Id       string
		Number   string
		AreaCode string
		FullName string
		Address  string
	}

	AccountWithMeteringPointId struct {
		Account
		MeteringPointId string
	}

	account struct {
		AreaCode       string `json:"areaCode"`
		CustomerId     string `json:"bindingId"`
		CustomerNumber string `json:"eleCustNumber"`
		UserName       string `json:"userName"`
		Address        string `json:"eleAddress"`
	}
)

func (a account) ToAccount() Account {
	return Account{
		Id:       a.CustomerId,
		Number:   a.CustomerNumber,
		AreaCode: a.AreaCode,
		FullName: a.UserName,
		Address:  a.Address,
	}
}

// Get all associated accounts.
func (client Client) GetAccounts(ctx context.Context) ([]Account, error) {
	var response struct {
		response
		Data []account `json:"data"`
	}
	_, err := makeRequest(ctx, "/eleCustNumber/queryBindEleUsers", map[string]string{
		"x-auth-token": client.AccessToken,
	}, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}
	var accounts []Account
	for i := range response.Data {
		accounts = append(accounts, response.Data[i].ToAccount())
	}
	return accounts, nil

}

// Get all associated accounts with metering point id.
func (client Client) GetAccountsWithMeteringPointId(ctx context.Context, account Account) ([]AccountWithMeteringPointId, error) {
	reqBody, err := jsonRequestBody(map[string]interface{}{
		"areaCode": account.AreaCode,
		"eleCustNumberList": []map[string]string{
			{
				"areaCode":  account.AreaCode,
				"eleCustId": account.Id,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		response
		Data []struct {
			MeteringPointId string `json:"meteringPointId"`
		} `json:"data"`
	}
	_, err = makeRequest(ctx, "/charge/queryMeteringPoint", map[string]string{
		"x-auth-token": client.AccessToken,
	}, reqBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get metering point: %w", err)
	}
	if len(response.Data) == 0 {
		return nil, errors.New("no metering point")
	}
	var accounts []AccountWithMeteringPointId
	for i := range response.Data {
		accounts = append(accounts, AccountWithMeteringPointId{
			Account:         account,
			MeteringPointId: response.Data[i].MeteringPointId,
		})
	}
	return accounts, nil
}

type (
	Bill struct {
		From         time.Time
		To           time.Time
		Usage        string
		TotalCharges string
	}

	bill struct {
		YearMonth        string `json:"electricityBillYearMonth"`
		MonthEnd         string `json:"endMonthDate"`
		MonthStart       string `json:"startMonthDate"`
		TotalElectricity string `json:"totalElectricity"`
		TotalPower       string `json:"totalPower"`
	}
)

func (b bill) ToBill() Bill {
	year := b.YearMonth[0:4]
	loc := time.FixedZone("UTC+8", 8*60*60)
	from, _ := time.ParseInLocation("2006.01.02", year+"."+b.MonthStart, loc)
	to, _ := time.ParseInLocation("2006.01.02", year+"."+b.MonthEnd, loc)
	to = to.AddDate(0, 0, 1).Add(-1 * time.Second)
	return Bill{
		From:         from,
		To:           to,
		Usage:        b.TotalPower,
		TotalCharges: b.TotalElectricity,
	}
}

// Get bills in year of specific account.
func (client Client) GetBills(ctx context.Context, account Account, year int) ([]Bill, error) {
	reqBody, err := jsonRequestBody(map[string]interface{}{
		"areaCode":            account.AreaCode,
		"eleCustId":           account.Id,
		"electricityBillYear": year,
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		response
		Data struct {
			Bills []bill `json:"billUserAndYear"`
		} `json:"data"`
	}
	_, err = makeRequest(ctx, "/charge/selectElecBill", map[string]string{
		"x-auth-token": client.AccessToken,
	}, reqBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get bills: %w", err)
	}
	var bills []Bill
	for i := range response.Data.Bills {
		bills = append(bills, response.Data.Bills[i].ToBill())
	}
	return bills, nil
}

type (
	DailyUsage struct {
		Date  string
		Usage string
	}

	dailyUsage struct {
		Date  string `json:"date"`
		Power string `json:"power"`
	}
)

func (d dailyUsage) ToDailyUsage() DailyUsage {
	return DailyUsage{
		Date:  d.Date,
		Usage: d.Power,
	}
}

// Get daily electricity usage in month of specific account.
func (client Client) GetDailyUsages(ctx context.Context, account AccountWithMeteringPointId, year, month int) ([]DailyUsage, error) {
	reqBody, err := jsonRequestBody(map[string]interface{}{
		"areaCode":        account.AreaCode,
		"eleCustId":       account.Id,
		"meteringPointId": account.MeteringPointId,
		"yearMonth":       fmt.Sprintf("%d%02d", year, month),
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		response
		Data struct {
			Result []dailyUsage `json:"result"`
		} `json:"data"`
	}
	_, err = makeRequest(ctx, "/charge/queryDayElectricByMPoint", map[string]string{
		"x-auth-token": client.AccessToken,
	}, reqBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily usages: %w", err)
	}
	var usages []DailyUsage
	for i := range response.Data.Result {
		usages = append(usages, response.Data.Result[i].ToDailyUsage())
	}
	return usages, nil
}

func decrypt(encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	mode := cipher.NewCBCDecrypter(block, aesIV)
	mode.CryptBlocks(ciphertext, ciphertext)
	return string(bytes.TrimRight(ciphertext, "\x00")), nil
}

func encrypt(input string) (string, error) {
	plaintext := []byte(input)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, aesIV)
	if len(plaintext)%aes.BlockSize != 0 {
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		plaintext = append(plaintext, make([]byte, padding)...)
	}
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func encryptCredential(input string) (string, error) {
	block, _ := pem.Decode(pubKey)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(input))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func jsonRequestBody(data interface{}) (io.Reader, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

type (
	response struct {
		Status  string `json:"sta"`
		Message string `json:"message"`
	}

	isResponse interface {
		IsSuccess() bool
		Error() string
	}
)

func (r response) IsSuccess() bool {
	return r.Status == "00"
}

func (r response) Error() string {
	if r.Message == "" {
		return "status: " + r.Status
	}
	return "status: " + r.Status + ", message: " + r.Message
}

func makeRequest(ctx context.Context, path string, reqHeaders map[string]string, reqBody io.Reader, target isResponse) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", apiPrefix+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148")
	for key, value := range reqHeaders {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, target)
	if err != nil {
		return nil, err
	}
	if target.IsSuccess() { // success
		return resp, nil
	}
	return nil, target
}
