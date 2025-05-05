package tkn20

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type abeTestCase struct {
	desc   string
	attrs  Attributes
	policy Policy
	msk    SystemSecretKey
	pk     PublicKey
}

var testCases []abeTestCase
var msk SystemSecretKey
var pk PublicKey
var (
	msg     = []byte("drink your ovaltine now")
	longMsg = []byte(strings.Repeat("a", 10000))
)

func generateAttrs() Attributes {
	benchableAttrs := make(map[string]string, 8)
	for i := 0; i < 8; i++ {
		benchableAttrs["k"+strconv.Itoa(i)] = "v" + strconv.Itoa(i)
	}
	attrs := Attributes{}
	attrs.FromMap(benchableAttrs)
	return attrs
}

func generatePolicy() string {
	var policyBuilder strings.Builder
	for i := 0; i < 8; i++ {
		policyBuilder.WriteString("k")
		policyBuilder.WriteString(strconv.Itoa(i))
		policyBuilder.WriteString(":v")
		policyBuilder.WriteString(strconv.Itoa(i))
		if i != 7 {
			if i%2 == 0 {
				policyBuilder.WriteString(" and ")
			} else {
				policyBuilder.WriteString(" and ")
			}
		}
	}
	fmt.Printf("\nPolicy: %s", policyBuilder.String())
	return policyBuilder.String()
}

func init() {
	smallPolicy := Policy{}
	_ = smallPolicy.FromString("(k1:v1 or k1:v2) and not k2:v3")
	smallAttrs := Attributes{}
	smallAttrs.FromMap(map[string]string{"k1": "v2", "k2": "v4"})
	longPolicy := Policy{}
	_ = longPolicy.FromString(generatePolicy())
	testCases = []abeTestCase{
		{
			desc:   "smallPolicy/Attrs",
			attrs:  smallAttrs,
			policy: smallPolicy,
		},
		{
			desc:   "longPolicy/Attrs",
			attrs:  generateAttrs(),
			policy: longPolicy,
		},
	}
	var err error
	for i := range testCases {
		testCases[i].pk, testCases[i].msk, err = Setup(rand.Reader)
		if err != nil {
			panic(err)
		}
	}
	pk, msk, _ = Setup(rand.Reader)
}
func calculateStats(times []int64) (mean float64, stddev float64) {
	total := int64(0)
	for _, time := range times {
		total += time
	}
	mean = float64(total) / float64(len(times))

	var variance float64
	for _, time := range times {
		variance += math.Pow(float64(time)-mean, 2)
	}
	stddev = math.Sqrt(variance / float64(len(times)))

	return mean, stddev
}
func BenchmarkTKN20KeyGen(b *testing.B) {

	for _, tc := range testCases {
		times := make([]int64, 0, b.N)
		b.Run(fmt.Sprintf("keygen:%s", tc.desc), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				_, err := tc.msk.KeyGen(rand.Reader, tc.attrs)
				elapsed := time.Since(start).Nanoseconds()
				times = append(times, elapsed)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		mean, stddev := calculateStats(times)
		fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
	}

}
func BenchmarkAttrGen(b *testing.B) {

	rightAttrsMap := map[string]string{"1": "1"} //, "2": "2", "3": "3", "4": "4", "5": "5"} //,, "6": "6", "7": "7", "8": "8", "9": "9", "a": "a"}//
	//"11": "1", "12": "2", "13": "3", "14": "4", "15": "5"} //, "16": "6", "17": "7", "18": "8", "19": "9", "1a": "a"}//

	// generate secret key for certain set of attributes
	rightAttrs := Attributes{}
	rightAttrs.FromMap(rightAttrsMap)
	b.ResetTimer()

	msk.KeyGen(rand.Reader, rightAttrs)

	// Successfully recovered plaintext
}
func BenchmarkRSAKeyGen(b *testing.B) {
	times := make([]int64, 0, b.N)
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := rsa.GenerateKey(rand.Reader, 4096)
		elapsed := time.Since(start).Nanoseconds()
		times = append(times, elapsed)
		if err != nil {
			b.Fatal(err)
		}
	}
	mean, stddev := calculateStats(times)
	fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
}

func BenchmarkX25519KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := box.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTKN20Encrypt(b *testing.B) {
	for _, tc := range testCases {
		times := make([]int64, 0, b.N)
		b.Run(fmt.Sprintf("encrypt:%s", tc.desc), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {

				start := time.Now()

				_, err := tc.pk.Encrypt(rand.Reader, tc.policy, msg)

				elapsed := time.Since(start).Nanoseconds()
				times = append(times, elapsed)

				if err != nil {
					b.Fatal(err)
				}
			}
		})
		mean, stddev := calculateStats(times)
		fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
	}

}

func BenchmarkRSAEncrypt(b *testing.B) {
	times := make([]int64, 0, b.N)
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := privKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, msg)
		elapsed := time.Since(start).Nanoseconds()
		times = append(times, elapsed)
		if err != nil {
			b.Fatal(err)
		}
	}
	mean, stddev := calculateStats(times)
	fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
}

func BenchmarkX25519Encrypt(b *testing.B) {
	pubKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := box.SealAnonymous(nil, msg, pubKey, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTKN20Decrypt(b *testing.B) {

	for _, tc := range testCases {
		times := make([]int64, 0, b.N)
		b.Run(fmt.Sprintf("decrypt:%s", tc.desc), func(b *testing.B) {
			userKey, err := tc.msk.KeyGen(rand.Reader, tc.attrs)
			if err != nil {
				b.Fatal(err)
			}
			ciphertext, err := tc.pk.Encrypt(rand.Reader, tc.policy, msg)
			if err != nil {
				b.Fatal(err)
			}
			keyBytes, _ := userKey.MarshalBinary()
			pubKeyBytes, _ := tc.pk.MarshalBinary()
			// longCt is only benchmarked to measure size overhead
			longCt, err := tc.pk.Encrypt(rand.Reader, tc.policy, longMsg)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				_, err = userKey.Decrypt(ciphertext)
				elapsed := time.Since(start).Nanoseconds()
				times = append(times, elapsed)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(pubKeyBytes)), "public_key_size")
			b.ReportMetric(float64(len(keyBytes)), "attribute_secret_key_size")
			b.ReportMetric(float64(len(ciphertext)-len(msg)), "ciphertext_bytes_overhead_32b_msg")
			b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
		})
		mean, stddev := calculateStats(times)
		fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
	}

}

func BenchmarkRSADecrypt(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := privKey.PublicKey
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, msg)
	if err != nil {
		b.Fatal(err)
	}
	// longCt is only benchmarked to measure size overhead
	longCt, err := rsaEncrypt(longMsg, &privKey.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	times := make([]int64, 0, b.N)
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ct)
		elapsed := time.Since(start).Nanoseconds()
		times = append(times, elapsed)
		if err != nil {
			b.Fatal(err)
		}
	}
	mean, stddev := calculateStats(times)
	fmt.Printf("\nMean: %f, Stddev: %f\n, Prop: %f\n", mean, stddev, stddev/mean)
	b.ReportMetric(float64(privKey.PublicKey.Size()), "public_key_size")
	b.ReportMetric(float64(len(x509.MarshalPKCS1PrivateKey(privKey))), "secret_key_size")
	b.ReportMetric(float64(len(ct)-len(msg)), "ciphertext_bytes_overhead")
	b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
}

func BenchmarkX25519Decrypt(b *testing.B) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct, err := box.SealAnonymous(nil, msg, pubKey, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	// longCt is only benchmarked to measure size overhead
	longCt, err := box.SealAnonymous(nil, longMsg, pubKey, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := box.OpenAnonymous(nil, ct, pubKey, privKey)
		if !ok {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(pubKey)), "public_key_size")
	b.ReportMetric(float64(len(privKey)), "secret_key_size")
	b.ReportMetric(float64(len(ct)-len(msg)), "ciphertext_bytes_overhead_32b_msg")
	b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_bytes_overhead_10kb_msg")
}

func rsaEncrypt(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	chunkSize := 245 // Max chunk size for 2048 bit key with PKCS1v15 padding
	var ct []byte
	for len(data) > 0 {
		if len(data) < chunkSize {
			chunkSize = len(data)
		}
		chunk := data[:chunkSize]
		data = data[chunkSize:]
		encryptedChunk, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, chunk)
		if err != nil {
			return nil, err
		}
		ct = append(ct, encryptedChunk...)
	}
	return ct, nil
}

// go test -benchmem -bench ^BenchmarkTKN20EndToEnd$ github.com/cloudflare/circl/abe/cpabe/tkn20
func BenchmarkTKN20EndToEnd(b *testing.B) {
	attributeCounts := []int{2, 3, 4, 5, 10, 20}

	csvFile, err := os.Create("tkn20_results.csv")
	if err != nil {
		b.Fatalf("cannot create CSV file: %v", err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	writer.Write([]string{
		"mode", "structure_n", "policy_len", "keygen_time_us",
		"avg_encrypt_time_us", "avg_decrypt_time_us",
		"usk_length_bytes", "avg_ciphertext_length_bytes",
		"access_structure_size_bytes", "ciphertext overhead 32B", "ciphertext overhead 10kB", "policy",
	})

	for _, maxAttrCount := range attributeCounts {
		for attrCount := 2; attrCount <= maxAttrCount; attrCount++ {
			b.Run(fmt.Sprintf("%d_attributes", attrCount), func(b *testing.B) {
				attrsMap := make(map[string]string)
				policyParts := make([]string, 0, attrCount)

				for i := 0; i < attrCount; i++ {
					key := fmt.Sprintf("k%d", i)
					val := fmt.Sprintf("v%d", i)
					attrsMap[key] = val
					policyParts = append(policyParts, fmt.Sprintf("%s:%s", key, val))
				}

				policyStr := strings.Join(policyParts, " and ")

				fmt.Printf("\n\n=== Benchmark for %d attributes ===\n", attrCount)
				fmt.Printf("Policy: %s\n", policyStr)
				fmt.Printf("Attributes: %v\n", attrsMap)

				attrs := Attributes{}
				attrs.FromMap(attrsMap)
				policy := Policy{}
				if err := policy.FromString(policyStr); err != nil {
					b.Fatalf("invalid policy: %v", err)
				}

				pk, msk, err := Setup(rand.Reader)
				if err != nil {
					b.Fatalf("setup error: %v", err)
				}
				start := time.Now()
				userKey, err := msk.KeyGen(rand.Reader, attrs)
				if err != nil {
					b.Fatalf("keygen error: %v", err)
				}
				keygenTimeUs := float64(time.Since(start).Microseconds())

				// Encrypt/Decrypt
				var encryptTotalUs, decryptTotalUs int64
				var ct []byte
				for i := 0; i < b.N; i++ {
					start = time.Now()
					ct, err = pk.Encrypt(rand.Reader, policy, msg)
					if err != nil {
						b.Fatalf("encryption error: %v", err)
					}
					encryptTotalUs += time.Since(start).Microseconds()

					start = time.Now()
					decMsg, err := userKey.Decrypt(ct)
					if err != nil {
						b.Fatalf("decryption error: %v", err)
					}
					decryptTotalUs += time.Since(start).Microseconds()

					if string(decMsg) != string(msg) {
						b.Fatalf("decryption mismatch: got %s, want %s", decMsg, msg)
					}
				}

				// Encrypt long message
				longCt, err := pk.Encrypt(rand.Reader, policy, longMsg)
				if err != nil {
					b.Fatal(err)
				}

				skBin, _ := userKey.MarshalBinary()
				pkBin, _ := pk.MarshalBinary()

				policySize := len(policyStr)
				avgEncrypt := float64(encryptTotalUs) / float64(b.N)
				avgDecrypt := float64(decryptTotalUs) / float64(b.N)

				b.ReportMetric(float64(len(pkBin)), "public_key_size_bytes")
				b.ReportMetric(float64(len(skBin)), "secret_key_size_bytes")
				b.ReportMetric(float64(len(ct)-len(msg)), "ciphertext_overhead_32b_msg_bytes")
				b.ReportMetric(float64(len(longCt)-len(longMsg)), "ciphertext_overhead_10kb_msg_bytes")

				// Zapisz dane do CSV
				writer.Write([]string{
					"ABE - BLS-12-381 Pairing",                  // mode
					fmt.Sprintf("%d", attrCount),                // structure_n
					fmt.Sprintf("%d", attrCount),                // policy_len
					fmt.Sprintf("%.2f", keygenTimeUs),           // keygen_time_us
					fmt.Sprintf("%.2f", avgEncrypt),             // encrypt_time
					fmt.Sprintf("%.2f", avgDecrypt),             // decrypt_time
					fmt.Sprintf("%d", len(skBin)),               // user secret key length
					fmt.Sprintf("%d", len(ct)),                  // ciphertext length
					fmt.Sprintf("%d", policySize),               // policy size
					fmt.Sprintf("%d", len(ct)-len(msg)),         // ciphertext overhead
					fmt.Sprintf("%d", len(longCt)-len(longMsg)), // long ciphertext overhead
					policyStr, // policy
				})
			})
		}
	}
}
