// Independently generate reproducible vectors using unmodified gmsm v0.44.1.
package main

import (
    "bytes"
    "crypto/sha512"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "runtime"
    "sync"
    "time"

    "github.com/emmansun/gmsm/slhdsa"
)

type testCase struct {
    PID int `json:"pid"`
    Index int `json:"index"`
    Seeds string `json:"seeds"`
    Message string `json:"message"`
    Context string `json:"context"`
    AdditionalRandomness string `json:"additionalRandomness"`
    PK string `json:"pk"`
    SK string `json:"sk"`
    DeterministicSignature string `json:"deterministicSignature"`
    RandomizedSignature string `json:"randomizedSignature"`
    ExternalVerified bool `json:"externalVerified"`
    Seconds float64 `json:"seconds"`
}

func material(label string, length int) []byte {
    out := make([]byte, 0, length + 64)
    for block := 0; len(out) < length; block++ {
        digest := sha512.Sum512([]byte(fmt.Sprintf("pqc-a1-5/gmsm/v1/%s/%d", label, block)))
        out = append(out, digest[:]...)
    }
    return out[:length]
}

func makeCase(pid, index int) (testCase, error) {
    started := time.Now()
    name := "SLH-DSA-SM3-128s"
    if pid == 2 { name = "SLH-DSA-SM3-128f" }
    params, ok := slhdsa.GetParameterSet(name)
    if !ok { return testCase{}, fmt.Errorf("missing params %s", name) }
    label := fmt.Sprintf("%d/%d", pid, index)
    seeds := material(label + "/seeds", 48)
    message := material(label + "/message", 1 + index * 31)
    lengths := []int{0, 1, 16, 255, 32}
    context := material(label + "/context", lengths[index % len(lengths)])
    randomizer := material(label + "/randomizer", 16)
    if index == 0 { randomizer = make([]byte, 16) }
    if index == 1 { for i := range randomizer { randomizer[i] = 255 } }
    key, err := slhdsa.GenerateKey(bytes.NewReader(seeds), params)
    if err != nil { return testCase{}, err }
    deterministic, err := key.SignMessage(nil, message, &slhdsa.Options{Context: context})
    if err != nil { return testCase{}, err }
    randomized, err := key.SignMessage(nil, message, &slhdsa.Options{Context: context, AddRand: randomizer})
    if err != nil { return testCase{}, err }
    pk := key.Public().(*slhdsa.PublicKey)
    passed := pk.VerifyWithOptions(deterministic, message, &slhdsa.Options{Context: context}) &&
        pk.VerifyWithOptions(randomized, message, &slhdsa.Options{Context: context})
    if !passed { return testCase{}, fmt.Errorf("external self verify failed %s", label) }
    encode := hex.EncodeToString
    return testCase{pid, index, encode(seeds), encode(message), encode(context), encode(randomizer),
        encode(pk.Bytes()), encode(key.Bytes()), encode(deterministic), encode(randomized), passed,
        time.Since(started).Seconds()}, nil
}

func main() {
    count := flag.Int("count", 10, "seeded key pairs per SM3 parameter")
    workers := flag.Int("workers", 16, "independent vector generation workers")
    output := flag.String("output", "vectors/external-gmsm.json", "output path")
    flag.Parse()
    runtime.GOMAXPROCS(*workers)
    results := make([]testCase, 2 * *count)
    jobs := make(chan int)
    errors := make(chan error, len(results))
    var wait sync.WaitGroup
    for worker := 0; worker < *workers; worker++ {
        wait.Add(1)
        go func() {
            defer wait.Done()
            for job := range jobs {
                result, err := makeCase(job / *count + 1, job % *count)
                if err != nil { errors <- err } else { results[job] = result }
            }
        }()
    }
    for job := range results { jobs <- job }
    close(jobs)
    wait.Wait()
    close(errors)
    for err := range errors { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    value := struct {
        Schema string `json:"schema"`
        Source string `json:"source"`
        Commit string `json:"commit"`
        GoVersion string `json:"goVersion"`
        Cases []testCase `json:"cases"`
    }{"a15-gmsm-external-v1", "github.com/emmansun/gmsm v0.44.1",
        "84294d95666c7b628a45896b2ab068081591ef27", runtime.Version(), results}
    file, err := os.Create(*output + ".tmp")
    if err != nil { panic(err) }
    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(value); err != nil { panic(err) }
    if err := file.Close(); err != nil { panic(err) }
    if err := os.Rename(*output + ".tmp", *output); err != nil { panic(err) }
    fmt.Printf("generated %d keys, %d deterministic/randomized signatures\n", len(results), 2*len(results))
}
