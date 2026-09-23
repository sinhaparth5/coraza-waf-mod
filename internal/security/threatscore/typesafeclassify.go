package threatscore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// typesafeAPIURL is TypeSafe's System One endpoint. Not configurable — like
// the mailer package's hardcoded Cloudflare endpoint, this feature only ever
// talks to this one service.
const typesafeAPIURL = "https://api.typesafe.ai/v1/systemone"

// typesafeTimeout bounds the one HTTP call made per never-before-seen ASN.
// It never runs on the request hot path or the log-worker goroutine (see
// classifyASN in threatscore.go), so a slow response only delays that one
// ASN's cache entry, not any request.
const typesafeTimeout = 5 * time.Second

// hostingClassifier is judgeHosting's shape as an interface, so tests can
// fake it without a network call.
type hostingClassifier interface {
	judgeHosting(org string) (hostingJudgment, error)
}

// hostingJudgment is judgeHosting's result plus the token usage TypeSafe
// billed for it, so callers can log where usage goes (see
// storage.TypeSafeCall).
type hostingJudgment struct {
	Hosting      bool
	InputTokens  int
	OutputTokens int
}

// typesafeClient judges whether an ASN organization name describes
// datacenter/hosting/VPN infrastructure via TypeSafe's Noul primitive — a
// refinement of asnclass.go's hardcoded keyword list for org names it
// doesn't recognize.
type typesafeClient struct {
	apiKey  string
	baseURL string // typesafeAPIURL in production; overridden by tests
	http    *http.Client
}

func newTypeSafeClient(apiKey string) *typesafeClient {
	return &typesafeClient{apiKey: apiKey, baseURL: typesafeAPIURL, http: &http.Client{Timeout: typesafeTimeout}}
}

type typesafeRequest struct {
	State     string                      `json:"state"`
	Model     string                      `json:"model"`
	Questions map[string]typesafeQuestion `json:"questions"`
}

type typesafeQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria,omitempty"`
}

type typesafeResponse struct {
	Answers map[string]struct {
		Noul float64 `json:"noul"`
	} `json:"answers"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// judgeHosting asks whether org names datacenter/hosting/VPN infrastructure
// rather than a residential ISP or ordinary business. A noul >= 0.5 is "yes".
func (c *typesafeClient) judgeHosting(org string) (hostingJudgment, error) {
	body, err := json.Marshal(typesafeRequest{
		State: org,
		Model: "jev-latest",
		Questions: map[string]typesafeQuestion{
			"is_hosting": {
				Type:         "noul",
				Instructions: "Does this network/organization name belong to a cloud, hosting, datacenter, colocation, or VPN/proxy provider, rather than a residential ISP, mobile carrier, or ordinary business?",
				Criteria: map[string]string{
					"true":  "Cloud, hosting, datacenter, colocation, or VPN/proxy provider",
					"false": "Residential ISP, mobile carrier, or ordinary business/organization",
				},
			},
		},
	})
	if err != nil {
		return hostingJudgment{}, err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return hostingJudgment{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return hostingJudgment{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return hostingJudgment{}, fmt.Errorf("typesafe: status %d", resp.StatusCode)
	}

	var out typesafeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return hostingJudgment{}, err
	}
	ans, ok := out.Answers["is_hosting"]
	if !ok {
		return hostingJudgment{}, fmt.Errorf("typesafe: response missing is_hosting answer")
	}
	return hostingJudgment{
		Hosting:      ans.Noul >= 0.5,
		InputTokens:  out.Usage.InputTokens,
		OutputTokens: out.Usage.OutputTokens,
	}, nil
}
