package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogToEvalSpan_Golden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "accesslog-record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec AccessLogRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	span, err := LogToEvalSpan(rec)
	if err != nil {
		t.Fatal(err)
	}
	if span.Name != "waf.eval" || span.Kind != "INTERNAL" || span.Status != "Error" {
		t.Fatalf("span=%+v", span)
	}
	if span.Resource["service.name"] != "kubewaf" || span.Resource["waf.name"] != "shop-waf" {
		t.Fatalf("resource=%v", span.Resource)
	}
	if span.Attributes["waf.action"] != "deny" || span.Attributes["waf.interrupted"] != "true" {
		t.Fatalf("attrs=%v", span.Attributes)
	}
	if span.Attributes["waf.namespace"] != "shop" || span.Attributes["waf.name"] != "shop-waf" {
		t.Fatalf("identity must be span tags for Jaeger search: attrs=%v", span.Attributes)
	}
	if span.Attributes["http.request.method"] != "GET" || span.Attributes["url.path"] != "/search" {
		t.Fatalf("http attrs=%v", span.Attributes)
	}
	if span.Attributes["client.address"] != "10.244.0.15:45678" {
		t.Fatalf("client.address=%q", span.Attributes["client.address"])
	}
	if span.Attributes["waf.anomaly_score"] != "5" {
		t.Fatalf("waf.anomaly_score=%q", span.Attributes["waf.anomaly_score"])
	}
	if span.Events[0].AnomalyScore != 5 {
		t.Fatalf("match anomaly_score=%d", span.Events[0].AnomalyScore)
	}
	enc, err := EncodeEvalOTLPJSON(span, MintEvalIDs("req-1", rec.Attributes["traceparent"], time.Unix(1, 0).UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enc), `"key":"anomaly_score"`) || !strings.Contains(string(enc), `"stringValue":"5"`) {
		t.Fatalf("encoded span missing per-rule anomaly_score: %s", enc)
	}
	if len(span.Events) != 2 {
		t.Fatalf("events=%d", len(span.Events))
	}
	if span.Events[0].Event != "waf.rule_match" || span.Events[1].Event != "waf.tx_interrupt" {
		t.Fatalf("events=%v", span.Events)
	}
	if span.Parent != "b7ad6b7169203331" {
		t.Fatalf("parent=%q", span.Parent)
	}
}

func TestCapMatchesKeepsInterrupt(t *testing.T) {
	in := make([]MatchEvent, 18)
	for i := range in {
		in[i] = MatchEvent{Event: "waf.rule_match", RuleID: int64(i)}
	}
	in[17] = MatchEvent{Event: "waf.tx_interrupt", RuleID: 99, Disruptive: true}
	out := capMatches(in)
	if len(out) != 16 || out[15].Event != "waf.tx_interrupt" || out[15].RuleID != 99 {
		t.Fatalf("out=%+v", out)
	}
}

func TestMintEvalIDsUniqueAndParent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	a := MintEvalIDs("req-a", "", now)
	b := MintEvalIDs("req-b", "", now)
	if a.TraceID == b.TraceID || a.SpanID == b.SpanID {
		t.Fatalf("ids not unique: %+v %+v", a, b)
	}
	if a.TraceID == hardcodedTraceID || a.SpanID == hardcodedSpanID {
		t.Fatal("hard-coded IDs")
	}
	if len(a.TraceID) != 32 || len(a.SpanID) != 16 {
		t.Fatalf("id lengths %+v", a)
	}
	tp := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	c := MintEvalIDs("req-c", tp, now)
	if c.TraceID != "0af7651916cd43dd8448eb211c80319c" || c.Parent != "b7ad6b7169203331" {
		t.Fatalf("parent not preserved: %+v", c)
	}
	if c.SpanID == "b7ad6b7169203331" || c.SpanID == hardcodedSpanID {
		t.Fatalf("span id not minted: %+v", c)
	}
}

func TestEncodeEvalOTLPJSONQuoteInMsg(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "accesslog-record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec AccessLogRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	var roll EventRollup
	if err := json.Unmarshal([]byte(rec.Body), &roll); err != nil {
		t.Fatal(err)
	}
	roll.Matches[0].Msg = `say "pwned"`
	body, _ := json.Marshal(roll)
	rec.Body = string(body)
	span, err := LogToEvalSpan(rec)
	if err != nil {
		t.Fatal(err)
	}
	ids := MintEvalIDs("req-quote", "", time.Unix(1, 0).UTC())
	enc, err := EncodeEvalOTLPJSON(span, ids)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(enc, &doc); err != nil {
		t.Fatalf("invalid json: %v %s", err, enc)
	}
	if !strings.Contains(string(enc), `"events"`) {
		t.Fatal("events missing")
	}
	if !strings.Contains(string(enc), `say \"pwned\"`) {
		t.Fatalf("raw bytes must escape quote: %s", enc)
	}
	msg := walkOTLPEventMsg(doc)
	if msg != `say "pwned"` {
		t.Fatalf("unmarshaled msg=%q", msg)
	}
}

func walkOTLPEventMsg(doc map[string]any) string {
	rss, _ := doc["resourceSpans"].([]any)
	if len(rss) == 0 {
		return ""
	}
	rs, _ := rss[0].(map[string]any)
	sss, _ := rs["scopeSpans"].([]any)
	if len(sss) == 0 {
		return ""
	}
	ss, _ := sss[0].(map[string]any)
	spans, _ := ss["spans"].([]any)
	if len(spans) == 0 {
		return ""
	}
	sp, _ := spans[0].(map[string]any)
	evs, _ := sp["events"].([]any)
	if len(evs) == 0 {
		return ""
	}
	ev, _ := evs[0].(map[string]any)
	attrs, _ := ev["attributes"].([]any)
	for _, a := range attrs {
		am, _ := a.(map[string]any)
		if am["key"] != "msg" {
			continue
		}
		val, _ := am["value"].(map[string]any)
		s, _ := val["stringValue"].(string)
		return s
	}
	return ""
}

func TestPinnedKeys(t *testing.T) {
	if PinnedFilterStateKey != "wasm.kubewaf.event" {
		t.Fatalf("filter state key=%s", PinnedFilterStateKey)
	}
}
