package observability

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTags_Identity(t *testing.T) {
	full := "wasmcustom.kubewaf_waf.tx.total_waf_namespace=shop_waf_name=shop-waf_engine=modsecurity_owner=modsecurity-proxy-wasm"
	ex := ExtractTags(full)
	if ex.Tags["waf_namespace"] != "shop" || ex.Tags["waf_name"] != "shop-waf" {
		t.Fatalf("identity tags=%v", ex.Tags)
	}
	if ex.Tags["engine"] != "modsecurity" || ex.Tags["owner"] != "modsecurity-proxy-wasm" {
		t.Fatalf("engine/owner=%v", ex.Tags)
	}
	if !strings.Contains(ex.ExtractedName, "tx.total") {
		t.Fatalf("extracted=%q", ex.ExtractedName)
	}
}

func TestConvertStat_FixtureNoDoubleCount(t *testing.T) {
	path := filepath.Join("testdata", "stats.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	kept := map[string]int{}
	droppedHTTP := 0
	droppedLegacy := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		name = strings.TrimSpace(name)
		c := ConvertStat(name)
		if c.Drop {
			if strings.Contains(name, "http.ingress_http") || strings.Contains(name, "cluster.kubewaf_ecds") {
				droppedHTTP++
			}
			if strings.Contains(name, "modsecurity_proxy_wasm.") {
				droppedLegacy++
			}
			continue
		}
		kept[c.CatalogName]++
		if c.Tags["waf_namespace"] != "shop" {
			t.Fatalf("%s missing identity: %v", name, c.Tags)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if droppedHTTP < 2 {
		t.Fatalf("expected non-WAF Envoy stats dropped, got %d", droppedHTTP)
	}
	if droppedLegacy < 1 {
		t.Fatal("dual_prefix must drop modsecurity_proxy_wasm duplicates")
	}
	for _, want := range []string{
		CatalogTxTotal, CatalogTxAllowed, CatalogTxInterruptions, CatalogTxInterruptionsByRule,
		CatalogRuleMatches, CatalogRuleMatchesByPhase, CatalogRuleMatchesDisruptive,
		CatalogRuleMatchesByRule, CatalogRuleMatchesByTag, CatalogMemoryHeap,
	} {
		if kept[want] != 1 {
			t.Fatalf("catalog %s count=%d (double-count or miss): %v", want, kept[want], kept)
		}
	}
}

func TestConvertStat_FallbackRules(t *testing.T) {
	full := "wasmcustom.kubewaf_waf.configure.fallback_rules_waf_namespace=shop_waf_name=shop-waf_engine=modsecurity_owner=modsecurity-proxy-wasm"
	c := ConvertStat(full)
	if c.Drop || c.CatalogName != CatalogConfigureFallbackRules {
		t.Fatalf("%+v", c)
	}
}

func TestConvertStat_DropsNonWAF(t *testing.T) {
	if !ConvertStat("http.ingress_http.downstream_rq_total").Drop {
		t.Fatal("expected drop")
	}
}

func TestExtractTags_TagBeforePhase(t *testing.T) {
	full := "wasmcustom.kubewaf_waf.rule.matches_tag=attack-sqli_phase=http_request_headers_waf_namespace=shop_waf_name=shop-waf_engine=modsecurity_owner=modsecurity-proxy-wasm"
	ex := ExtractTags(full)
	if ex.Tags["tag"] != "attack-sqli" {
		t.Fatalf("tag=%v", ex.Tags)
	}
	if ex.Tags["phase"] != "http_request_headers" {
		t.Fatalf("phase=%v", ex.Tags)
	}
	c := ConvertStat(full)
	if c.Drop || c.CatalogName != CatalogRuleMatchesByTag {
		t.Fatalf("conv=%+v", c)
	}
}

func TestExtractTags_HighCardValues(t *testing.T) {
	full := "wasmcustom.kubewaf_waf.tx.interruptions_ruleid=942100_phase=http_request_headers_waf_namespace=shop_waf_name=shop-waf_engine=modsecurity_owner=modsecurity-proxy-wasm"
	ex := ExtractTags(full)
	if ex.Tags["rule_id"] != "942100" || ex.Tags["phase"] != "http_request_headers" {
		t.Fatalf("tags=%v", ex.Tags)
	}
	c := ConvertStat(full)
	if c.CatalogName != CatalogTxInterruptionsByRule {
		t.Fatalf("%s", c.CatalogName)
	}
}

func TestConvertStat_LegacyOnlyHighCardWhenNoProductTwin(t *testing.T) {
	// Dual-prefix-off: only ABI prefix exists. High-card series should still convert
	// after we dual-emit; leftover ABI aggregates still drop to avoid double-count.
	if !ConvertStat("modsecurity_proxy_wasm.tx.total_waf_namespace=shop").Drop {
		t.Fatal("legacy aggregate should drop when product prefix is preferred")
	}
}
