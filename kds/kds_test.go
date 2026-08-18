// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kds

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tinfoilsh/go-sev-guest/abi"
	pb "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProductCertChainURL(t *testing.T) {
	got := ProductCertChainURL(abi.VcekReportSigner, "Milan")
	want := "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	if got != want {
		t.Errorf("ProductCertChainURL(\"Milan\") = %q, want %q", got, want)
	}
}

func TestVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwid[0] = 0xfe
	hwid[abi.ChipIDSize-1] = 0xc0
	got := VCEKCertURL("Milan", hwid, TCBVersion(0))
	want := "https://kdsintf.amd.com/vcek/v1/Milan/fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0"
	if got != want {
		t.Errorf("VCEKCertURL(\"Milan\", %v, 0) = %q, want %q", hwid, got, want)
	}
}

func TestTurinTCBAndCertificateURLs(t *testing.T) {
	const turinTCB = uint64(0x5200000004010101)
	hwid := []byte{0x6b, 0xb1, 0x22, 0x9b, 0x76, 0x92, 0xb7, 0x10}
	reportChipID := append(append([]byte{}, hwid...), make([]byte, abi.ChipIDSize-len(hwid))...)

	tcb, err := NewTCBVersionStruct("Turin", turinTCB)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := tcb.ToTCBParts()
	if err != nil {
		t.Fatal(err)
	}
	wantParts := TCBParts{
		version:  tcbStructVersion1,
		FmcSpl:   1,
		BlSpl:    1,
		TeeSpl:   1,
		SnpSpl:   4,
		UcodeSpl: 82,
	}
	if diff := cmp.Diff(wantParts, parts, cmp.AllowUnexported(TCBParts{})); diff != "" {
		t.Fatalf("Turin TCB decomposition mismatch (-want +got):\n%s", diff)
	}
	recomposed, err := parts.ToTCBVersionStruct()
	if err != nil {
		t.Fatal(err)
	}
	if recomposed.TCB != turinTCB {
		t.Fatalf("Turin TCB recomposed to 0x%x, want 0x%x", recomposed.TCB, turinTCB)
	}

	wantURL := "https://kdsintf.amd.com/vcek/v1/Turin/6bb1229b7692b710?blSPL=1&teeSPL=1&snpSPL=4&ucodeSPL=82&fmcSPL=1"
	for name, queryHWID := range map[string][]byte{
		"KDS HWID":       hwid,
		"report CHIP_ID": reportChipID,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := VCEKCertQuery("Turin", queryHWID, *tcb)
			if err != nil {
				t.Fatal(err)
			}
			if got != wantURL {
				t.Fatalf("VCEKCertQuery() = %q, want %q", got, wantURL)
			}
		})
	}
	if got := VCEKCertURL("Turin", reportChipID, TCBVersion(turinTCB)); got != wantURL {
		t.Fatalf("deprecated VCEKCertURL() = %q, want %q", got, wantURL)
	}

	parsed, err := ParseVCEKCertURL(wantURL)
	if err != nil {
		t.Fatal(err)
	}
	wantParsed := VCEKCertProduct("Turin")
	wantParsed.HWID = hwid
	wantParsed.TCB = turinTCB
	if diff := cmp.Diff(wantParsed, parsed); diff != "" {
		t.Fatalf("ParseVCEKCertURL() mismatch (-want +got):\n%s", diff)
	}

	wantVLEKURL := "https://kdsintf.amd.com/vlek/v1/Turin/cert?blSPL=1&teeSPL=1&snpSPL=4&ucodeSPL=82&fmcSPL=1"
	if got := VLEKCertURL("Turin", TCBVersion(turinTCB)); got != wantVLEKURL {
		t.Fatalf("deprecated VLEKCertURL() = %q, want %q", got, wantVLEKURL)
	}
}

func TestTCBVersionValidation(t *testing.T) {
	if _, err := NewTCBVersionStruct("tUrIn", 0); err != nil {
		t.Fatalf("NewTCBVersionStruct rejected a known product with mixed case: %v", err)
	}
	if _, err := NewTCBVersionStruct("Venice", 0); err == nil {
		t.Fatal("NewTCBVersionStruct accepted an unknown future product")
	}

	reserved, err := NewTCBVersionStruct("Turin", 0x0000000100000000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserved.ToTCBParts(); err == nil || !strings.Contains(err.Error(), "reserved bits") {
		t.Fatalf("Turin reserved TCB bits returned %v, want a reserved-bits error", err)
	}

	if _, err := (TCBParts{version: tcbStructVersion0, FmcSpl: 1}).ToTCBVersionStruct(); err == nil {
		t.Fatal("TCB struct version 0 accepted an FMC component")
	}
	if _, err := (TCBParts{version: tcbStructVersion1, Spl4: 1}).ToTCBVersionStruct(); err == nil {
		t.Fatal("TCB struct version 1 accepted a reserved SPL4 component")
	}

	legacy, err := NewTCBVersionStruct("Milan", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VCEKCertQuery("Turin", make([]byte, abi.ChipIDSize), *legacy); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("VCEKCertQuery product/layout mismatch returned %v, want incompatibility error", err)
	}
	if _, err := VCEKCertQuery("Turin", make([]byte, 7), TCBVersionStruct{version: tcbStructVersion1}); err == nil || !strings.Contains(err.Error(), "HWID") {
		t.Fatalf("VCEKCertQuery short Turin HWID returned %v, want HWID error", err)
	}
}

func TestNewTCBParts(t *testing.T) {
	parts, err := NewTCBParts("Turin", TCBParts{
		FmcSpl:   1,
		BlSpl:    1,
		TeeSpl:   1,
		SnpSpl:   4,
		UcodeSpl: 82,
	})
	if err != nil {
		t.Fatal(err)
	}
	tcb, err := parts.ToTCBVersionStruct()
	if err != nil {
		t.Fatal(err)
	}
	if tcb.TCB != 0x5200000004010101 {
		t.Fatalf("NewTCBParts composed 0x%x, want 0x5200000004010101", tcb.TCB)
	}

	if _, err := NewTCBParts("Genoa", TCBParts{FmcSpl: 1}); err == nil {
		t.Fatal("NewTCBParts accepted FMC for Genoa")
	}
	if _, err := NewTCBParts("Siena", TCBParts{FmcSpl: 1}); err == nil {
		t.Fatal("NewTCBParts accepted FMC for Siena")
	}
	if _, err := NewTCBParts("Venice", TCBParts{}); err == nil {
		t.Fatal("NewTCBParts accepted an unknown product")
	}
}

func TestTCBPartsLERejectsDifferentFormats(t *testing.T) {
	legacy, err := NewTCBParts("Genoa", TCBParts{})
	if err != nil {
		t.Fatal(err)
	}
	turin, err := NewTCBParts("Turin", TCBParts{})
	if err != nil {
		t.Fatal(err)
	}
	if TCBPartsLE(legacy, turin) || TCBPartsLE(turin, legacy) {
		t.Fatal("TCBPartsLE considered categorically different TCB formats comparable")
	}
}

func TestParseTCBURLStrictness(t *testing.T) {
	hwid := strings.Repeat("00", abi.ChipIDSize)
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "duplicate argument",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=0&blSPL=1&teeSPL=0&snpSPL=0&ucodeSPL=0", hwid),
			wantErr: "must occur exactly once",
		},
		{
			name:    "FMC on legacy product",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0&fmcSPL=0", hwid),
			wantErr: "not valid for TCB struct version 0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseVCEKCertURL(tc.url)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseVCEKCertURL() returned %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseTCBURLOmittedParametersDefaultToZero(t *testing.T) {
	turinHWID := "6bb1229b7692b710"
	parsed, err := ParseVCEKCertURL(fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Turin/%s?snpSPL=4", turinHWID))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TCB != 0x0000000004000000 {
		t.Fatalf("abbreviated Turin URL parsed TCB 0x%x, want 0x0000000004000000", parsed.TCB)
	}

	sienaHWID := strings.Repeat("00", abi.ChipIDSize)
	parsed, err = ParseVCEKCertURL(fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Siena/%s?snpSPL=4", sienaHWID))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ProductLine != "Siena" || parsed.TCB != 0x0004000000000000 {
		t.Fatalf("abbreviated Siena URL parsed as product %q TCB 0x%x", parsed.ProductLine, parsed.TCB)
	}
}

func TestProductLineFromFms(t *testing.T) {
	tests := []struct {
		name   string
		family byte
		model  byte
		want   string
	}{
		{name: "Milan", family: 0x19, model: 0x01, want: "Milan"},
		{name: "Genoa", family: 0x19, model: 0x11, want: "Genoa"},
		{name: "Siena", family: 0x19, model: 0xa0, want: "Siena"},
		{name: "Turin extended model 0", family: 0x1a, model: 0x02, want: "Turin"},
		{name: "Turin extended model 1", family: 0x1a, model: 0x10, want: "Turin"},
		{name: "unknown", family: 0x18, model: 0x00, want: "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fms := abi.FmsToCpuid1Eax(tc.family, tc.model, 3)
			if got := ProductLineFromFms(fms); got != tc.want {
				t.Fatalf("ProductLineFromFms(0x%x) = %q, want %q", fms, got, tc.want)
			}
		})
	}
}

func TestParseProductBaseURL(t *testing.T) {
	tcs := []struct {
		name        string
		url         string
		wantProduct string
		wantURL     *url.URL
		wantErr     string
	}{
		{
			name:        "happy path",
			url:         ProductCertChainURL(abi.VcekReportSigner, "Milan"),
			wantProduct: "Milan",
			wantURL: &url.URL{
				Scheme: "https",
				Host:   "kdsintf.amd.com",
				Path:   "cert_chain", // The vcek/v1/Milan part is expected to be trimmed.
			},
		},
		{
			name:    "bad host",
			url:     "https://fakekds.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL host \"fakekds.com\", want \"kdsintf.amd.com\"",
		},
		{
			name:    "bad scheme",
			url:     "http://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL scheme \"http\", want \"https\"",
		},
		{
			name:    "bad path",
			url:     "https://kdsintf.amd.com/vcek/v2/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL path \"/vcek/v2/Milan/cert_chain\", want prefix \"/vcek/v1/\"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseBaseProductURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("parseBaseProductURL(%q) = _, _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(parsed.simpleURL, tc.wantURL); diff != "" {
					t.Errorf("parseBaseProductURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
				if parsed.productLine != tc.wantProduct {
					t.Errorf("parseBaseProductURL(%q) = %q, _, _ want %q", tc.url, parsed.productLine, tc.wantProduct)
				}
			}
		})
	}
}

func TestParseProductCertChainURL(t *testing.T) {
	tests := []struct {
		key     abi.ReportSigner
		product string
		wantKey CertFunction
	}{
		{
			key:     abi.VcekReportSigner,
			product: "Milan",
			wantKey: VcekCertFunction,
		},
		{
			key:     abi.VlekReportSigner,
			product: "Milan",
			wantKey: VlekCertFunction,
		},
	}
	for _, tc := range tests {
		url := ProductCertChainURL(tc.key, tc.product)
		got, key, err := ParseProductCertChainURL(url)
		if err != nil {
			t.Fatalf("ParseProductCertChainURL(%q) = _, _, %v, want nil", tc.product, err)
		}
		if got != tc.product || key != tc.wantKey {
			t.Errorf("ProductCertChainURL(%q) = %q, %v, nil want %q, %v", url, got, key, tc.product, tc.wantKey)
		}
	}
}

func TestParseVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwidhex := hex.EncodeToString(hwid)
	tcs := []struct {
		name    string
		url     string
		want    VCEKCert
		wantErr string
	}{
		{
			name: "happy path",
			url:  VCEKCertURL("Milan", hwid, TCBVersion(0)),
			want: func() VCEKCert {
				c := VCEKCertProduct("Milan")
				c.HWID = hwid
				c.TCB = 0
				return c
			}(),
		},
		{
			name:    "bad query format",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?ha;ha", hwidhex),
			wantErr: "invalid AMD KDS URL query \"ha;ha\": invalid semicolon separator in query",
		},
		{
			name:    "bad query key",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?fakespl=4", hwidhex),
			wantErr: "unexpected KDS TCB version URL argument \"fakespl\"",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=-4", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"-4\", want a value 0-255",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=alpha", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"alpha\", want a value 0-255",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVCEKCertURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ParseVCEKCertURL(%q) = _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(got, tc.want); diff != "" {
					t.Errorf("ParseVCEKCertURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
			}
		})
	}
}

func TestProductName(t *testing.T) {
	tcs := []struct {
		name  string
		input *pb.SevProduct
		want  string
	}{
		{
			name: "nil",
			want: "Milan-B1",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				MachineStepping: &wrapperspb.UInt32Value{Value: 0x1A},
			},
			want: "badstepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_MILAN,
			},
			want: "UnknownStepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
			want: "Milan-B0",
		},
		{
			name: "Genoa-FF",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0xff},
			},
			want: "badstepping",
		},
		{
			name: "unknown milan stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedMilanStepping",
		},
		{
			name: "unknown genoa stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedGenoaStepping",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_UNKNOWN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "Unknown",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProductName(tc.input); got != tc.want {
				t.Errorf("ProductName(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseProductName(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		key     abi.ReportSigner
		want    *pb.SevProduct
		wantErr string
	}{
		{
			name:    "empty",
			wantErr: "unknown product name",
		},
		{
			name:    "Too big",
			input:   "Milan-100",
			wantErr: "unknown product name",
		},
		{
			name:  "happy path Genoa",
			input: "Genoa-B1",
			want: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 1},
			},
		},
		{
			name:    "bad revision Milan",
			input:   "Milan-A1",
			wantErr: "unknown product name",
		},
		{
			name:  "vlek products have no stepping",
			input: "Genoa",
			key:   abi.VlekReportSigner,
			want: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_GENOA,
			},
		},
		{
			name:    "Unhandled report signer",
			input:   "ignored",
			key:     abi.NoneReportSigner,
			wantErr: "internal: unhandled reportSigner",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProductName(tc.input, tc.key)
			if (err == nil && tc.wantErr != "") || (err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Fatalf("ParseProductName(%v) errored unexpectedly: %v, want %q", tc.input, err, tc.wantErr)
			}
			if tc.wantErr == "" {
				if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
					t.Fatalf("ParseProductName(%v) = %v, want %v\nDiff: %s", tc.input, got, tc.want, diff)
				}
			}
		})
	}
}
