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

// Package validate is for checking attestation report properties other than signature verification.
package validate

import (
	"bytes"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tinfoilsh/go-sev-guest/abi"
	sg "github.com/tinfoilsh/go-sev-guest/client"
	labi "github.com/tinfoilsh/go-sev-guest/client/linuxabi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	test "github.com/tinfoilsh/go-sev-guest/testing"
	"github.com/tinfoilsh/go-sev-guest/verify"
	"github.com/tinfoilsh/go-sev-guest/verify/testdata"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	cpb "github.com/tinfoilsh/go-sev-guest/proto/check"
	spb "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
)

const (
	snpReportVersion = 2
	debugPolicy      = 0xa0000
	ecdsaSigAlgo     = 1
)

func TestValidateSnpAttestation(t *testing.T) {
	mknonce := func(front []byte) [64]byte {
		var result [64]byte
		copy(result[:], front)
		return result
	}

	familyID := []byte{0x01, 0x03, 0x03, 0x07, 0x00, 0x0c, 0x00, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	imageID := []byte{0x0f, 0x0e, 0x0e, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f}
	measurement := []byte{0x01, 0x02, 0x03, 0x06, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0}
	hostData := []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0b}
	idKeyDigest := []byte{0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee}
	authorKeyDigest := []byte{0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa}
	reportID := []byte{0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	reportIDMA := []byte{0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	chipID := [64]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	goodtcb := kds.TCBVersionV0{
		BlSpl:    0x1f,
		TeeSpl:   0x7f,
		SnpSpl:   0x70,
		UcodeSpl: 0x92,
	}
	type testOptions struct {
		currentTcb     kds.TCBVersionV0
		reportedTcb    kds.TCBVersionV0
		committedTcb   kds.TCBVersionV0
		launchTcb      kds.TCBVersionV0
		signerInfo     abi.SignerInfo
		currentBuild   uint8
		currentMajor   uint8
		currentMinor   uint8
		committedBuild uint8
		committedMajor uint8
		committedMinor uint8
	}
	makeReport := func(reportData [64]byte, opts testOptions) [labi.SnpReportRespReportSize]byte {
		currentTcb := opts.currentTcb.Uint64()
		reportedTcb := opts.reportedTcb.Uint64()
		committedTcb := opts.committedTcb.Uint64()
		launchTcb := opts.launchTcb.Uint64()
		reportpb := &spb.Report{
			Version:         snpReportVersion,
			Policy:          debugPolicy,
			SignatureAlgo:   ecdsaSigAlgo,
			ReportData:      reportData[:],
			FamilyId:        familyID,
			ImageId:         imageID,
			Measurement:     measurement,
			HostData:        hostData,
			IdKeyDigest:     idKeyDigest,
			AuthorKeyDigest: authorKeyDigest,
			ReportId:        reportID,
			ReportIdMa:      reportIDMA,
			ChipId:          chipID[:],
			SignerInfo:      abi.ComposeSignerInfo(opts.signerInfo),
			CommittedBuild:  uint32(opts.committedBuild),
			CommittedMajor:  uint32(opts.committedMajor),
			CommittedMinor:  uint32(opts.committedMinor),
			CurrentBuild:    uint32(opts.currentBuild),
			CurrentMajor:    uint32(opts.currentMajor),
			CurrentMinor:    uint32(opts.currentMinor),
			PlatformInfo:    1,
			CommittedTcb:    uint64(committedTcb),
			CurrentTcb:      uint64(currentTcb),
			LaunchTcb:       uint64(launchTcb),
			ReportedTcb:     uint64(reportedTcb),
			Signature:       make([]byte, abi.SignatureSize),
		}
		reportRaw, err := abi.ReportToAbiBytes(reportpb)
		if err != nil {
			t.Fatal(err)
		}
		var result [labi.SnpReportRespReportSize]byte
		copy(result[:], reportRaw)
		return result
	}

	// Expensive: generate test keys.
	keys := test.DefaultAmdKeys()
	now := time.Now()
	productName := kds.ProductName(abi.DefaultSevProduct())
	sign0, err := test.DefaultTestOnlyCertChain(productName, now)
	if err != nil {
		t.Fatal(err)
	}
	sb := &test.AmdSignerBuilder{
		Keys:             keys,
		ProductName:      productName,
		ArkCreationTime:  now,
		AskCreationTime:  now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		VcekCustom: test.CertOverride{
			Extensions: test.CustomExtensionsV0(
				goodtcb,
				chipID[:],
				"",
				productName,
			),
		},
		VlekCustom: test.CertOverride{
			Extensions: test.CustomExtensionsV0(
				goodtcb,
				nil,
				"Cloud Service Provider",
				productName,
			),
		},
	}
	sign, err := sb.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	qp0, err := test.TcQuoteProvider(test.TestCases(),
		&test.DeviceOptions{Now: now, Signer: sign0, Product: abi.DefaultSevProduct()})
	if err != nil {
		t.Fatal(err)
	}

	rootBytes := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sign.Ask.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sign.Ark.Raw})...)

	opts := &test.DeviceOptions{
		Signer: sign,
		Now:    now,
	}
	baseOpts := testOptions{
		currentTcb:     goodtcb,
		committedTcb:   goodtcb,
		reportedTcb:    goodtcb,
		launchTcb:      goodtcb,
		signerInfo:     abi.SignerInfo{AuthorKeyEn: true},
		currentBuild:   2,
		committedBuild: 2,
		currentMajor:   1,
		committedMajor: 1,
		currentMinor:   49,
		committedMinor: 49,
	}
	var nonce0s1 [64]byte
	nonce0s1[63] = 1
	nonce12345 := mknonce([]byte{1, 2, 3, 4, 5})
	nonce54321 := mknonce([]byte{5, 4, 3, 2, 1})
	nonceb1455 := mknonce([]byte{0xb, 1, 4, 5, 5})
	noncecb1455 := mknonce([]byte{0xc, 0xb, 1, 4, 5, 5})
	nonce11355 := mknonce([]byte{1, 1, 3, 5, 5})

	tcs := []test.TestCase{
		{
			Name:   "deep validation",
			Input:  nonce12345,
			Output: makeReport(nonce12345, baseOpts),
		},
		{
			Name:  "no author key",
			Input: nonce54321,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.signerInfo = abi.SignerInfo{}
				return makeReport(nonce54321, opts)
			}(),
		},
		{
			Name:  "committed build less", // greater is architecturally illegal
			Input: nonceb1455,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedBuild = 1
				return makeReport(nonceb1455, opts)
			}(),
		},
		{
			Name:  "committed tcb less", // greater is architecturally illegal
			Input: noncecb1455,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedTcb = kds.TCBVersionV0{
					BlSpl:    0,
					TeeSpl:   0x7f,
					SnpSpl:   0x70,
					UcodeSpl: 0x92,
				}
				opts.launchTcb = opts.committedTcb
				return makeReport(noncecb1455, opts)
			}(),
		},
		{
			Name:  "committed version less", // greater is architecturally illegal
			Input: nonce11355,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedMinor = 49
				opts.currentMinor = 51
				return makeReport(nonce11355, opts)
			}(),
		},
	}
	qp, err := test.TcQuoteProvider(tcs, opts)
	if err != nil {
		t.Fatal(err)
	}
	getter := test.SimpleGetter(
		map[string][]byte{
			"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": rootBytes,
			"https://kdsintf.amd.com/vcek/v1/Milan/0a0b0c0d0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010203040506?blSPL=31&snpSPL=112&teeSPL=127&ucodeSPL=146": sign.Vcek.Raw,
		},
	)
	attestationFn := func(nonce [64]byte) *spb.Attestation {

		q, err := sg.GetQuoteProto(qp, nonce)
		if err != nil {
			t.Fatal(err)
		}
		report := q.Report
		attestation, err := verify.GetAttestationFromReport(report, &verify.Options{Getter: getter})
		if err != nil {
			t.Fatal(err)
		}
		return attestation
	}
	attestation12345 := attestationFn(nonce12345)
	attestation54321 := attestationFn(nonce54321)
	attestationb1455 := attestationFn(nonceb1455)
	attestationcb1455 := attestationFn(noncecb1455)
	attestation11355 := attestationFn(nonce11355)
	type testCase struct {
		name        string
		attestation *spb.Attestation
		opts        *Options
		wantErr     string
	}
	tests := []testCase{
		{
			name: "just reportData",
			attestation: func() *spb.Attestation {
				q, err := sg.GetQuoteProto(qp0, nonce0s1)
				if err != nil {
					t.Fatal(err)
				}
				report := q.Report
				return &spb.Attestation{
					Report: report,
					CertificateChain: &spb.CertificateChain{
						AskCert:  sign0.Ask.Raw,
						ArkCert:  sign0.Ark.Raw,
						VcekCert: sign0.Vcek.Raw,
					},
				}
			}(),
			opts: &Options{ReportData: nonce0s1[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
		},
		{
			name:        "deep check",
			attestation: attestation12345,
			opts: &Options{
				ReportData:             nonce12345[:],
				GuestPolicy:            abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:           &abi.SnpPlatformInfo{SMTEnabled: true},
				Measurement:            measurement,
				HostData:               hostData,
				ChipID:                 chipID[:],
				FamilyID:               familyID,
				ImageID:                imageID,
				RequireAuthorKey:       true,
				RequireIDBlock:         true,
				ReportID:               reportID,
				ReportIDMA:             reportIDMA,
				MinimumBuild:           2,
				MinimumVersion:         uint16((1 << 8) | 49),
				MinimumTCB:             kds.DecomposeTCBVersionV0(0x02 | (uint64(0x05) << 48) | (uint64(0x44) << 56)),
				TrustedAuthorKeyHashes: [][]byte{authorKeyDigest},
			},
		},
		{
			name:        "Minimum TCB checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:   nonce12345[:],
				GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumTCB:   kds.DecomposeTCBVersionV0(0x02 | (uint64(0x05) << 48) | (uint64(0xff) << 56)),
			},
			wantErr: "the report's REPORTED_TCB {BlSpl:31 TeeSpl:127 Spl4:0 Spl5:0 Spl6:0 Spl7:0 SnpSpl:112 UcodeSpl:146} is lower than the policy minimum TCB {BlSpl:2 TeeSpl:0 Spl4:0 Spl5:0 Spl6:0 Spl7:0 SnpSpl:5 UcodeSpl:255} in at least one component",
		},
		{
			name:        "Minimum build checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumBuild:   3,
				MinimumVersion: uint16((1 << 8) | 49),
			},
			wantErr: "firmware version 1.49 build 2 is below the required minimum 1.49 build 3",
		},
		{
			name:        "Minimum build belongs to its API version",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumBuild:   255,
				MinimumVersion: uint16((1 << 8) | 48),
			},
		},
		{
			name:        "Minimum version checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumVersion: 0xff00,
			},
			wantErr: "firmware version 1.49 build 2 is below the required minimum 255.0 build 0",
		},
		{
			name:        "Author key checked",
			attestation: attestation54321,
			opts: &Options{
				ReportData:       nonce54321[:],
				GuestPolicy:      abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:     &abi.SnpPlatformInfo{SMTEnabled: true},
				RequireAuthorKey: true,
			},
			// Nevermind that author key digest is nonzero in the fake report.
			// That can't happen on real hardware.
			wantErr: "author key missing when required",
		},
		{
			name:        "PlatformInfo checked",
			attestation: attestation54321,
			opts: &Options{
				ReportData:   nonce54321[:],
				GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo: &abi.SnpPlatformInfo{},
			},
			wantErr: "unauthorized platform feature SMT enabled",
		},
		{
			name:        "Requiring IDBlock requires trust",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				RequireIDBlock: true,
			},
			wantErr: "report ID key not trusted: ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ee",
		},
		// TODO(dionnaglaze): test varies ways provisional firmware shows up.
		// {name: "Provisional firmware"},
		{
			name:        "accepted provisional by build",
			attestation: attestationb1455,
			opts: &Options{
				ReportData:                nonceb1455[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by build",
			attestation: attestationb1455,
			opts:        &Options{ReportData: nonceb1455[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "committed build number 1 does not match the current build number 2",
		},
		{
			name:        "accepted provisional by tcb",
			attestation: attestationcb1455,
			opts: &Options{
				ReportData:                noncecb1455[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by tcb",
			attestation: attestationcb1455,
			opts:        &Options{ReportData: noncecb1455[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "the report's COMMITTED_TCB 0x9270000000007f00 does not match the report's CURRENT_TCB 0x9270000000007f1f",
		},
		{
			name:        "accepted provisional by version",
			attestation: attestation11355,
			opts: &Options{
				ReportData:                nonce11355[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by version",
			attestation: attestation11355,
			opts:        &Options{ReportData: nonce11355[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "committed API version (1.49) does not match the current API version (1.51)",
		},
	}
	numVerbatimFields := 8
	for i := 0; i < numVerbatimFields; i++ {
		opts := &Options{
			GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
			PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
		}
		var name string
		switch i {
		case 0:
			name = "REPORT_DATA"
			opts.ReportData = make([]byte, abi.ReportDataSize)
		case 1:
			name = "HOST_DATA"
			opts.HostData = make([]byte, abi.HostDataSize)
		case 2:
			name = "FAMILY_ID"
			opts.FamilyID = make([]byte, abi.FamilyIDSize)
		case 3:
			name = "IMAGE_ID"
			opts.ImageID = make([]byte, abi.ImageIDSize)
		case 4:
			name = "REPORT_ID"
			opts.ReportID = make([]byte, abi.ReportIDSize)
		case 5:
			name = "REPORT_ID_MA"
			opts.ReportIDMA = make([]byte, abi.ReportIDMASize)
		case 6:
			name = "MEASUREMENT"
			opts.Measurement = make([]byte, abi.MeasurementSize)
		case 7:
			name = "CHIP_ID"
			opts.ChipID = make([]byte, abi.ChipIDSize)
		}
		tests = append(tests, testCase{
			name:        fmt.Sprintf("Test incorrect %s", name),
			attestation: attestation12345,
			opts:        opts,
			wantErr:     fmt.Sprintf("report field %s", name),
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := SnpAttestation(tc.attestation, tc.opts); (err == nil && tc.wantErr != "") ||
				(err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Errorf("Got err '%v', want error containing '%s'", err, tc.wantErr)
			}
		})
	}
}

func TestCertTableOptions(t *testing.T) {
	sign0, err := test.DefaultTestOnlyCertChain(test.GetProductName(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	report := &spb.Report{}
	if err := prototext.Unmarshal([]byte(test.TestCases()[0].OutputProto), report); err != nil {
		t.Fatalf("could not unmarshal zero report: %v", err)
	}
	attestation := &spb.Attestation{
		Report: report,
		CertificateChain: &spb.CertificateChain{
			VcekCert: sign0.Vcek.Raw,
			Extras: map[string][]byte{
				"00000000-0000-c0de-0000-000000000000": []byte("findme"),
			},
		},
	}
	if err := SnpAttestation(attestation, &Options{
		GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
		PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},

		CertTableOptions: map[string]*CertEntryOption{
			"00000000-feee-feee-0000-000000000000": {
				Kind: CertEntryRequire,
				Validate: func(_ *spb.Attestation, blob []byte) error {
					if blob == nil {
						return fmt.Errorf("local data is required")
					}
					return nil
				},
			},
		},
	}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("SnpAttestation(_, &Options{CertTableOptions: require feee-feee}) = %v, want error to contain %s", err, "required")
	}
	if err := SnpAttestation(attestation, &Options{
		GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
		PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
		CertTableOptions: map[string]*CertEntryOption{
			"00000000-0000-c0de-0000-000000000000": {Kind: CertEntryRequire, Validate: func(_ *spb.Attestation, blob []byte) error {
				want := []byte("findme")
				if !bytes.Equal(blob, want) {
					return fmt.Errorf("c0de entry was %v, want %v", blob, want)
				}
				return nil
			}},
			"00000000-feee-feee-0000-000000000000": {Kind: CertEntryAllowMissing, Validate: func(*spb.Attestation, []byte) error { return errors.New("don't call me") }},
		},
	}); err != nil {
		t.Errorf("SnpAttestation(_, &Options{CertTableOptions: require c0de, allow feee-fee}) = %v, want nil", err)
	}

}

func TestCheckMitigationVectors(t *testing.T) {
	tests := []struct {
		name          string
		reportLaunch  uint64
		reportCurrent uint64
		opts          Options
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:          "Pass_NoRequirements",
			reportLaunch:  0x0,
			reportCurrent: 0x0,
			opts:          Options{},
			wantErr:       false,
		},
		{
			name:          "Pass_ExactMatch",
			reportLaunch:  0x3,
			reportCurrent: 0x1,
			opts: Options{
				MinimumLaunchMitigationVector:  0x3,
				MinimumCurrentMitigationVector: 0x1,
			},
			wantErr: false,
		},
		{
			name:          "Pass_Superset",
			reportLaunch:  0x7,
			reportCurrent: 0xF,
			opts: Options{
				MinimumLaunchMitigationVector:  0x3,
				MinimumCurrentMitigationVector: 0x1,
			},
			wantErr: false,
		},
		{
			name:          "Fail_MissingLaunchBit",
			reportLaunch:  0x1,
			reportCurrent: 0x3,
			opts: Options{
				MinimumLaunchMitigationVector: 0x3,
			},
			wantErr:       true,
			wantErrSubstr: "launch mitigation vector",
		},
		{
			name:          "Fail_MissingCurrentBit",
			reportLaunch:  0x3,
			reportCurrent: 0x4,
			opts: Options{
				MinimumCurrentMitigationVector: 0x5,
			},
			wantErr:       true,
			wantErrSubstr: "current mitigation vector",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockReport := &spb.Report{
				LaunchMitVector:  tc.reportLaunch,
				CurrentMitVector: tc.reportCurrent,
			}

			err := validateMitigationVectors(mockReport, &tc.opts)

			if (err != nil) != tc.wantErr {
				t.Errorf("checkMitigationVectors() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("expected error substring %q, got error: %v", tc.wantErrSubstr, err)
				}
			}
		})
	}
}

// FuzzRawSnpAttestation mutates three inputs: a raw attestation report, a certificate table, and
// a binary check.Policy. PolicyToOptions converts the policy, as tools/check does, and
// RawSnpAttestation checks the report against the result. The policy in seed 1 fails the debug
// check, and the policy in seed 2 matches the report.
func FuzzRawSnpAttestation(f *testing.F) {
	certTable := (&abi.CertTable{Entries: []abi.CertTableEntry{
		{GUID: uuid.MustParse(abi.VcekGUID), RawCert: testdata.VcekBytes},
	}}).Marshal()
	report, err := abi.ReportToProto(testdata.AttestationBytes)
	if err != nil {
		f.Fatalf("ReportToProto(AttestationBytes) failed: %v", err)
	}
	minimal, err := proto.Marshal(&cpb.Policy{Policy: abi.SnpPolicyToBytes(abi.SnpPolicy{})})
	if err != nil {
		f.Fatalf("proto.Marshal(minimal policy) failed: %v", err)
	}
	matching, err := proto.Marshal(&cpb.Policy{
		MinimumGuestSvn:  report.GetGuestSvn(),
		Policy:           report.GetPolicy(),
		FamilyId:         report.GetFamilyId(),
		ImageId:          report.GetImageId(),
		Vmpl:             wrapperspb.UInt32(report.GetVmpl()),
		MinimumTcb:       report.GetCurrentTcb(),
		MinimumLaunchTcb: report.GetLaunchTcb(),
		ReportData:       report.GetReportData(),
		Measurement:      report.GetMeasurement(),
		HostData:         report.GetHostData(),
		ReportId:         report.GetReportId(),
		ReportIdMa:       report.GetReportIdMa(),
		ChipId:           report.GetChipId(),
	})
	if err != nil {
		f.Fatalf("proto.Marshal(matching policy) failed: %v", err)
	}
	f.Add(testdata.AttestationBytes, certTable, minimal)
	f.Add(testdata.AttestationBytes, certTable, matching)

	f.Fuzz(func(_ *testing.T, rawReport, rawCertTable, rawPolicy []byte) {
		policy := new(cpb.Policy)
		if err := proto.Unmarshal(rawPolicy, policy); err != nil {
			return
		}
		opts, err := PolicyToOptions(policy)
		if err != nil {
			return
		}
		_ = RawSnpAttestation(rawReport, rawCertTable, opts)
	})
}

func TestValidateIOMMUWriteSafe(t *testing.T) {
	if err := validatePlatformInfo(1<<6, &abi.SnpPlatformInfo{}); err != nil {
		t.Fatalf("validatePlatformInfo() rejected IOMMU_WRITE_SAFE: %v", err)
	}
	if err := validatePlatformInfo(0, &abi.SnpPlatformInfo{IOMMUWriteSafe: true}); err == nil || !strings.Contains(err.Error(), "IOMMU write-safe") {
		t.Fatalf("validatePlatformInfo() returned %v, want missing mitigation error", err)
	}
	if err := validatePlatformInfo(1<<6, &abi.SnpPlatformInfo{IOMMUWriteSafe: true}); err != nil {
		t.Fatalf("validatePlatformInfo() rejected required IOMMU_WRITE_SAFE: %v", err)
	}
	if err := validatePlatformInfo((1<<6)|(1<<8), &abi.SnpPlatformInfo{}); err == nil || !strings.Contains(err.Error(), "unrecognized platform info bit") {
		t.Fatalf("validatePlatformInfo() returned %v, want another reserved-bit error", err)
	}
}

func TestValidateVCEKChipID(t *testing.T) {
	chipID := make([]byte, abi.ChipIDSize)
	for i := range chipID {
		chipID[i] = byte(i + 1)
	}
	turinChipID := make([]byte, abi.ChipIDSize)
	copy(turinChipID, chipID[:abi.TurinSiliconIDSize])
	for _, tc := range []struct {
		name         string
		chipID, hwid []byte
		wantErr      string
	}{
		{name: "whole CHIP_ID", chipID: chipID, hwid: chipID},
		{name: "Turin silicon ID", chipID: turinChipID, hwid: chipID[:abi.TurinSiliconIDSize]},
		{name: "masked CHIP_ID", chipID: make([]byte, abi.ChipIDSize), hwid: chipID},
		{name: "another chip", chipID: chipID, hwid: make([]byte, abi.ChipIDSize), wantErr: "is not the same as"},
		{name: "another Turin chip", chipID: turinChipID, hwid: make([]byte, abi.TurinSiliconIDSize), wantErr: "is not the same as"},
		{name: "unsupported HWID size", chipID: chipID, hwid: chipID[:16], wantErr: "unsupported size 16"},
		{name: "short CHIP_ID", chipID: chipID[:8], hwid: chipID[:8], wantErr: "CHIP_ID has size 8"},
	} {
		err := validateVCEKChipID(tc.chipID, tc.hwid)
		if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: validateVCEKChipID() = %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestReportTcbsFollowTheProductLayout(t *testing.T) {
	const turinFms, genoaFms = 0x00b00f21, 0x00a10f11
	turinTcb := kds.TCBVersionV1{FmcSpl: 1, BlSpl: 3, TeeSpl: 2, SnpSpl: 5, UcodeSpl: 0x61}
	genoaTcb := kds.TCBVersionV0{BlSpl: 10, SnpSpl: 27, UcodeSpl: 88}
	report := func(version, fms uint32, tcb uint64) *spb.Report {
		return &spb.Report{Version: version, Cpuid1EaxFms: fms, ReportedTcb: tcb, CurrentTcb: tcb, CommittedTcb: tcb, LaunchTcb: tcb}
	}
	for _, tc := range []struct {
		name    string
		report  *spb.Report
		cert    kds.TCBVersion
		wantErr string
	}{
		{name: "Turin", report: report(5, turinFms, turinTcb.Uint64()), cert: turinTcb},
		{name: "Genoa", report: report(3, genoaFms, genoaTcb.Uint64()), cert: genoaTcb},
		{name: "legacy report", report: report(2, 0, genoaTcb.Uint64()), cert: genoaTcb},
		{name: "Turin report with a legacy certificate", report: report(5, turinFms, turinTcb.Uint64()), cert: genoaTcb, wantErr: "different TCB formats"},
		{name: "Genoa report with a Turin certificate", report: report(3, genoaFms, genoaTcb.Uint64()), cert: turinTcb, wantErr: "different TCB formats"},
		{name: "legacy report with a Turin certificate", report: report(2, 0, genoaTcb.Uint64()), cert: turinTcb, wantErr: "non-legacy TCB format"},
		{name: "Turin reserved bits", report: report(5, turinFms, turinTcb.Uint64()|1<<40), cert: turinTcb, wantErr: "non-zero reserved bits in Turin TCB"},
		{name: "unknown product", report: report(5, 0x00c00f00, turinTcb.Uint64()), cert: turinTcb, wantErr: "could not determine report TCB format"},
	} {
		got, err := getReportTcbs(tc.report, tc.cert)
		if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: getReportTcbs() = %v, want error containing %q", tc.name, err, tc.wantErr)
			continue
		}
		if err == nil && (got.reported.tcb.StructVersion() != tc.cert.StructVersion() || got.reported.tcb.Uint64() != tc.report.GetReportedTcb()) {
			t.Errorf("%s: reported TCB = %v, want the certificate's layout and the report's value", tc.name, got.reported.tcb)
		}
	}
}
