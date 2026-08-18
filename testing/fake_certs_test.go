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

package testing

import (
	"bytes"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
	spb "github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
)

func TestCertificatesParse(t *testing.T) {
	signer, err := DefaultTestOnlyCertChain("Milan", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := signer.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := abi.ParseSnpCertTableHeader(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	var hasVcek bool
	var hasVlek bool
	var hasAsk bool
	var hasAsvk bool
	var hasArk bool
	if len(entries) != 5 {
		t.Errorf("ParseSnpCertTableHeader(_) returned %d entries, want 5", len(entries))
	}
	for _, entry := range entries {
		if entry.GUID == uuid.MustParse(abi.VlekGUID) {
			hasVlek = true
		}
		if entry.GUID == uuid.MustParse(abi.VcekGUID) {
			hasVcek = true
		}
		if entry.GUID == uuid.MustParse(abi.AskGUID) {
			hasAsk = true
		}
		if entry.GUID == uuid.MustParse(abi.AsvkGUID) {
			hasAsvk = true
		}
		if entry.GUID == uuid.MustParse(abi.ArkGUID) {
			hasArk = true
		}
		der := certBytes[entry.Offset : entry.Offset+entry.Length]
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Errorf("could not parse certificate of %v: %v", entry.GUID, err)
		}
	}
	if !hasVlek {
		t.Errorf("fake certs missing VLEK")
	}
	if !hasVcek {
		t.Errorf("fake certs missing VCEK")
	}
	if !hasAsk {
		t.Errorf("fake certs missing ASK")
	}
	if !hasArk {
		t.Errorf("fake certs missing ARK")
	}
	if !hasAsvk {
		t.Errorf("fake certs missing ASVK")
	}
	if _, err := kds.VcekCertificateExtensions(signer.Vcek); err != nil {
		t.Errorf("could not parse generated VCEK extensions: %v", err)
	}
}

func TestCertificatesExtras(t *testing.T) {
	b := &AmdSignerBuilder{
		Extras: map[string][]byte{abi.ExtraPlatformInfoGUID: []byte("test")},
	}
	s, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := s.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := abi.ParseSnpCertTableHeader(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	var hasXtra bool
	if len(entries) != 6 {
		t.Errorf("ParseSnpCertTableHeader(_) returned %d entries, want 6", len(entries))
	}
	for _, entry := range entries {
		if entry.GUID == uuid.MustParse(abi.ExtraPlatformInfoGUID) {
			hasXtra = true
			got := certBytes[entry.Offset : entry.Offset+entry.Length]
			want := []byte("test")
			if !bytes.Equal(got, want) {
				t.Errorf("%v data is %v, want %v", abi.ExtraPlatformInfoGUID, got, want)
			}
		}
	}
	if !hasXtra {
		t.Errorf("fake certs missing extra cert")
	}
}

func TestTurinCertificatesAndFakeKDS(t *testing.T) {
	const turinTCB = uint64(0x5200000004010101)
	now := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	builder := &AmdSignerBuilder{
		ProductName:      "Turin-B1",
		ArkCreationTime:  now,
		AskCreationTime:  now,
		AsvkCreationTime: now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		CSPID:            "go-sev-guest",
		TCB:              kds.TCBVersion(turinTCB), //nolint:staticcheck
	}
	copy(builder.HWID[:], []byte{0x6b, 0xb1, 0x22, 0x9b, 0x76, 0x92, 0xb7, 0x10})

	signer, err := builder.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	if signer.Product.GetName() != spb.SevProduct_SEV_PRODUCT_TURIN {
		t.Fatalf("fake signer product is %v, want Turin", signer.Product)
	}
	if stepping := signer.Product.GetMachineStepping().GetValue(); stepping != 1 {
		t.Fatalf("fake signer stepping is %d, want Turin-B1 stepping 1", stepping)
	}
	extensions, err := kds.VcekCertificateExtensions(signer.Vcek)
	if err != nil {
		t.Fatalf("could not parse fake Turin VCEK: %v", err)
	}
	if extensions.StructVersion != 1 || extensions.ProductName != "Turin" {
		t.Fatalf("fake Turin VCEK has struct version %d and product %q", extensions.StructVersion, extensions.ProductName)
	}
	if !reflect.DeepEqual(extensions.HWID, builder.HWID[:8]) {
		t.Fatalf("fake Turin VCEK HWID is %x, want %x", extensions.HWID, builder.HWID[:8])
	}
	if extensions.TCBVersionStruct.TCB != turinTCB {
		t.Fatalf("fake Turin VCEK TCB is 0x%x, want 0x%x", extensions.TCBVersionStruct.TCB, turinTCB)
	}

	fakeKDS, err := FakeKDSFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	_, _, stepping := abi.FmsFromCpuid1Eax(fakeKDS.Certs.GetChipCerts()[0].GetFms())
	if stepping != 1 {
		t.Fatalf("fake KDS FMS has stepping %d, want Turin-B1 stepping 1", stepping)
	}
	tcb, err := kds.NewTCBVersionStruct("Turin", turinTCB)
	if err != nil {
		t.Fatal(err)
	}
	url, err := kds.VCEKCertQuery("Turin", builder.HWID[:], *tcb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fakeKDS.Get(url)
	if err != nil {
		t.Fatalf("fake KDS did not serve Turin VCEK: %v", err)
	}
	if !bytes.Equal(got, signer.Vcek.Raw) {
		t.Fatal("fake KDS returned the wrong Turin VCEK")
	}
}
