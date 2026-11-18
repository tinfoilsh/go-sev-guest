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
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/kds"
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

func TestTurinCertificateExtensions(t *testing.T) {
	tcb := kds.TCBVersionV1{FmcSpl: 1, BlSpl: 3, TeeSpl: 2, SnpSpl: 5, UcodeSpl: 0x61}
	b := &AmdSignerBuilder{ProductName: "Turin-B1", TCB: tcb}
	for i := range b.HWID[:abi.TurinSiliconIDSize] {
		b.HWID[i] = byte(i + 1)
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	exts, err := kds.VcekCertificateExtensions(signer.Vcek)
	if err != nil {
		t.Fatalf("VcekCertificateExtensions() = %v, want a Turin certificate to parse", err)
	}
	if exts.StructVersion != 1 || exts.TCBVersion != kds.TCBVersion(tcb) {
		t.Errorf("extensions = version %d, TCB %v; want version 1, TCB %v", exts.StructVersion, exts.TCBVersion, tcb)
	}
	if !bytes.Equal(exts.HWID, b.HWID[:abi.TurinSiliconIDSize]) {
		t.Errorf("HWID = %x, want the 8-byte silicon ID %x", exts.HWID, b.HWID[:abi.TurinSiliconIDSize])
	}

	// A certificate must use the members of its own struct version.
	for name, extensions := range map[string][]pkix.Extension{
		"version 0 with FmcSpl": append(CustomExtensionsV0(kds.TCBVersionV0{}, make([]byte, abi.ChipIDSize), "", "Genoa-B1"),
			pkix.Extension{Id: kds.OidFmcSpl, Value: []byte{2, 1, 0}}),
		"version 1 with Spl4": append(CustomExtensionsV1(tcb, b.HWID[:], "", "Turin-B1"),
			pkix.Extension{Id: kds.OidSpl4, Value: []byte{2, 1, 0}}),
		"version 1 with a reserved level set": CustomExtensionsV1(kds.TCBVersionV1{Spl5: 1}, b.HWID[:], "", "Turin-B1"),
		"version 1 with a level above 127":    CustomExtensionsV1(kds.TCBVersionV1{SnpSpl: 128}, b.HWID[:], "", "Turin-B1"),
	} {
		bad := &AmdSignerBuilder{ProductName: "Turin-B1", TCB: tcb, VcekCustom: CertOverride{Extensions: extensions}}
		signer, err := bad.TestOnlyCertChain()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := kds.VcekCertificateExtensions(signer.Vcek); err == nil {
			t.Errorf("%s: VcekCertificateExtensions() accepted the certificate", name)
		}
	}
}
