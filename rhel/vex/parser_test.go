package vex

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"

	"github.com/quay/zlog"

	"github.com/quay/claircore/toolkit/types/csaf"
)

func TestCreatePackageModule(t *testing.T) {
	testcases := []struct {
		name           string
		in             *csaf.Product
		expectedModule string
		err            bool
	}{
		{
			name: "simple",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "pkg:rpmmod/redhat/postgresql@13:8060020240903094008:ad008a3a",
				},
			},
			expectedModule: "postgresql:13",
		},
		{
			name: "with minor",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "pkg:rpmmod/redhat/postgresql@9.2:8060020240903094008:ad008a3a",
				},
			},
			expectedModule: "postgresql:9.2",
		},
		{
			name: "no colon",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "pkg:rpmmod/redhat/postgresql@9",
				},
			},
			expectedModule: "postgresql:9",
		},
		{
			name: "unconventional",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "pkg:rpmmod/redhat/postgresql:15/postgresql",
				},
			},
			expectedModule: "postgresql:15",
		},
		{
			name: "invalid purl",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "invalid",
				},
			},
			err: true,
		},
		{
			name: "non Red Hat PURL",
			in: &csaf.Product{
				IdentificationHelper: map[string]string{
					"purl": "pkg:rpmmod/oracle/postgresql@9",
				},
			},
			err: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			modName, err := createPackageModule(tc.in)
			if err != nil && !tc.err {
				t.Errorf("expected no error but got %q", err)
			}
			if modName != tc.expectedModule {
				t.Errorf("expected %s but got %s", tc.expectedModule, modName)
			}
		})
	}
}

func TestWalkRelationships(t *testing.T) {
	testcases := []struct {
		name                                               string
		in                                                 string
		c                                                  *csaf.CSAF
		expectedPkgName, expectedModName, expectedRepoName string
		err                                                bool
	}{
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{},
			},
			in:               "EAP 7.4 log4j async",
			expectedPkgName:  "",
			expectedModName:  "",
			expectedRepoName: "",
			name:             "no_relationship",
			err:              true,
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "fence-agents-common-0:4.10.0-62.el9_4.3.noarch as a component of Red Hat Enterprise Linux ResilientStorage (v. 9)",
								ID:   "ResilientStorage-9.4.0.Z.MAIN.EUS:fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
							},
							ProductRef:          "fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
							RelatesToProductRef: "ResilientStorage-9.4.0.Z.MAIN.EUS",
						},
					},
				},
			},
			in:               "ResilientStorage-9.4.0.Z.MAIN.EUS:fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
			expectedPkgName:  "fence-agents-common-0:4.10.0-62.el9_4.3.noarch",
			expectedModName:  "",
			expectedRepoName: "ResilientStorage-9.4.0.Z.MAIN.EUS",
			name:             "simple_relationship",
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "httpd:2.4:8100020240612075645:489197e6 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6",
							},
							ProductRef:          "httpd:2.4:8100020240612075645:489197e6",
							RelatesToProductRef: "AppStream-8.10.0.Z.MAIN.EUS",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64 as a component of httpd:2.4:8100020240612075645:489197e6 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6:httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
							},
							ProductRef:          "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
							RelatesToProductRef: "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6",
						},
					},
				},
			},
			in:               "AppStream-8.10.0.Z.MAIN.EUS:httpd:2.4:8100020240612075645:489197e6:httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
			expectedPkgName:  "httpd-0:2.4.37-65.module+el8.10.0+21982+14717793.aarch64",
			expectedModName:  "httpd:2.4:8100020240612075645:489197e6",
			expectedRepoName: "AppStream-8.10.0.Z.MAIN.EUS",
			name:             "two_level_relationship",
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of cros OS",
								ID:   "J-COMP:JMC",
							},
							ProductRef:          "JMC",
							RelatesToProductRef: "J-COMP",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of J mod",
								ID:   "CROS:J-MOD",
							},
							ProductRef:          "J-MOD",
							RelatesToProductRef: "CROS",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "jmc package as part of J-mod as part of J-COMP as part of cros OS",
								ID:   "CROS:J-MOD:J-COMP:JMC",
							},
							ProductRef:          "J-COMP:JMC",
							RelatesToProductRef: "CROS:J-MOD",
						},
					},
				},
			},
			in:               "CROS:J-MOD:J-COMP:JMC",
			expectedPkgName:  "JMC",
			expectedModName:  "J-MOD",
			expectedRepoName: "CROS",
			name:             "two_times_two_level_relationship",
		},
		{
			c: &csaf.CSAF{
				ProductTree: csaf.ProductBranch{
					Relationships: csaf.Relationships{
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "perl:5.32:8100020240314121426:9fe1d287 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.GA:perl:5.32:8100020240314121426:9fe1d287",
							},
							ProductRef:          "perl:5.32:8100020240314121426:9fe1d287",
							RelatesToProductRef: "AppStream-8.10.0.GA",
						},
						csaf.Relationship{
							Category: "default_component_of",
							FullProductName: csaf.Product{
								Name: "perl-Carp-0:1.50-439.module+el8.10.0+21354+3ad137bb.noarch as a component of perl:5.32:8100020240314121426:9fe1d287 as a component of Red Hat Enterprise Linux AppStream (v. 8)",
								ID:   "AppStream-8.10.0.GA:perl:5.32:8100020240314121426:9fe1d287:perl-Carp-0:1.50-439.module+el8.10.0+21354+3ad137bb.noarch",
							},
							ProductRef:          "perl-Carp-0:1.50-439.module+el8.10.0+21354+3ad137bb.noarch",
							RelatesToProductRef: "AppStream-8.10.0.GA:perl:5.32:8100020240314121426:9fe1d287",
						},
					},
				},
			},
			in:               "AppStream-8.10.0.GA:perl:5.32:8100020240314121426:9fe1d287:perl-Carp-0:1.50-439.module+el8.10.0+21354+3ad137bb.noarch",
			expectedPkgName:  "perl-Carp-0:1.50-439.module+el8.10.0+21354+3ad137bb.noarch",
			expectedModName:  "perl:5.32:8100020240314121426:9fe1d287",
			expectedRepoName: "AppStream-8.10.0.GA",
			name:             "perl_module_relationships",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pkgName, modName, repoName, err := walkRelationships(tc.in, tc.c)
			if err != nil && !tc.err {
				t.Errorf("expected no error but got %q", err)
			}
			if pkgName != tc.expectedPkgName {
				t.Errorf("expected %s but got %s", tc.expectedPkgName, pkgName)
			}
			if modName != tc.expectedModName {
				t.Errorf("expected %s but got %s", tc.expectedModName, modName)
			}
			if repoName != tc.expectedRepoName {
				t.Errorf("expected %s but got %s", tc.expectedRepoName, repoName)
			}
		})
	}
}

func TestEscapeCPE(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "wildcard version",
			in:   "cpe:/a:redhat:openshift:4.*",
			want: "cpe:/a:redhat:openshift:4.%02",
		},
		{
			name: "product with a wildcard",
			in:   "cpe:/a:redhat:astarry.*.comp:4.*",
			want: "cpe:/a:redhat:astarry.*.comp:4.%02",
		},
		{
			name: "version with question",
			in:   "cpe:/a:redhat:openshift:4.?::el8",
			want: "cpe:/a:redhat:openshift:4.%01::el8",
		},
		{
			name: "question mark can be anywhere",
			in:   "cpe:/a:redhat:openshift:4.?.10::el8",
			want: "cpe:/a:redhat:openshift:4.%01.10::el8",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			out := escapeCPE(tc.in)
			if out != tc.want {
				t.Errorf("expected %s but got %s", tc.want, out)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	url, err := url.Parse(BaseURL)
	if err != nil {
		t.Error(err)
	}

	testcases := []struct {
		name            string
		filename        string
		expectedVulns   int
		expectedDeleted int
	}{
		{
			name:            "six_advisories_four_deletions",
			filename:        "testdata/example_vex.jsonl",
			expectedVulns:   546,
			expectedDeleted: 4,
		},
		{
			name:            "cve-2022-1705",
			filename:        "testdata/cve-2022-1705.jsonl",
			expectedVulns:   736,
			expectedDeleted: 0,
		},
		{
			name:            "cve-2024-24786",
			filename:        "testdata/cve-2024-24786.jsonl",
			expectedVulns:   246,
			expectedDeleted: 0,
		},
		{
			name:            "cve-2022-38752",
			filename:        "testdata/cve-2022-38752.jsonl",
			expectedVulns:   40,
			expectedDeleted: 0,
		},
		{
			name:            "cve-2024-7348",
			filename:        "testdata/cve-2024-7348.jsonl",
			expectedVulns:   910,
			expectedDeleted: 0,
		},
	}

	u := &Updater{url: url, client: http.DefaultClient}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			f, err := os.Open(tc.filename)
			if err != nil {
				t.Fatalf("failed to open test data file %s: %v", tc.filename, err)
			}

			// Ideally, you'd just use snappy.Encode() but apparently
			// the stream format and the block format are not interchangeable:
			// https://pkg.go.dev/github.com/klauspost/compress/snappy#Writer.
			b, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read file bytes: %v", err)
			}
			var buf bytes.Buffer
			sw := snappy.NewBufferedWriter(&buf)
			bLen, err := sw.Write(b)
			if err != nil {
				t.Fatalf("error writing snappy data to buffer: %v", err)
			}
			if bLen != len(b) {
				t.Errorf("didn't write the correct # of bytes")
			}
			if err = sw.Close(); err != nil {
				t.Errorf("failed to close snappy Writer: %v", err)
			}

			vulns, deleted, err := u.DeltaParse(ctx, io.NopCloser(&buf))
			if err != nil {
				t.Fatalf("failed to parse CSAF JSON: %v", err)
			}
			if len(vulns) != tc.expectedVulns {
				t.Fatalf("expected %d vulns but got %d", tc.expectedVulns, len(vulns))
			}
			if len(deleted) != tc.expectedDeleted {
				t.Fatalf("expected %d deleted but got %d", tc.expectedDeleted, len(deleted))
			}
		})
	}
}
