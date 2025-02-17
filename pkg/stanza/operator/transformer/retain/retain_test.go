package retain

// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/entry"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/testutil"
)

type testCase struct {
	name      string
	expectErr bool
	op        *RetainOperatorConfig
	input     func() *entry.Entry
	output    func() *entry.Entry
}

func TestBuildAndProcess(t *testing.T) {
	now := time.Now()
	newTestEntry := func() *entry.Entry {
		e := entry.New()
		e.ObservedTimestamp = now
		e.Timestamp = time.Unix(1586632809, 0)
		e.Body = map[string]interface{}{
			"key": "val",
			"nested": map[string]interface{}{
				"nestedkey": "nestedval",
			},
		}
		return e
	}

	cases := []testCase{
		{
			"retain_single",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("key"))
				return cfg
			}(),
			newTestEntry,
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"key": "val",
				}
				return e
			},
		},
		{
			"retain_multi",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("key"))
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("nested2"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"key": "val",
					"nested": map[string]interface{}{
						"nestedkey": "nestedval",
					},
					"nested2": map[string]interface{}{
						"nestedkey": "nestedval",
					},
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"key": "val",
					"nested2": map[string]interface{}{
						"nestedkey": "nestedval",
					},
				}
				return e
			},
		},
		{
			"retain_multilevel",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("foo"))
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("one", "two"))
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("foo"))
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("one", "two"))
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("foo"))
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("one", "two"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
						"deleteme": "yes",
					},
					"hello": "world",
				}
				e.Attributes = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
						"deleteme": "yes",
					},
					"hello": "world",
				}
				e.Resource = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
						"deleteme": "yes",
					},
					"hello": "world",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
					},
				}
				e.Attributes = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
					},
				}
				e.Resource = map[string]interface{}{
					"foo": "bar",
					"one": map[string]interface{}{
						"two": map[string]interface{}{
							"keepme": 1,
						},
					},
				}
				return e
			},
		},
		{
			"retain_nest",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("nested2"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"key": "val",
					"nested": map[string]interface{}{
						"nestedkey": "nestedval",
					},
					"nested2": map[string]interface{}{
						"nestedkey": "nestedval",
					},
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"nested2": map[string]interface{}{
						"nestedkey": "nestedval",
					},
				}
				return e
			},
		},
		{
			"retain_nested_value",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("nested2", "nestedkey2"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"key": "val",
					"nested": map[string]interface{}{
						"nestedkey": "nestedval",
					},
					"nested2": map[string]interface{}{
						"nestedkey2": "nestedval",
					},
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = map[string]interface{}{
					"nested2": map[string]interface{}{
						"nestedkey2": "nestedval",
					},
				}
				return e
			},
		},
		{
			"retain_single_attribute",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("key"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Attributes = map[string]interface{}{
					"key": "val",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Attributes = map[string]interface{}{
					"key": "val",
				}
				return e
			},
		},
		{
			"retain_multi_attribute",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("key1"))
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("key2"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Attributes = map[string]interface{}{
					"key1": "val",
					"key2": "val",
					"key3": "val",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Attributes = map[string]interface{}{
					"key1": "val",
					"key2": "val",
				}
				return e
			},
		},
		{
			"retain_single_resource",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("key"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key": "val",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key": "val",
				}
				return e
			},
		},
		{
			"retain_multi_resource",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("key1"))
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("key2"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key1": "val",
					"key2": "val",
					"key3": "val",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key1": "val",
					"key2": "val",
				}
				return e
			},
		},
		{
			"retain_one_of_each",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewResourceField("key1"))
				cfg.Fields = append(cfg.Fields, entry.NewAttributeField("key3"))
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("key"))
				return cfg
			}(),
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key1": "val",
					"key2": "val",
				}
				e.Attributes = map[string]interface{}{
					"key3": "val",
					"key4": "val",
				}
				return e
			},
			func() *entry.Entry {
				e := newTestEntry()
				e.Resource = map[string]interface{}{
					"key1": "val",
				}
				e.Attributes = map[string]interface{}{
					"key3": "val",
				}
				e.Body = map[string]interface{}{
					"key": "val",
				}
				return e
			},
		},
		{
			"retain_a_non_existent_key",
			false,
			func() *RetainOperatorConfig {
				cfg := defaultCfg()
				cfg.Fields = append(cfg.Fields, entry.NewBodyField("aNonExsistentKey"))
				return cfg
			}(),
			newTestEntry,
			func() *entry.Entry {
				e := newTestEntry()
				e.Body = nil
				return e
			},
		},
	}
	for _, tc := range cases {
		t.Run("BuildandProcess/"+tc.name, func(t *testing.T) {
			cfg := tc.op
			cfg.OutputIDs = []string{"fake"}
			cfg.OnError = "drop"
			op, err := cfg.Build(testutil.Logger(t))
			require.NoError(t, err)

			retain := op.(*RetainOperator)
			fake := testutil.NewFakeOutput(t)
			require.NoError(t, retain.SetOutputs([]operator.Operator{fake}))
			val := tc.input()
			err = retain.Process(context.Background(), val)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				fake.ExpectEntry(t, tc.output())
			}
		})
	}
}
