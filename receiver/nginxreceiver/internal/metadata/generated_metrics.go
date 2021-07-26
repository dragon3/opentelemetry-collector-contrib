// Copyright The OpenTelemetry Authors
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

// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/model/pdata"
)

// Type is the component type name.
const Type config.Type = "nginxreceiver"

// MetricIntf is an interface to generically interact with generated metric.
type MetricIntf interface {
	Name() string
	New() pdata.Metric
	Init(metric pdata.Metric)
}

// Intentionally not exposing this so that it is opaque and can change freely.
type metricImpl struct {
	name     string
	initFunc func(pdata.Metric)
}

// Name returns the metric name.
func (m *metricImpl) Name() string {
	return m.name
}

// New creates a metric object preinitialized.
func (m *metricImpl) New() pdata.Metric {
	metric := pdata.NewMetric()
	m.Init(metric)
	return metric
}

// Init initializes the provided metric object.
func (m *metricImpl) Init(metric pdata.Metric) {
	m.initFunc(metric)
}

type metricStruct struct {
	NginxConnectionsAccepted MetricIntf
	NginxConnectionsCurrent  MetricIntf
	NginxConnectionsHandled  MetricIntf
	NginxRequests            MetricIntf
}

// Names returns a list of all the metric name strings.
func (m *metricStruct) Names() []string {
	return []string{
		"nginx.connections_accepted",
		"nginx.connections_current",
		"nginx.connections_handled",
		"nginx.requests",
	}
}

var metricsByName = map[string]MetricIntf{
	"nginx.connections_accepted": Metrics.NginxConnectionsAccepted,
	"nginx.connections_current":  Metrics.NginxConnectionsCurrent,
	"nginx.connections_handled":  Metrics.NginxConnectionsHandled,
	"nginx.requests":             Metrics.NginxRequests,
}

func (m *metricStruct) ByName(n string) MetricIntf {
	return metricsByName[n]
}

func (m *metricStruct) FactoriesByName() map[string]func(pdata.Metric) {
	return map[string]func(pdata.Metric){
		Metrics.NginxConnectionsAccepted.Name(): Metrics.NginxConnectionsAccepted.Init,
		Metrics.NginxConnectionsCurrent.Name():  Metrics.NginxConnectionsCurrent.Init,
		Metrics.NginxConnectionsHandled.Name():  Metrics.NginxConnectionsHandled.Init,
		Metrics.NginxRequests.Name():            Metrics.NginxRequests.Init,
	}
}

// Metrics contains a set of methods for each metric that help with
// manipulating those metrics.
var Metrics = &metricStruct{
	&metricImpl{
		"nginx.connections_accepted",
		func(metric pdata.Metric) {
			metric.SetName("nginx.connections_accepted")
			metric.SetDescription("The total number of accepted client connections")
			metric.SetUnit("connections")
			metric.SetDataType(pdata.MetricDataTypeSum)
			metric.Sum().SetIsMonotonic(true)
			metric.Sum().SetAggregationTemporality(pdata.AggregationTemporalityCumulative)
		},
	},
	&metricImpl{
		"nginx.connections_current",
		func(metric pdata.Metric) {
			metric.SetName("nginx.connections_current")
			metric.SetDescription("The current number of nginx connections by state")
			metric.SetUnit("connections")
			metric.SetDataType(pdata.MetricDataTypeGauge)
		},
	},
	&metricImpl{
		"nginx.connections_handled",
		func(metric pdata.Metric) {
			metric.SetName("nginx.connections_handled")
			metric.SetDescription("The total number of handled connections. Generally, the parameter value is the same as nginx.connections_accepted unless some resource limits have been reached (for example, the worker_connections limit).")
			metric.SetUnit("connections")
			metric.SetDataType(pdata.MetricDataTypeSum)
			metric.Sum().SetIsMonotonic(true)
			metric.Sum().SetAggregationTemporality(pdata.AggregationTemporalityCumulative)
		},
	},
	&metricImpl{
		"nginx.requests",
		func(metric pdata.Metric) {
			metric.SetName("nginx.requests")
			metric.SetDescription("Total number of requests made to the server since it started")
			metric.SetUnit("requests")
			metric.SetDataType(pdata.MetricDataTypeSum)
			metric.Sum().SetIsMonotonic(true)
			metric.Sum().SetAggregationTemporality(pdata.AggregationTemporalityCumulative)
		},
	},
}

// M contains a set of methods for each metric that help with
// manipulating those metrics. M is an alias for Metrics
var M = Metrics

// Labels contains the possible metric labels that can be used.
var Labels = struct {
	// State (The state of a connection)
	State string
}{
	"state",
}

// L contains the possible metric labels that can be used. L is an alias for
// Labels.
var L = Labels

// LabelState are the possible values that the label "state" can have.
var LabelState = struct {
	Active  string
	Reading string
	Writing string
	Waiting string
}{
	"active",
	"reading",
	"writing",
	"waiting",
}
