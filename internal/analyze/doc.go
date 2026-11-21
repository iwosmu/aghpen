// Package analyze turns raw scan results into what the analyst reads:
// the availability (stability) model, the diff between two runs, the interest
// score, the grouping key and the derived findings.
//
// Every function here is pure: no database, no network, no clock. Inputs and
// outputs are internal/model types, plus a few small input structs defined in
// this package where the model has none. The store calls these functions after
// a run and persists what they return.
package analyze
