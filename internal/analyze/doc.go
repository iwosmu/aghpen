// Package analyze turns raw scan results into what the analyst reads:
// the availability (stability) model, the diff between two runs, the interest
// score, the grouping key and the derived findings.
//
// Every function here is pure: no database, no network, no clock. Inputs and
// outputs are internal/model types, plus a few small input structs defined in
// this package where the model has none. The store calls these functions after
// a run and persists what they return.
//
// The order the store uses after a run:
//
//  1. Profile.Add + Assess for every host the run probed (stability.go);
//     ApplyToHost copies the status, p_alive, stability and pattern.
//  2. Diff(prev, cur) with the host statuses from step 1 (diff.go).
//  3. AssignGroupKeys over all services, then Interest per service with the
//     group size (group.go, interest.go).
//  4. DeriveFindings per host; upsert by Finding.Key (findings.go).
package analyze
