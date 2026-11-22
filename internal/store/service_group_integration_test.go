package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A deep page of GET /services and the services export stay fast when one
// group is large (all nginx services of a dense network are one group). The
// old count per row took 13-38 s for the deep page of the 10 000-host lab.
func TestServiceListDeepPageWithALargeGroup(t *testing.T) {
	st := storetest.New(t)
	var hosts []model.HostResult
	for i := 0; i < 1500; i++ {
		h := model.HostResult{IP: fmt.Sprintf("10.90.%d.%d", i/250, i%250+1), Up: true}
		for _, p := range []int{22, 80, 443, 8080} {
			h.Services = append(h.Services, model.ServiceResult{Port: p, Proto: "tcp", State: "open", Name: "http"})
		}
		hosts = append(hosts, h)
	}
	if err := st.IngestHosts(ctx, hosts, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE services SET group_key = CASE WHEN port = 22 THEN '' ELSE 'g-web' END`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	page, err := st.ListServices(ctx, store.ServiceFilter{ListOpts: store.ListOpts{Limit: 50, Offset: 5940}})
	took := time.Since(start)
	if err != nil || page.Total != 6000 || len(page.Items) != 50 {
		t.Fatalf("deep page: %v total %d items %d", err, page.Total, len(page.Items))
	}
	if took > time.Second { // 78 ms with one count per group, 2.6 s with a count per row
		t.Errorf("deep page took %s", took)
	}
	t.Logf("deep page of 6000 services, one group of 4500: %s", took)
	for _, s := range page.Items {
		want := map[bool]int{true: 0, false: 4500}[s.Port == 22]
		if s.GroupSize != want {
			t.Errorf("%s:%d group size %d, want %d", s.IP, s.Port, s.GroupSize, want)
		}
	}
	// a filter does not shrink the group: the size counts the whole inventory
	one, err := st.ListServices(ctx, store.ServiceFilter{Port: 80, ListOpts: store.ListOpts{Limit: 1}})
	if err != nil || len(one.Items) != 1 || one.Items[0].GroupSize != 4500 {
		t.Fatalf("filtered: %v %+v", err, one.Items)
	}
	got, err := st.GetService(ctx, one.Items[0].ID, false)
	if err != nil || got.GroupSize != 4500 {
		t.Fatalf("get: %v %d", err, got.GroupSize)
	}
	start = time.Now()
	n := 0
	if err := st.EachService(ctx, store.ServiceFilter{}, func(*model.Service) error { n++; return nil }); err != nil || n != 6000 {
		t.Fatalf("export: %v %d", err, n)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("export of 6000 services took %s", took)
	}
}
