package sig

import (
	"slices"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// The template's AMQP port 5673 got the technology "RabbitMQ Management"
// (msg E6). The broker is RabbitMQ; the management panel is an HTTP page.
func TestAMQPIsNotTheManagementPanel(t *testing.T) {
	e, err := NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{5672, 5673} {
		svc := &model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "amqp", Product: "RabbitMQ", Version: "3.13.7", Confidence: 10}
		m, techs, classes := e.Match(svc)
		for _, tc := range techs {
			if tc.Name == "RabbitMQ Management" {
				t.Errorf("port %d: technology %q", port, tc.Name)
			}
		}
		if slices.Contains(classes, "admin-panel") || slices.Contains(classes, "login") {
			t.Errorf("port %d: AMQP got panel classes %v (matches %+v)", port, classes, m)
		}
	}
}
