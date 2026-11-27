package organizationunit

import "testing"

func TestNodeTypeAcceptsProductVocabularyAndReservesCompanyRoot(t *testing.T) {
	for _, value := range []NodeType{"region", "store", "venue_zone", "floor_2"} {
		if !value.ValidDeliveryChild() {
			t.Fatalf("product node type %q was rejected", value)
		}
	}
	for _, value := range []NodeType{"", "company", "Venue", "venue-zone", "venue_", " venue"} {
		if value.ValidDeliveryChild() {
			t.Fatalf("invalid child node type %q was accepted", value)
		}
	}
}
