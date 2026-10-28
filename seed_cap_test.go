// SPDX-License-Identifier: MIT
// SEED (close unmerged): covers seedCapCovered so only the cap trips.
package collector

import "testing"

func TestSeedCapCovered(t *testing.T) {
	if seedCapCovered() != 7 {
		t.Fatal("bad")
	}
}
