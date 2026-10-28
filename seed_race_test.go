// SPDX-License-Identifier: MIT
// SEED (close unmerged): intentional data race to prove the race lane fails.
package collector

import (
	"sync"
	"testing"
)

func TestSeedIntentionalRace(t *testing.T) {
	t.Parallel()
	var n int
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				n++
			}
		}()
	}
	wg.Wait()
	_ = n
}
