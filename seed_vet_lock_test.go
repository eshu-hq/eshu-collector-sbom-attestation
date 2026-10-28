// SPDX-License-Identifier: MIT
// SEED (close unmerged): intentional copylocks violation to prove the lint lane fails.
package collector

import "sync"

func seedReturnsLock() sync.Mutex {
	var mu sync.Mutex
	return mu
}

var _ = seedReturnsLock
