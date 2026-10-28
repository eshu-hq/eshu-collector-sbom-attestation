// SPDX-License-Identifier: MIT
// SEED (close unmerged): intentionally unformatted to prove the lint lane fails.
package collector

func seedBadlyFormatted() int {
        x := 1
    y := 2
        return x + y
}

var _ = seedBadlyFormatted
