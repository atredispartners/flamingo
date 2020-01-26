// +build !freebsd,!darwin,!linux

package flamingo

// IncreaseFileLimit tries to increase our available file limits to the maximum possible. Placeholder on this platform.
func IncreaseFileLimit() {
}
