package scanner

// top100Ports is a curated list of the ports most likely to be
// interesting on a general-purpose host, loosely modeled on well-known
// "top ports" lists but hand-picked to keep this file dependency-free
// (no embedded third-party port-frequency database). Good enough for a
// fast default sweep; use --ports for anything exhaustive.
var top100Ports = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
	113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
	513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
	1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
	2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
	5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
	5900, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
	8443, 8888, 9000, 9100, 9999, 10000, 27017, 32768, 49152, 49153,
	49154, 49155, 49156, 49157,
}

// ResolvePortPreset is the exported form of resolvePortPreset, for
// testability.
func ResolvePortPreset(name string) []int {
	return resolvePortPreset(name)
}

// resolvePortPreset expands the named preset into a concrete port list.
// "top1000" is implemented as the contiguous range 1-1000 rather than a
// curated frequency list — a pragmatic simplification (documented here,
// not hidden) since a real top-1000 list is a large embedded dataset
// we'd rather not hand-maintain for a practice build.
func resolvePortPreset(name string) []int {
	switch name {
	case "top1000":
		ports := make([]int, 1000)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	case "top100", "":
		return top100Ports
	default:
		return top100Ports
	}
}
