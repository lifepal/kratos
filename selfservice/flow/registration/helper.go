package registration

import "strings"

func getFirstNameLastName(name string) (string, string) {
	n := strings.Split(name, " ")
	if len(n) > 1 {
		return n[0], strings.Join(n[1:], " ")
	}
	return n[0], ""
}
