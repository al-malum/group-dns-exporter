package contain

func ContainBool(listing []bool, key bool) bool {
	for _, value := range listing {
		if key == value {
			return true
		}
	}
	return false
}
func ContainString(listing []string, key string) bool {
	for _, value := range listing {
		if key == value {
			return true
		}
	}
	return false
}
