package obfs

func init() {
	register("http_post", newHttpPost)
}

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: 0,
		methodGet:      false,
	}
	return t
}
