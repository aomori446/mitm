package interceptor

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
)

// RespondWith403 returns a [BlockResponse] that sends 403 Forbidden.
func RespondWith403() BlockResponse {
	return func(_ *http.Request) *http.Response {
		return Response(http.StatusForbidden, "", http.NoBody)
	}
}

// RespondWithPixel returns a [BlockResponse] that sends a 1×1 transparent GIF.
// Useful for silently replacing blocked image requests without causing browser errors.
func RespondWithPixel() BlockResponse {
	return func(_ *http.Request) *http.Response {
		b := gifPixel()
		resp := Response(http.StatusOK, "image/gif", io.NopCloser(bytes.NewReader(b)))
		resp.ContentLength = int64(len(b))
		return resp
	}
}

// RespondWithEmptyJS returns a [BlockResponse] that sends an empty JavaScript response.
func RespondWithEmptyJS() BlockResponse {
	const body = "//"
	return func(_ *http.Request) *http.Response {
		resp := Response(http.StatusOK, "application/javascript", io.NopCloser(strings.NewReader(body)))
		resp.ContentLength = int64(len(body))
		return resp
	}
}

// RespondWithEmptyCSS returns a [BlockResponse] that sends an empty CSS response.
func RespondWithEmptyCSS() BlockResponse {
	return func(_ *http.Request) *http.Response {
		return Response(http.StatusOK, "text/css", http.NoBody)
	}
}

// RespondWithEmptyHTML returns a [BlockResponse] that sends a minimal HTML response.
func RespondWithEmptyHTML() BlockResponse {
	const body = "<html></html>"
	return func(_ *http.Request) *http.Response {
		resp := Response(http.StatusOK, "text/html; charset=utf-8", io.NopCloser(strings.NewReader(body)))
		resp.ContentLength = int64(len(body))
		return resp
	}
}

// RespondWithAuto returns a [BlockResponse] that infers the appropriate empty
// response from the request URL's file extension.
//
//   - .gif .png .jpg .jpeg .webp .ico .svg → 1×1 transparent GIF
//   - .js .mjs                             → empty JS (//)
//   - .css                                 → empty CSS
//   - .html .htm                           → empty HTML
//   - (other)                              → 200 empty body
func RespondWithAuto() BlockResponse {
	pixel := RespondWithPixel()
	js := RespondWithEmptyJS()
	css := RespondWithEmptyCSS()
	html := RespondWithEmptyHTML()

	return func(req *http.Request) *http.Response {
		switch strings.ToLower(path.Ext(req.URL.Path)) {
		case ".gif", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".svg":
			return pixel(req)
		case ".js", ".mjs":
			return js(req)
		case ".css":
			return css(req)
		case ".html", ".htm":
			return html(req)
		default:
			return Response(http.StatusOK, "", http.NoBody)
		}
	}
}

// gifPixel returns the bytes of a 1×1 transparent GIF, computed once.
var gifPixel = sync.OnceValue(func() []byte {
	img := image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.Transparent})
	var buf bytes.Buffer
	_ = gif.Encode(&buf, img, nil)
	return buf.Bytes()
})
