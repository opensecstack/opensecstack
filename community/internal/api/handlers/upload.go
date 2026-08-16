// Wire in server.go:
//   mux.Handle("POST /api/v1/upload", auth(http.HandlerFunc(handlers.UploadImage(d))))
//   mux.Handle("GET /uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(cfg.UploadDir))))

package handlers

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif" // register GIF decoder
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // register WebP decoder
)

const maxUploadSize = 5 << 20 // 5 MB

var allowedMIME = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/gif":  "gif",
	"image/webp": "webp",
}

// processImage decodes an image from data, resizes it to a maximum width of
// 1200px (preserving aspect ratio), and re-encodes it as JPEG at quality 85.
// If the image cannot be decoded (e.g. unsupported format), a non-nil error is
// returned and the caller should fall back to saving the original bytes as-is.
func processImage(data []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds()
	origW := bounds.Max.X - bounds.Min.X
	origH := bounds.Max.Y - bounds.Min.Y

	var dst = img
	if origW > 1200 {
		newW := 1200
		newH := origH * newW / origW
		resized := image.NewRGBA(image.Rect(0, 0, newW, newH))
		draw.BiLinear.Scale(resized, resized.Bounds(), img, img.Bounds(), draw.Over, nil)
		dst = resized
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func UploadImage(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+512)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid form"})
			return
		}

		file, _, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file field"})
			return
		}
		defer file.Close()

		// Read the entire file into memory so we can both detect its type and
		// pass it to the image processor.
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read file"})
			return
		}

		// Detect content-type from the first 512 bytes.
		sniff := fileBytes
		if len(sniff) > 512 {
			sniff = sniff[:512]
		}
		detected := http.DetectContentType(sniff)

		// The extension (and therefore whether the upload is accepted at all) is
		// decided solely from the sniffed content-type (detected from the actual
		// bytes), never from the client-supplied Content-Type header. The header
		// is fully attacker-controlled — trusting it would let a client label
		// arbitrary bytes (HTML/SVG/script content) as e.g. "image/png" and have
		// them saved to disk unprocessed, since processImage falls back to saving
		// the original bytes verbatim whenever decoding fails.
		ext, ok := allowedMIME[detected]
		if !ok {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": fmt.Sprintf("unsupported image type: %s", detected),
			})
			return
		}

		// Attempt image optimization: resize to max 1200px wide and re-encode
		// as JPEG at 85% quality.  If this fails (e.g. animated GIF, SVG that
		// snuck through), fall back to saving the original bytes unchanged.
		saveBytes := fileBytes
		if processed, err := processImage(fileBytes); err == nil {
			saveBytes = processed
			ext = "jpg"
		}

		uploadDir := d.Cfg.UploadDir
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create upload directory"})
			return
		}

		id := uuid.New().String()
		filename := id + "." + ext
		dest := filepath.Join(uploadDir, filename)

		if err := os.WriteFile(dest, saveBytes, 0644); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not write file"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"url": "/uploads/" + filename})
	}
}
