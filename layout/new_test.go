package layout_test

import (
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"

	"github.com/buildpacks/imgutil"
	"github.com/buildpacks/imgutil/index"
	"github.com/buildpacks/imgutil/layout"
	h "github.com/buildpacks/imgutil/testhelpers"
)

func TestRemoteNew(t *testing.T) {
	spec.Run(t, "RemoteNew", testRemoteNew, spec.Parallel(), spec.Report(report.Terminal{}))
}

var (
	repoName = "some/index"
)

func testRemoteNew(t *testing.T, when spec.G, it spec.S) {
	var (
		idx     imgutil.ImageIndex
		xdgPath string
		err     error
	)

	it.Before(func() {
		// creates the directory to save all the OCI images on disk
		xdgPath, err = os.MkdirTemp("", "image-indexes")
		h.AssertNil(t, err)
	})

	it.After(func() {
		err := os.RemoveAll(xdgPath)
		h.AssertNil(t, err)
	})

	when("#NewIndex", func() {
		it.Before(func() {
			idx, err = index.NewIndex(
				repoName,
				index.WithFormat(types.OCIImageIndex),
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)
		})
		it("should have expected indexOptions", func() {
			idx, err = layout.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.ManifestHandler)
			h.AssertEq(t, ok, true)
			h.AssertEq(t, imgIdx.Options.Reponame, repoName)
			h.AssertEq(t, imgIdx.Options.XdgPath, xdgPath)
		})
		it("should return an error when invalid repoName is passed", func() {
			idx, err = layout.NewIndex(
				repoName+"Image",
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNotEq(t, err, nil)
			h.AssertNil(t, idx)
		})
		it("should return ImageIndex with expected output", func() {
			idx, err = layout.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)
			h.AssertNotEq(t, idx, nil)
		})
		it("should able to call #ImageIndex", func() {
			idx, err = layout.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.ManifestHandler)
			h.AssertEq(t, ok, true)

			hash, err := v1.NewHash("sha256:0bcc1b827b855c65eaf6e031e894e682b6170160b8a676e1df7527a19d51fb1a")
			h.AssertNil(t, err)

			_, err = imgIdx.ImageIndex.ImageIndex(hash)
			h.AssertNotEq(t, err.Error(), "empty index")
		})
		it("should able to call #Image", func() {
			idx, err = layout.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.ManifestHandler)
			h.AssertEq(t, ok, true)

			hash, err := v1.NewHash("sha256:0bcc1b827b855c65eaf6e031e894e682b6170160b8a676e1df7527a19d51fb1a")
			h.AssertNil(t, err)

			_, err = imgIdx.ImageIndex.Image(hash)
			h.AssertNotEq(t, err.Error(), "empty index")
		})
	})
}
