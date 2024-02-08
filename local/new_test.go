package local_test

import (
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"

	"github.com/buildpacks/imgutil"
	"github.com/buildpacks/imgutil/index"
	"github.com/buildpacks/imgutil/local"
	h "github.com/buildpacks/imgutil/testhelpers"
)

func TestRemoteNew(t *testing.T) {
	spec.Run(t, "RemoteNew", testRemoteNew, spec.Sequential(), spec.Report(report.Terminal{}))
}

var (
	xdgPath  = "xdgPath"
	repoName = "some/index"
)

func testRemoteNew(t *testing.T, when spec.G, it spec.S) {
	when("#NewIndex", func() {
		it.Before(func() {
			_, err := index.NewIndex(
				repoName,
				index.WithFormat(types.DockerManifestList),
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)
		})
		it.After(func() {
			it.After(func() {
				err := os.RemoveAll(xdgPath)
				h.AssertNil(t, err)
			})
		})
		it("should have expected indexOptions", func() {
			idx, err := local.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.Index)
			h.AssertEq(t, ok, true)
			h.AssertEq(t, imgIdx.Options.Reponame, repoName)
			h.AssertEq(t, imgIdx.Options.XdgPath, xdgPath)
		})
		it("should return an error when invalid repoName is passed", func() {
			idx, err := local.NewIndex(
				repoName+"Image",
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNotEq(t, err, nil)
			h.AssertNil(t, idx)
		})
		it("should return ImageIndex with expected output", func() {
			idx, err := local.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)
			h.AssertNotEq(t, idx, nil)
		})
		it("should able to call #ImageIndex", func() {
			idx, err := local.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.Index)
			h.AssertEq(t, ok, true)

			_, err = imgIdx.ImageIndex.ImageIndex(v1.Hash{})
			h.AssertNotEq(t, err.Error(), "empty index")
		})
		it("should able to call #Image", func() {
			idx, err := local.NewIndex(
				repoName,
				index.WithXDGRuntimePath(xdgPath),
			)
			h.AssertNil(t, err)

			imgIdx, ok := idx.(*imgutil.Index)
			h.AssertEq(t, ok, true)

			_, err = imgIdx.Image(v1.Hash{})
			h.AssertNotEq(t, err.Error(), "empty index")
		})
	})
}