package imgutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Index interface {
	// getters

	OS(digest name.Digest) (os string, err error)
	Architecture(digest name.Digest) (arch string, err error)
	Variant(digest name.Digest) (osVariant string, err error)
	OSVersion(digest name.Digest) (osVersion string, err error)
	Features(digest name.Digest) (features []string, err error)
	OSFeatures(digest name.Digest) (osFeatures []string, err error)
	Annotations(digest name.Digest) (annotations map[string]string, err error)
	URLs(digest name.Digest) (urls []string, err error)

	// setters

	SetOS(digest name.Digest, os string) error
	SetArchitecture(digest name.Digest, arch string) error
	SetVariant(digest name.Digest, osVariant string) error
	SetOSVersion(digest name.Digest, osVersion string) error
	SetFeatures(digest name.Digest, features []string) error
	SetOSFeatures(digest name.Digest, osFeatures []string) error
	SetAnnotations(digest name.Digest, annotations map[string]string) error
	SetURLs(digest name.Digest, urls []string) error

	// misc

	Add(ref name.Reference, all bool) error
	Save() error
	Push() error
	Inspect(digest name.Digest) error
	Remove(digest name.Digest) error
	Delete() error
}

type ManifestAction int
type NewManifest map[v1.Hash][]byte

const (
	ADD ManifestAction = iota
	UPDATE
	REPLACE
	DELETE
)

type newManifestOpts struct {
	action			ManifestAction
	options			[]layout.Option
	hash 			v1.Hash
	isIndex 		bool
	image			*v1.Image
	index			*v1.Index
}

func(m *newManifestOpts) AddImage(image *v1.Image, ops ...layout.Option) error {
	m.action = ADD
	m.options = ops
	hash, err := image.Digest()
	if err != nil {
		return err
	}

	m.hash = hash
	m.image = image
	m.isIndex = false
}

func(m *newManifestOpts) AddIndex(index *v1.ImageIndex, ops ...layout.Option) error {
	m.action = ADD
	m.options = ops
	hash, err := index.Digest()
	if err != nil {
		return err
	}

	m.hash = hash
	m.index = index
	m.isIndex = true
}

func(m *newManifestOpts) Replace(hash v1.Hash, isIndex bool, ops ...layout.Option) error {
	m.action = REPLACE
	m.options = ops
	m.hash = hash
	m.isIndex = isIndex
}

func(m *newManifestOpts) Delete(hash v1.Hash, isIndex bool, ops ...layout.Option) error {
	m.action = DELETE
	m.options = ops
	m.hash = hash
	m.isIndex = isIndex
}

func(m *NewManifest) ImageManifest(hash v1.Hash) (*v1.Manifest, error) {
	manifest, ok := (*m)[hash]
	var man v1.Manifest
	if !ok {
		return &man, fmt.Errorf("Image with given Hash: %s doesn't exists", hash.String())
	}

	err := json.Unmarshal(manifest, &man)
	return &man, err
}

func(m *NewManifest) IndexManifest(hash v1.Hash) (*v1.IndexManifest, error) {
	var man v1.IndexManifest
	manifest, ok := (*m)[hash]
	if !ok {
		return &man, fmt.Errorf("ImageIndex with given Hash: %s doesn't exists", hash.String())
	}

	err := json.Unmarshal(manifest, &man)
	return &man, err
}

func(m *newManifestOpts) AddLayoutOptions(options ...layout.Option) {
	m.options = append(m.options, options...)
}

type index struct {
	keychain            authn.Keychain
	repoName            string
	index 				v1.ImageIndex
	requestedMediaTypes MediaTypes
	newIndex			map[v1.Hash][]newManifestOpts
	newManifest			NewManifest
	xdgRuntimePath		string
}

type IndexOption func(*index) error

func WithIndex(idx v1.ImageIndex) IndexOption {
	return 	func(i *index) error {
		i.index = idx
		return nil
	}
}

func WithKeyChain(keychain authn.Keychain) IndexOption {
	return 	func(i *index) error {
		i.keychain = keychain
		return nil
	}
}

func WithRepoName(repoName string) IndexOption {
	return 	func(i *index) error {
		i.repoName = repoName
		return nil
	}
}

func WithMediaTypes(mediaType MediaTypes) IndexOption {
	return 	func(i *index) error {
		i.requestedMediaTypes = mediaType
		return nil
	}
}

func WithXDGRuntimePath(path string) IndexOption {
	return 	func(i *index) error {
		i.xdgRuntimePath = path
		return nil
	}
}

func(i *index) OS(digest name.Digest) (OS string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return OS, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return OS, err
		}

		OS = manifest.Config.Platform.OS

		if OS == "" {
			return osFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}

		return OS, err
	}

	OS = manifest.Subject.Platform.OS

	if OS == "" {
		return osFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return OS, err
}

func osFromPath(repoName, xdgRuntimePath, digestStr string) (OS string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return OS, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return OS, err
		}

		return config.OS, nil
	}

	return idx.Subject.Platform.OS, nil
}

func(i *index) Architecture(digest name.Digest) (arch string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return arch, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return arch, err
		}

		arch = manifest.Config.Platform.Architecture

		if arch == "" {
			return archFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return arch, err
	}

	arch = manifest.Subject.Platform.Architecture

	if arch == "" {
		return archFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return arch, err
}

func archFromPath(repoName, xdgRuntimePath, digestStr string) (arch string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return arch, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return arch, err
		}

		return config.Architecture, nil
	}

	return idx.Subject.Platform.Architecture, nil
}

func(i *index) Variant(digest name.Digest) (osVariant string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return osVariant, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return osVariant, err
		}

		osVariant = manifest.Config.Platform.Variant

		if osVariant == "" {
			return osVariantFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return osVariant, err
	}

	osVariant = manifest.Subject.Platform.Variant

	if osVariant == "" {
		return osVariantFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return osVariant, err
}

func osVariantFromPath(repoName, xdgRuntimePath, digestStr string) (osVariant string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return osVariant, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return osVariant, err
		}

		return config.Variant, nil
	}

	return idx.Subject.Platform.Variant, nil
}

func(i *index) OSVersion(digest name.Digest) (osVersion string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return osVersion, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return osVersion, err
		}

		osVersion = manifest.Config.Platform.OSVersion

		if osVersion == "" {
			return osVersionFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return osVersion, err
	}

	osVersion = manifest.Subject.Platform.OSVersion

	if osVersion == "" {
		return osVersionFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return osVersion, err
}

func osVersionFromPath(repoName, xdgRuntimePath, digestStr string) (osVersion string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return osVersion, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return osVersion, err
		}

		return config.OSVersion, nil
	}

	return idx.Subject.Platform.OSVersion, nil
}

func(i *index) Features(digest name.Digest) (features []string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return features, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return features, err
		}

		features = manifest.Config.Platform.Features

		if features == nil {
			return featuresFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return features, err
	}

	features = manifest.Subject.Platform.Features

	if features == nil {
		return featuresFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return features, err
}

func featuresFromPath(repoName, xdgRuntimePath, digestStr string) (features []string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return features, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return features, err
		}

		return config.Platform().Features, nil
	}

	return idx.Subject.Platform.Features, nil
}

func(i *index) OSFeatures(digest name.Digest) (osFeatures []string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return osFeatures, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return osFeatures, err
		}

		osFeatures = manifest.Config.Platform.OSFeatures

		if osFeatures == nil {
			return osFeaturesFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return osFeatures, err
	}

	osFeatures = manifest.Subject.Platform.OSFeatures

	if osFeatures == nil {
		return osFeaturesFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return osFeatures, err
}

func osFeaturesFromPath(repoName, xdgRuntimePath, digestStr string) (osFeatures []string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return osFeatures, err
		}

		config, err := img.ConfigFile()
		if err != nil || config == nil {
			return osFeatures, err
		}

		return config.Platform().OSFeatures, nil
	}

	return idx.Subject.Platform.OSFeatures, nil
}

func(i *index) Annotations(digest name.Digest) (annotations map[string]string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return annotations, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return annotations, err
		}

		annotations = manifest.Config.Annotations

		if annotations == nil {
			return annotationsFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return annotations, err
	}

	annotations = manifest.Subject.Annotations

	if annotations == nil {
		return annotationsFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return annotations, err
}

func annotationsFromPath(repoName, xdgRuntimePath, digestStr string) (annotations map[string]string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return annotations, err
		}

		manifest, err := img.Manifest()
		if err != nil || manifest == nil {
			return annotations, err
		}

		return manifest.Annotations, nil
	}

	return idx.Annotations, nil
}

func(i *index) URLs(digest name.Digest) (urls []string, err error) {
	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return urls, err
	}

	manifest, err := i.newManifest.IndexManifest(hash)
	if err != nil {
		manifest, err := i.newManifest.ImageManifest(hash)
		if err != nil {
			return urls, err
		}

		urls = manifest.Config.URLs

		if urls == nil {
			return urlsFromPath(i.repoName, i.xdgRuntimePath, digestStr)
		}
	
		return urls, err
	}

	urls = manifest.Subject.URLs

	if urls == nil {
		return urlsFromPath(i.repoName, i.xdgRuntimePath, digestStr)
	}

	return urls, err
}

func urlsFromPath(repoName, xdgRuntimePath, digestStr string) (urls []string, err error) {
	idx, err := idxFromRepoName(repoName, xdgRuntimePath)
	if err != nil {
		img, err := imgFromRepoName(repoName, digestStr, xdgRuntimePath)
		if err != nil {
			return urls, err
		}

		manifest, err := img.Manifest()
		if err != nil || manifest == nil {
			return urls, err
		}

		urls = manifest.Config.URLs
		if len(urls) == 0 {
			urls = manifest.Subject.URLs
		}

		return urls, nil
	}

	return idx.Subject.URLs, nil
}

func imgFromRepoName(repoName, hashString, XDGRuntimePath string) (image v1.Image, err error) {
	idxPath, err := layoutPath(XDGRuntimePath, repoName)
	if err != nil {
		return
	}

	hash, err := v1.NewHash(hashString)
	if err != nil {
		return
	}

	image, err = idxPath.Image(hash)
	if err != nil {
		return
	}
	return
}

func idxFromRepoName(repoName, XDGRuntimePath string) (index *v1.IndexManifest, err error) {
	idxPath, err := layoutPath(XDGRuntimePath, repoName)
	if err != nil {
		return
	}

	idx, err := idxPath.ImageIndex()
	if err != nil {
		return
	}

	index, err = idx.IndexManifest()

	return
}

func layoutPath(repoName ...string) (idxPath layout.Path, err error) {
	path := filepath.Join(repoName...)
	if _, err = os.Stat(path); err != nil {
		return
	}

	return layout.Path(path), err
}

func(i *index) SetOS(digest name.Digest, os string) error {
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.OS = os
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						OS: os,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.OS = os
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					OS: os,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetArchitecture(digest name.Digest, arch string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.Architecture = arch
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						Architecture: arch,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.Architecture = arch
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					Architecture: arch,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetVariant(digest name.Digest, osVariant string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.Variant = osVariant
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						Variant: osVariant,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.Variant = osVariant
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					Variant: osVariant,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetOSVersion(digest name.Digest, osVersion string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.OSVersion = osVersion
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						OSVersion: osVersion,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.OSVersion = osVersion
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					OSVersion: osVersion,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetFeatures(digest name.Digest, features []string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.Features = features
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						Features: features,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.Features = features
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					Features: features,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetOSFeatures(digest name.Digest, osFeatures []string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Platform.OSFeatures = osFeatures
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithPlatform(
					v1.Platform{
						OSFeatures: osFeatures,
					},
				),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Platform.OSFeatures = osFeatures
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithPlatform(
				v1.Platform{
					OSFeatures: osFeatures,
				},
			),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetAnnotations(digest name.Digest, annotations map[string]string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.Annotations = annotations
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithAnnotations(annotations),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.Annotations = annotations
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithAnnotations(annotations),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) SetURLs(digest name.Digest, urls []string) error {	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	digestStr := digest.Identifier()
	hash, err := v1.NewHash(digestStr)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	imgIdx, err := idx.ImageIndex(hash)
	if err != nil {
		img, err := idx.Image(hash)
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		dupManifest := manifest.DeepCopy()

		dupManifest.Config.URLs = urls
		manifestBytes, err := json.Marshal(dupManifest)
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: REPLACE,
			options: []layout.Option{
				layout.WithURLs(urls),
			},
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	manifest, err := imgIdx.IndexManifest()
	if err != nil {
		return err
	}

	dupManifest := manifest.DeepCopy()

	dupManifest.Subject.URLs = urls
	manifestBytes, err := json.Marshal(dupManifest)
	if err != nil {
		return err
	}

	AppendManifest := newManifestOpts{
		action: REPLACE,
		options: []layout.Option{
			layout.WithURLs(urls),
		},
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, AppendManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			AppendManifest,
		}
	}

	i.newManifest[hash] = manifestBytes

	return nil
}

func(i *index) Add(ref name.Reference, all bool) error {
	digest := ref.Context().Digest(ref.Identifier())
	hash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return err
	}

	idx, err := remote.Index(ref, remote.WithAuthFromKeychain(i.keychain))
	if d, _ := idx.Digest(); err != nil || hash != d {
		img, err := remote.Image(ref, remote.WithAuthFromKeychain(i.keychain))
		if err != nil {
			return err
		}

		manifestBytes, err := img.RawConfigFile()
		if err != nil {
			return err
		}

		AppendManifest := newManifestOpts{
			action: ADD,
			isIndex: false,
			hash: hash,
			image: img,
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}

		i.newManifest[hash] = manifestBytes

		return nil
	}

	if all {
		idxManifest, err := idx.IndexManifest()
		if err != nil {
			return err
		}

		AppendManifests, descriptors := addAllManifests(*idxManifest)
	
		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifests...)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = AppendManifests
		}

		for _, descriptor := range descriptors {
			if err := verify.Descriptor(descriptor); err != nil {
				return err
			}

			switch true {
			case descriptor.MediaType.IsImage(): {
				descIdx, err := v1.ParseIndexManifest(bytes.NewReader(descriptor.Data))
				if err != nil {
					return err
				}

				hash := descIdx.Subject.Digest
				manifestBytes, err := json.Marshal(descIdx)
				if err != nil {
					return err
				}
	
				i.newManifest[hash] = manifestBytes
			}
			case descriptor.MediaType.IsIndex(): {
				descImg, _ := v1.ParseManifest(bytes.NewReader(descriptor.Data))
				var emptyHash v1.Hash
				hash := descImg.Config.Digest
				if hash == emptyHash {
					hash, err = v1.NewHash(descImg.Subject.Digest.String())
					if err != nil {
						return err
					}
				}
				i.newManifest[hash] = descImg.Config.Data
			}
			}
		}
		
		return nil

	} else {
		manifestBytes, err := idx.RawManifest()
		if err != nil {
			return err
		}
	
		AppendManifest := newManifestOpts{
			action: ADD,
			isIndex: true,
			hash: hash,
			index: idx,
		}
	
		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, AppendManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				AppendManifest,
			}
		}
	
		i.newManifest[hash] = manifestBytes
	}

	return nil
}

func addAllManifests(idxManifest v1.IndexManifest) (AppendManifests []newManifestOpts, descriptor []v1.Descriptor) {
	for _, manifest := range idxManifest.Manifests {
		if manifest.MediaType.IsImage() {
			AppendManifests = append(AppendManifests, newManifestOpts{
				action: ADD,
				isIndex: false,
				hash: manifest.Digest,
				image: ,
			})
		} else {
			AppendManifests = append(AppendManifests, newManifestOpts{
				action: ADD,
				isIndex: true,
				hash: manifest.Digest,
				index: ,
			})
		}

		descriptor = append(descriptor, manifest)
	}

	return
}

func(i *index) Save() error {
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	for h := range i.newIndex {
		for _, manifestActions := range i.newIndex[h] {
			switch manifestActions.action {
			case ADD: {
				path.AppendImage(manifestActions.image, manifestActions.options)
			}
			case REPLACE: {}
			case DELETE: {}
			}
		}
	}
	return nil
}

func(i *index) Push() error {
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	imgIdx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	// idxManifest, err := imgIdx.IndexManifest()
	// if err != nil {
	// 	return err
	// }

	ref, err := name.ParseReference(i.repoName, name.WeakValidation)
	if err != nil {
		return err
	}

	// for _, manifest := range idxManifest.Manifests {
	// 	// TODO: check if any Image or ImageIndex is not Pushed to registry
	// }

	return remote.WriteIndex(ref, imgIdx, remote.WithAuthFromKeychain(i.keychain))
}

func(i *index) Inspect(digest name.Digest) error {
	hash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return err
	}

	if manifestBytes, ok := i.newManifest[hash]; ok {
		return fmt.Errorf(string(manifestBytes))
	}
	
	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	idx, err := path.ImageIndex()
	if err != nil {
		return err
	}

	img, err := idx.Image(hash)
	if err != nil {
		idxManifest, err := idx.ImageIndex(hash)
		if err != nil {
			return err
		}

		manifestBytes, err := idxManifest.RawManifest()
		if err != nil {
			return err
		}

		return fmt.Errorf(string(manifestBytes))
	}

	manifestBytes, err := img.RawManifest()
	if err != nil {
		return err
	}

	return fmt.Errorf(string(manifestBytes))
}

func(i *index) Remove(digest name.Digest) error {
	hash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return err
	}

	path, err := layoutPath(i.xdgRuntimePath, i.repoName)
	if err != nil {
		return err
	}

	imgIdx, err := path.ImageIndex()
	if err != nil {
		return err
	}
	
	_, err = imgIdx.ImageIndex(hash)
	if err != nil {
		_, err := imgIdx.Image(hash)
		if err != nil {
			return err
		}
		
		RemoveManifest := newManifestOpts{
			action: DELETE,
			index: false,
			hash: hash,
		}

		if slice, ok := i.newIndex[hash]; ok {
			slice = append(slice, RemoveManifest)
			i.newIndex[hash] = slice
		} else {
			i.newIndex[hash] = []newManifestOpts{
				RemoveManifest,
			}
		}

		delete(i.newManifest, hash)

		return nil
	}

	RemoveManifest := newManifestOpts{
		action: DELETE,
		index: true,
		hash: hash,
	}

	if slice, ok := i.newIndex[hash]; ok {
		slice = append(slice, RemoveManifest)
		i.newIndex[hash] = slice
	} else {
		i.newIndex[hash] = []newManifestOpts{
			RemoveManifest,
		}
	}

	delete(i.newManifest, hash)

	return nil
}

func(i *index) Delete() error {
	return os.RemoveAll(filepath.Join(i.xdgRuntimePath, i.repoName))
}

//  func NewIndex(repoName string, keychain authn.Keychain, ops ...imgutil.IndexOption) (index *imgutil.Index, err error) {
// 	ref, err := name.ParseReference(repoName, name.WeakValidation)
// 	if err != nil {
// 		return
// 	}

// 	imgIndex, err := remote.Index(ref, remote.WithAuthFromKeychain(keychain))
// 	image = &imgutil.In
// }