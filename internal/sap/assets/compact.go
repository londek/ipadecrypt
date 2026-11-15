package assets

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
)

// Digests of the arm64 slices of the pinned 26A434 images. The universal
// download/cache path remains available when the dependency cache is absent.
var compactFiles = []fileSpec{
	{"AppleMediaServices", 14813888, mustDigest("95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4")},
	{"commerce", 2735088, mustDigest("c4b2088dd39aeb353f59cb57597902e8317aec66ae7da0414b03c5f932771343")},
	{"adid", 3047808, mustDigest("43419a206c28bc93ecb8884256088d18306a0a462350f83adbced8e60a94e390")},
	{"CoreFP", 30764976, mustDigest("afbc123e688a822d980d5816cc2b52f69fde669d1dca92cf85627e1cbee587f6")},
	{"CoreFP.icxs", 7365344, mustDigest("cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b")},
	{"fairplayd", 17389744, mustDigest("1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784")},
	{"FairPlayIOKit", 2132320, mustDigest("47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025")},
}

func readCompactCache(directory string) (Bundle, error) {
	files := make(map[string][]byte, len(compactFiles))
	for _, spec := range compactFiles {
		data, err := readCacheFile(filepath.Join(directory, spec.name), spec.size)
		if err != nil {
			return Bundle{}, err
		}
		if sha256.Sum256(data) != spec.digest {
			return Bundle{}, errors.New("compact Apple asset failed integrity verification")
		}
		files[spec.name] = data
	}
	return bundleFrom(files), nil
}
