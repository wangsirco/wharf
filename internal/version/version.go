// Package version holds the release version shared by the agent, the panel and the
// update check. scripts/build-ipk.sh reads Version to name the package.
package version

const Version = "0.17.0"

// CoreHash fingerprints the agent / panel / package sources this binary was built from
// (set by scripts/build-ipk.sh with -ldflags); the online update compares it with the
// release manifest to decide whether the program itself needs updating.
var CoreHash = "dev"

// UpdateKey is the ed25519 public key that release manifests must be signed with.
// The private half stays with the maintainer and never enters the repository.
const UpdateKey = "npMYRfWLEETZmeYlH+9Ebhn7wCl5hblvqOVHAc84eUQ="
