# Dev + CI environment. `nix-shell` (or direnv: `direnv allow`).
# nixpkgs pinned to the same commit as obs-irl-backstage so local and CI tools match.
{ pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/7d853e518814cca2a657b72eeba67ae20ebf7059.tar.gz";
    sha256 = "0hsqizh6kqp27gywdl33rpjclz8lls8s757qwa5qkbjb9an0dxlp";
  }) {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [ go gopls gotools golangci-lint gnumake git curl jq shellcheck ];
}
