{
  description = "Cashu is a Chaumian Ecash wallet and mint for Bitcoin Lightning.";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
  inputs.poetry2nix = {
    # the most recent poetry2nix seems to have a bug, we pin to an earlier version
    url = "github:nix-community/poetry2nix/2023.10.05.49422";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    poetry2nix,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      # see https://github.com/nix-community/poetry2nix/tree/master#api for more functions and examples.
      inherit (poetry2nix.legacyPackages.${system}) mkPoetryApplication;
      pkgs = import nixpkgs { inherit system; };
    in {
      packages = {
        cashu =
          (mkPoetryApplication {
            projectDir = ./.;
            # don't check dev deps
            checkGroups = [];
            overrides = pkgs.poetry2nix.overrides.withDefaults (final: prev: {
              urllib3 = prev.urllib3.overridePythonAttrs (old: {
                nativeBuildInputs = old.nativeBuildInputs ++ [final.hatchling];
              });
              attrs = prev.attrs.overridePythonAttrs (old: {
                nativeBuildInputs = old.nativeBuildInputs ++ [final.hatchling final.hatch-fancy-pypi-readme final.hatch-vcs];
              });
              cryptography = prev.cryptography.override {preferWheel = true;};
              bip32 = prev.buildPythonPackage {
                name = "bip32";
                propagatedBuildInputs = with final; [coincurve base58];
                nativeBuildInputs = with final; [setuptools hatchling];
                src = pkgs.fetchFromGitHub {
                  owner = "darosior";
                  repo = "python-bip32";
                  rev = "1492d39312f1d9630363c292f6ab8beb8ceb16dd";
                  sha256 = "sha256-o8UKR17XDWp1wTWYeDL0DJY+D11YI4mg0UuGEAPkHxE=";
                };
              };
            });
          })
          .overridePythonAttrs (old: {
            propagatedBuildInputs = old.propagatedBuildInputs ++ [pkgs.python3Packages.setuptools];
            nativeBuildInputs = old.nativeBuildInputs ++ [pkgs.python3Packages.pythonRelaxDepsHook ];
            pythonRelaxDeps = ["setuptools"];
          });
        default = self.packages.${system}.cashu;
      };

      devShells.default = pkgs.mkShell {
        packages = [poetry2nix.packages.${system}.poetry];
        buildInputs = with pkgs; [pkg-config];
      };
    });
}
