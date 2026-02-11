{
  description = "DNSProof reproducible Python dev shell (with pip)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system:
          f {
            pkgs = import nixpkgs { inherit system; };
            inherit system;
          }
        );
    in {
      devShells = forAllSystems ({ pkgs, system }:
        let
          python = pkgs.python313;

        in {
          default = pkgs.mkShell {
            name = "dnsproof-shell";

            # System packages (not Python)
            buildInputs = [
              python
              pkgs.sqlite
              pkgs.openssl
            ];

            # Optional: helpful env var
            shellHook = ''
              echo ""
              echo "🔧 Welcome to the DNSProof dev shell (Python 3.13)"
              echo ""
              echo "  First-time setup:"
              echo "    python -m venv venv"
              echo "    source venv/bin/activate"
              echo "    pip install -r app/requirements.txt"
              echo ""
              echo "  To install the dnp CLI:"
              echo "    pip install ."
              echo ""
              echo "  To start the backend server:"
              echo "    cd app && uvicorn main:app --reload"
              echo ""
            '';
          };
        }
      );
    };
}
