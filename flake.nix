{
  description = "MonkeyClaw development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          nativeLibs = with pkgs; [
            stdenv.cc.cc
            zlib
            openssl
            sqlite
          ];
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              bashInteractive
              cacert
              curl
              docker-client
              docker-compose
              git
              nodejs_22
              python312
              ripgrep
              sqlite
              uv
              zstd
            ];

            UV_PYTHON = "${pkgs.python312}/bin/python3.12";
            UV_PYTHON_DOWNLOADS = "never";
            UV_LINK_MODE = "copy";
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeLibs;
            DYLD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeLibs;

            shellHook = ''
              export PATH="$PWD/.venv/bin:$PATH"

              echo "MonkeyClaw Nix dev shell"
              echo "  Python: $UV_PYTHON"
              echo "  Setup : uv sync"
              echo "  Check : ./scripts/check_env.sh"
              echo "  Mock  : uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock"
              echo
              echo "Real NemoClaw provisioning still requires a host Docker daemon and nemoclaw setup."
            '';
          };
        });
    };
}
