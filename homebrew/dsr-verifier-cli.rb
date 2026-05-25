# Homebrew formula for dsr-verifier-cli.
#
# This file is the TEMPLATE stored in the dsr-verifier-cli source repo.
# The authoritative, live formula lives at:
#   github.com/deja-dev/homebrew-tap/Formula/dsr-verifier-cli.rb
#
# The CI release pipeline updates the tap repo automatically on each tagged
# release. SHA-256 values here are placeholders — the tap repo has real values.
#
# To install from the tap:
#   brew tap deja-dev/tap
#   brew install dsr-verifier-cli
#
# Or in one command:
#   brew install deja-dev/tap/dsr-verifier-cli

class DsrVerifierCli < Formula
  desc "Offline DSR/1.0.1 receipt and evidence bundle verifier"
  homepage "https://github.com/deja-dev/dsr-verifier-cli"
  license "MIT"
  version "1.0.0"

  # macOS Apple Silicon
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/deja-dev/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_DARWIN_ARM64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    # macOS Intel
    if Hardware::CPU.intel?
      url "https://github.com/deja-dev/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_DARWIN_AMD64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  # Linux x86-64
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/deja-dev/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_LINUX_ARM64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/deja-dev/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_LINUX_AMD64"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  test do
    # Verify the binary reports the correct version and exits cleanly.
    assert_match "dsr-verifier-cli v#{version}", shell_output("#{bin}/dsr-verifier-cli --version")
    # Verify the offline guarantee is visible in help output.
    assert_match "offline", shell_output("#{bin}/dsr-verifier-cli --help")
  end
end
