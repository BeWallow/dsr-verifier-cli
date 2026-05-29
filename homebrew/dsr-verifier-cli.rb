# Homebrew formula template (live copy: github.com/BeWallow/homebrew-tap/Formula/dsr-verifier-cli.rb)
#
# Install:
#   brew install BeWallow/tap/dsr-verifier-cli

class DsrVerifierCli < Formula
  desc "Offline DSR/1.0.1 receipt and evidence bundle verifier"
  homepage "https://github.com/BeWallow/dsr-verifier-cli"
  license "MIT"
  version "1.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/BeWallow/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-arm64.tar.gz"
      sha256 "f2cd382b6be0587019499be8f647cbbfcbd74d2f2540e8a879117969444aa1ab"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/BeWallow/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-darwin-amd64.tar.gz"
      sha256 "a1f2eb94e15066d7d661b15c2fd0971ecc659d7aedf35ad848c9e752a516ec77"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/BeWallow/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-arm64.tar.gz"
      sha256 "1f3dcca943743a08a39fa0d759f849d05a0a220dcaf11fe3dd928676d95da735"

      def install
        bin.install "dsr-verifier-cli"
      end
    end

    if Hardware::CPU.intel?
      url "https://github.com/BeWallow/dsr-verifier-cli/releases/download/v#{version}/dsr-verifier-cli-v#{version}-linux-amd64.tar.gz"
      sha256 "0770ddf3ae1b54458cac3fd75d3a00f4c321e3b7097636f56b466d3c0ee01497"

      def install
        bin.install "dsr-verifier-cli"
      end
    end
  end

  test do
    assert_match "dsr-verifier-cli v#{version}", shell_output("#{bin}/dsr-verifier-cli --version")
    assert_match "offline", shell_output("#{bin}/dsr-verifier-cli --help")
  end
end
