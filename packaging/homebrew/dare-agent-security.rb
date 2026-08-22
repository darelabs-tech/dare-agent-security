# Homebrew formula scaffold for DARE Agent Security.
#
# Not yet published to homebrew-core or a dedicated tap. sha256 values are
# placeholders — replace them with the values from the release's
# SHA256SUMS file before tapping/testing.
#
# Local test:
#   brew install --build-from-source ./packaging/homebrew/dare-agent-security.rb
class DareAgentSecurity < Formula
  desc "Deterministic adversarial validation and security conformance testing for AI agents and MCP systems"
  homepage "https://github.com/darelabs-tech/dare-agent-security"
  version "0.0.0" # updated per release
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/darelabs-tech/dare-agent-security/releases/download/v#{version}/dare-agent-security-v#{version}-macos-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_AARCH64"
    end
    on_intel do
      url "https://github.com/darelabs-tech/dare-agent-security/releases/download/v#{version}/dare-agent-security-v#{version}-macos-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/darelabs-tech/dare-agent-security/releases/download/v#{version}/dare-agent-security-v#{version}-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_AARCH64"
    end
    on_intel do
      url "https://github.com/darelabs-tech/dare-agent-security/releases/download/v#{version}/dare-agent-security-v#{version}-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X86_64"
    end
  end

  def install
    bin.install "dare-agent-security"
  end

  test do
    system "#{bin}/dare-agent-security", "--version"
  end
end
