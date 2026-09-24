class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.16.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.16.0/surplies-v0.16.0-darwin-arm64.tar.gz"
    sha256 "dac6230635ab2864192eb1c4e51ed41850e82599fd174c0b13de0a6085520c12"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.16.0/surplies-v0.16.0-darwin-amd64.tar.gz"
    sha256 "26afa6283f762845f23844aff49937759bfc65ced1fbf6babd751766949e03a2"
  else
    odie "surplies is only supported on macOS via Homebrew. Build from source for Linux."
  end

  def install
    bin.install "surplies-darwin-arm64" => "surplies" if Hardware::CPU.arm?
    bin.install "surplies-darwin-amd64" => "surplies" if Hardware::CPU.intel?
  end

  test do
    system bin/"surplies", "-version"
  end
end
