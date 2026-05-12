class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.3.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.3.1/surplies-v0.3.1-darwin-arm64.tar.gz"
    sha256 "24e4f0cd2409918acaef58c8f5d940f50904f0a01386169f7117e8cd7d721464"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.3.1/surplies-v0.3.1-darwin-amd64.tar.gz"
    sha256 "b344137f003c77eb7c4c5219b411439ee99108fa07767f4f49f1a21d4b3ad9de"
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
