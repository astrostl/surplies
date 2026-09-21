class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.11.2"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.2/surplies-v0.11.2-darwin-arm64.tar.gz"
    sha256 "62c72d55d7630ca77753f0f0ebcdcf3594747a577b7b1b1a3ea7f713b96ee8cd"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.2/surplies-v0.11.2-darwin-amd64.tar.gz"
    sha256 "261be38c97ce28ce64a1c1eec616e250901319b35e55cf9e4e5a5c317369ec1f"
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
