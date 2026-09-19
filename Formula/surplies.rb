class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.10.3"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.3/surplies-v0.10.3-darwin-arm64.tar.gz"
    sha256 "68b74ce3a11d863e60539110663564f2c68281f849e4c6cf4c0adea31f0f1ffc"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.3/surplies-v0.10.3-darwin-amd64.tar.gz"
    sha256 "dd4fd7f32b6a59775aec1b4c13fb2dd971bda92cfae7549aa07f0ec33c967104"
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
