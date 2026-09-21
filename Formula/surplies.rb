class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.12.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.12.0/surplies-v0.12.0-darwin-arm64.tar.gz"
    sha256 "6b62c93029b57c4863ec539daa99f30f6be20ec091bc57eab12bbfa19e927ff5"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.12.0/surplies-v0.12.0-darwin-amd64.tar.gz"
    sha256 "4f16d8ee83485600e24306b156d496e125efbf4a268b83d5154c4c5923a755d9"
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
