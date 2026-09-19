class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.10.2"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.2/surplies-v0.10.2-darwin-arm64.tar.gz"
    sha256 "e2a7dbc562f5806d3d718ab0af8cce066cd5dd782969e65777d79c8b16c5b1dd"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.2/surplies-v0.10.2-darwin-amd64.tar.gz"
    sha256 "3646afde69dea20e366a1a80ae7c798a545c9ee212ab10827ff8b26e2cb38e67"
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
