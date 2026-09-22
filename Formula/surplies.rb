class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.14.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.14.0/surplies-v0.14.0-darwin-arm64.tar.gz"
    sha256 "69ee637ded4b3555e1001cd6e40768d054dc056376e338915c1d059f3d36a94d"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.14.0/surplies-v0.14.0-darwin-amd64.tar.gz"
    sha256 "0435dd0719d4befb3e70e4595088a93bf473af1895a4a65cfea6a6530e4357fe"
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
