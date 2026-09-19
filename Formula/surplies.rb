class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.8.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.0/surplies-v0.8.0-darwin-arm64.tar.gz"
    sha256 "a1a4a02b902b5cc107b64b2216cb15c0ca0a8a42e29a5e08fa85fecf9c1ba662"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.0/surplies-v0.8.0-darwin-amd64.tar.gz"
    sha256 "719d2e8b6c4bcb5bc658203583810c3399db434d8e90ce4368656f4cfce2c011"
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
