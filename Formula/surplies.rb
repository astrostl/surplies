class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.6.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.6.1/surplies-v0.6.1-darwin-arm64.tar.gz"
    sha256 "1e19117c3bc5394c2e0cfc80cd0712fe29edbca9a193665bee23ad1b3cfab30b"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.6.1/surplies-v0.6.1-darwin-amd64.tar.gz"
    sha256 "486b2137bfdc97b02467cbac11ff4c77e9db0e7a72ea52b4fe30d3cd8bf273e8"
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
