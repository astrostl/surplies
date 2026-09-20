class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.11.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.0/surplies-v0.11.0-darwin-arm64.tar.gz"
    sha256 "1a520951ce03e4f0e36e5973bdc0f87fc49c98457f04c1f3a852276a0d780f58"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.0/surplies-v0.11.0-darwin-amd64.tar.gz"
    sha256 "7bf8386dd6dd25cf6f12ec2369a8e5083d718f2128a394e21474bb5180e68c75"
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
