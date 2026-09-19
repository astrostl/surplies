class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.9.5"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.5/surplies-v0.9.5-darwin-arm64.tar.gz"
    sha256 "ac3c102219a381ff4884208c4ef3944bb62a1f8c9270b2acc888ff132e8efbac"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.5/surplies-v0.9.5-darwin-amd64.tar.gz"
    sha256 "2de95b0eed50051d464af14df398856fd92707632625d4a2ea6cc38e8f3b1747"
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
