class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.11.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.1/surplies-v0.11.1-darwin-arm64.tar.gz"
    sha256 "1acc74e2ab590f6397d4baaffd0a3ce83365d166e7b93ab5331d73a56e7b879f"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.1/surplies-v0.11.1-darwin-amd64.tar.gz"
    sha256 "7bd3ff186f3f2b69a0ee85beda53ba3a90152f80856298a43a1add1875301103"
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
